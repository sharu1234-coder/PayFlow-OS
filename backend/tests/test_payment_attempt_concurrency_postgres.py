"""Disposable PostgreSQL payment-attempt concurrency test.

Runs only when explicitly enabled for the approved disposable DB.
Commits a synthetic fixture so two independent connections can see it.
Cleanup is limited to generated IDs and runs in finally.

An abrupt process termination may interrupt cleanup. In that event,
do not rerun until the disposable database has been inspected.
"""

import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.core.config import get_settings
from app.models import (
    MerchantProfile,
    Organization,
    OrganizationMembership,
    User,
)
from app.models.payments import PaymentOrder
from app.services.payment_attempts import (
    PaymentAttemptConflict,
    create_sandbox_payment_attempt,
)


TARGET = "payflow_payment_drill_20261117_020846_9fbac781"
EXPECTED_REVISION = "b2c1f20a7d31"

TABLES = (
    "audit_events",
    "auth_tokens",
    "merchant_profiles",
    "organization_invitations",
    "organization_memberships",
    "organizations",
    "payment_attempts",
    "payment_idempotency_records",
    "payment_orders",
    "user_sessions",
    "users",
)

pytestmark = pytest.mark.skipif(
    os.environ.get("PAYFLOW_ATTEMPT_TEST_DB") != TARGET,
    reason="Requires explicit disposable attempt test database",
)


def checked_urls():
    settings = get_settings()

    if settings.app_env != "development":
        raise RuntimeError("Development environment required")

    runtime = make_url(settings.database_url)
    migrator = make_url(settings.migration_database_url)

    for url, role in (
        (runtime, "payflow_runtime"),
        (migrator, "payflow_migrator"),
    ):
        if url.database != "payflow_db":
            raise RuntimeError("Unexpected configured database")

        if url.username != role:
            raise RuntimeError("Unexpected database role")

        if url.host not in ("localhost", "127.0.0.1"):
            raise RuntimeError("Remote PostgreSQL prohibited")

        if url.port not in (None, 5432):
            raise RuntimeError("Unexpected PostgreSQL port")

    return (
        runtime.set(database=TARGET),
        migrator.set(database=TARGET),
    )


def verify_identity(conn, expected_role):
    database, role = conn.execute(
        text("SELECT current_database(), current_user")
    ).one()

    if database != TARGET or role != expected_role:
        raise RuntimeError("Disposable database identity mismatch")


def assert_empty(conn):
    for table in TABLES:
        count = conn.exec_driver_sql(
            f"SELECT COUNT(*) FROM payflow.{table}"
        ).scalar_one()

        if count != 0:
            raise AssertionError(
                f"Disposable database is not empty: {table}={count}"
            )


def verify_schema(conn):
    revision = conn.execute(
        text(
            "SELECT version_num FROM payflow.alembic_version"
        )
    ).scalar_one()

    if revision != EXPECTED_REVISION:
        raise RuntimeError("Unexpected migration revision")

    catalog = conn.execute(
        text("""
            SELECT c.relname, c.relrowsecurity
            FROM pg_catalog.pg_class c
            JOIN pg_catalog.pg_namespace n
              ON n.oid = c.relnamespace
            WHERE n.nspname = 'payflow'
              AND c.relkind IN ('r', 'p')
        """)
    ).all()

    names = {name for name, _ in catalog}

    expected = set(TABLES) | {"alembic_version"}

    if names != expected:
        raise RuntimeError("Unexpected disposable schema inventory")

    if any(rls for _, rls in catalog):
        raise RuntimeError(
            "RLS requires a separate isolation review"
        )


def create_fixture(engine):
    fixture = {}

    # This transaction commits only to the disposable DB.
    with engine.begin() as conn:
        verify_identity(conn, "payflow_migrator")
        verify_schema(conn)
        assert_empty(conn)

        with Session(
            bind=conn,
            expire_on_commit=False,
            join_transaction_mode="create_savepoint",
        ) as db:
            with db.begin():
                unique = uuid.uuid4().hex

                actor = User(
                    email=f"attempt-{unique}@example.invalid",
                    password_hash="!synthetic-test-disabled!",
                    is_active=True,
                )
                db.add(actor)
                db.flush()

                organization = Organization(
                    name="Concurrency Sandbox",
                    slug="attempt-" + unique[:16],
                    status="active",
                )
                db.add(organization)
                db.flush()

                membership = OrganizationMembership(
                    organization_id=organization.id,
                    user_id=actor.id,
                    role="owner",
                    status="active",
                )

                merchant = MerchantProfile(
                    organization_id=organization.id,
                    business_name="Concurrency Test",
                    onboarding_status="approved",
                )

                order = PaymentOrder(
                    organization_id=organization.id,
                    merchant_order_reference=(
                        "attempt-" + unique[:24]
                    ),
                    amount_minor_units=12500,
                    currency="INR",
                    status="open",
                )

                db.add_all([membership, merchant, order])
                db.flush()

                fixture = {
                    "user_id": actor.id,
                    "organization_id": organization.id,
                    "order_id": order.id,
                }

    return fixture


def cleanup_fixture(engine, fixture):
    # Every DELETE is scoped to IDs created by this test.
    with engine.begin() as conn:
        verify_identity(conn, "payflow_migrator")

        org = fixture["organization_id"]
        order = fixture["order_id"]
        user = fixture["user_id"]

        conn.execute(
            text("""
                DELETE FROM payflow.payment_attempts
                WHERE organization_id = :org
                  AND order_id = :order_id
            """),
            {"org": org, "order_id": order},
        )

        conn.execute(
            text("""
                DELETE FROM payflow.payment_orders
                WHERE organization_id = :org
                  AND id = :order_id
            """),
            {"org": org, "order_id": order},
        )

        conn.execute(
            text("""
                DELETE FROM payflow.organization_memberships
                WHERE organization_id = :org
                  AND user_id = :user_id
            """),
            {"org": org, "user_id": user},
        )

        conn.execute(
            text("""
                DELETE FROM payflow.merchant_profiles
                WHERE organization_id = :org
            """),
            {"org": org},
        )

        conn.execute(
            text("""
                DELETE FROM payflow.organizations
                WHERE id = :org
            """),
            {"org": org},
        )

        conn.execute(
            text("""
                DELETE FROM payflow.users
                WHERE id = :user_id
            """),
            {"user_id": user},
        )

    # Verify in a new transaction after cleanup commits.
    with engine.connect() as conn:
        verify_identity(conn, "payflow_migrator")
        assert_empty(conn)

    print("PASS: All 11 application tables empty after cleanup")


def test_two_workers_cannot_create_two_active_attempts():
    runtime_url, migrator_url = checked_urls()

    runtime_engine = create_engine(
        runtime_url,
        poolclass=NullPool,
        connect_args={"connect_timeout": 5},
    )

    migrator_engine = create_engine(
        migrator_url,
        poolclass=NullPool,
        connect_args={"connect_timeout": 5},
    )

    fixture = None

    first_ready = threading.Event()
    second_started = threading.Event()
    second_done = threading.Event()
    release_first = threading.Event()

    try:
        with runtime_engine.connect() as conn:
            verify_identity(conn, "payflow_runtime")

        fixture = create_fixture(migrator_engine)

        def first_worker():
            with Session(runtime_engine) as db:
                with db.begin():
                    db.execute(
                        text("SET LOCAL lock_timeout = '8s'")
                    )

                    result = create_sandbox_payment_attempt(
                        db,
                        actor_user_id=fixture["user_id"],
                        organization_id=fixture["organization_id"],
                        order_id=fixture["order_id"],
                    )

                    # First attempt is flushed but not committed.
                    first_ready.set()

                    if not release_first.wait(timeout=15):
                        raise TimeoutError(
                            "First worker release timed out"
                        )

                # Transaction is committed here.
                return result

        def second_worker():
            if not first_ready.wait(timeout=12):
                raise TimeoutError(
                    "First worker never created an attempt"
                )

            try:
                with Session(runtime_engine) as db:
                    with db.begin():
                        db.execute(
                            text("SET LOCAL lock_timeout = '8s'")
                        )

                        second_started.set()

                        create_sandbox_payment_attempt(
                            db,
                            actor_user_id=fixture["user_id"],
                            organization_id=fixture["organization_id"],
                            order_id=fixture["order_id"],
                        )

                return "unexpected_second_creation"

            except PaymentAttemptConflict:
                return "blocked"

            finally:
                second_done.set()

        with ThreadPoolExecutor(max_workers=2) as executor:
            first_future = executor.submit(first_worker)

            try:
                assert first_ready.wait(timeout=12)

                second_future = executor.submit(
                    second_worker
                )

                assert second_started.wait(timeout=12)

                # The second transaction must not complete
                # while the first still holds the order lock.
                assert not second_done.wait(timeout=0.6), (
                    "Second transaction completed before "
                    "the first transaction was released"
                )

                release_first.set()

                first_result = first_future.result(
                    timeout=20
                )

                second_result = second_future.result(
                    timeout=20
                )

            finally:
                release_first.set()

        assert first_result.attempt_number == 1
        assert first_result.amount.minor_units == 12500
        assert first_result.amount.currency == "INR"
        assert first_result.provider_code == "sandbox"
        assert first_result.state.value == "created"

        assert second_result == "blocked", (
            "Concurrent duplicate attempt was not rejected"
        )

        # Verify persisted state using the migrator.
        with migrator_engine.connect() as conn:
            rows = conn.execute(
                text("""
                    SELECT id, attempt_number,
                           amount_minor_units, currency,
                           provider_code, provider_payment_id,
                           status
                    FROM payflow.payment_attempts
                    WHERE organization_id = :org
                      AND order_id = :order_id
                """),
                {
                    "org": fixture["organization_id"],
                    "order_id": fixture["order_id"],
                },
            ).all()

            assert len(rows) == 1, (
                "Exactly one persisted attempt required"
            )

            row = rows[0]

            assert row.id == first_result.id
            assert row.attempt_number == 1
            assert row.amount_minor_units == 12500
            assert row.currency == "INR"
            assert row.provider_code == "sandbox"
            assert row.provider_payment_id is None
            assert row.status == "created"

        print("PASS: Two independent runtime transactions")
        print("PASS: First attempt committed")
        print("PASS: Second attempt rejected")
        print("PASS: Exactly one active sandbox attempt")
        print("PASS: Correct amount and currency")
        print("PASS: No provider payment ID")
        print("PASS: No successful payment state")

    finally:
        release_first.set()

        try:
            if fixture is not None:
                cleanup_fixture(
                    migrator_engine,
                    fixture,
                )
            else:
                with migrator_engine.connect() as conn:
                    verify_identity(
                        conn,
                        "payflow_migrator",
                    )
                    assert_empty(conn)
        finally:
            runtime_engine.dispose()
            migrator_engine.dispose()


# PHASE_2B4B4_EXTENDED_CASES
# All tests target only the approved disposable PostgreSQL DB.

from contextlib import contextmanager

from app.services.payment_attempts import (
    PaymentAttemptAccessDenied,
    PaymentAttemptOrderNotFound,
)


@contextmanager
def extended_sandbox():
    """Create a committed fixture and clean it up in finally."""

    runtime_url, migrator_url = checked_urls()

    runtime_engine = create_engine(
        runtime_url,
        poolclass=NullPool,
        connect_args={"connect_timeout": 5},
    )

    migrator_engine = create_engine(
        migrator_url,
        poolclass=NullPool,
        connect_args={"connect_timeout": 5},
    )

    fixture = None

    try:
        with runtime_engine.connect() as conn:
            verify_identity(conn, "payflow_runtime")

        with migrator_engine.connect() as conn:
            verify_identity(conn, "payflow_migrator")
            verify_schema(conn)
            assert_empty(conn)

        fixture = create_fixture(migrator_engine)

        yield runtime_engine, migrator_engine, fixture

    finally:
        try:
            if fixture is not None:
                cleanup_fixture(migrator_engine, fixture)
            else:
                with migrator_engine.connect() as conn:
                    verify_identity(conn, "payflow_migrator")
                    assert_empty(conn)
        finally:
            runtime_engine.dispose()
            migrator_engine.dispose()


def submit_attempt(runtime_engine, fixture, **overrides):
    """Use an independent runtime transaction."""

    arguments = {
        "actor_user_id": fixture["user_id"],
        "organization_id": fixture["organization_id"],
        "order_id": fixture["order_id"],
    }

    arguments.update(overrides)

    with Session(runtime_engine) as db:
        with db.begin():
            return create_sandbox_payment_attempt(
                db,
                **arguments,
            )


def count_fixture_attempts(migrator_engine, fixture):
    with migrator_engine.connect() as conn:
        return conn.execute(
            text("""
                SELECT COUNT(*)
                FROM payflow.payment_attempts
                WHERE organization_id = :org
                  AND order_id = :order_id
            """),
            {
                "org": fixture["organization_id"],
                "order_id": fixture["order_id"],
            },
        ).scalar_one()


def test_sequential_duplicate_attempt_is_blocked():
    with extended_sandbox() as (runtime, migrator, fixture):
        first = submit_attempt(runtime, fixture)

        assert first.attempt_number == 1
        assert first.state.value == "created"

        with pytest.raises(PaymentAttemptConflict):
            submit_attempt(runtime, fixture)

        assert count_fixture_attempts(migrator, fixture) == 1

        print("PASS: Sequential duplicate rejected")


@pytest.mark.parametrize("terminal", ["failed", "cancelled"])
def test_retry_after_terminal_attempt(terminal):
    with extended_sandbox() as (runtime, migrator, fixture):
        first = submit_attempt(runtime, fixture)

        # Synthetic status change for testing only.
        # This is NOT a payment provider operation.
        with migrator.begin() as conn:
            verify_identity(conn, "payflow_migrator")

            result = conn.execute(
                text("""
                    UPDATE payflow.payment_attempts
                    SET status = :terminal
                    WHERE id = :attempt_id
                      AND organization_id = :org
                      AND order_id = :order_id
                      AND status = 'created'
                """),
                {
                    "terminal": terminal,
                    "attempt_id": first.id,
                    "org": fixture["organization_id"],
                    "order_id": fixture["order_id"],
                },
            )

            assert result.rowcount == 1

        second = submit_attempt(runtime, fixture)

        assert second.attempt_number == 2
        assert second.state.value == "created"
        assert second.id != first.id

        # The second attempt is active, blocking attempt 3.
        with pytest.raises(PaymentAttemptConflict):
            submit_attempt(runtime, fixture)

        with migrator.connect() as conn:
            rows = conn.execute(
                text("""
                    SELECT attempt_number, status
                    FROM payflow.payment_attempts
                    WHERE organization_id = :org
                      AND order_id = :order_id
                    ORDER BY attempt_number
                """),
                {
                    "org": fixture["organization_id"],
                    "order_id": fixture["order_id"],
                },
            ).all()

        assert [
            (row[0], row[1]) for row in rows
        ] == [
            (1, terminal),
            (2, "created"),
        ]

        print(f"PASS: Retry after {terminal}")


@pytest.mark.parametrize("order_status", ["paid", "cancelled"])
def test_terminal_order_blocks_new_attempt(order_status):
    with extended_sandbox() as (runtime, migrator, fixture):

        # This updates only a disposable synthetic order.
        with migrator.begin() as conn:
            verify_identity(conn, "payflow_migrator")

            result = conn.execute(
                text("""
                    UPDATE payflow.payment_orders
                    SET status = :order_status
                    WHERE id = :order_id
                      AND organization_id = :org
                      AND status = 'open'
                """),
                {
                    "order_status": order_status,
                    "order_id": fixture["order_id"],
                    "org": fixture["organization_id"],
                },
            )

            assert result.rowcount == 1

        with pytest.raises(PaymentAttemptConflict):
            submit_attempt(runtime, fixture)

        assert count_fixture_attempts(migrator, fixture) == 0

        print(
            f"PASS: Order status {order_status} blocks creation"
        )


def test_real_postgres_access_and_order_boundaries():
    with extended_sandbox() as (runtime, migrator, fixture):

        # Unrecognized actor.
        with pytest.raises(PaymentAttemptAccessDenied):
            submit_attempt(
                runtime,
                fixture,
                actor_user_id=uuid.uuid4(),
            )

        # Organization outside the actor's active membership.
        with pytest.raises(PaymentAttemptAccessDenied):
            submit_attempt(
                runtime,
                fixture,
                organization_id=uuid.uuid4(),
            )

        # Authenticated, authorized actor but unknown order.
        with pytest.raises(PaymentAttemptOrderNotFound):
            submit_attempt(
                runtime,
                fixture,
                order_id=uuid.uuid4(),
            )

        assert count_fixture_attempts(migrator, fixture) == 0

        print("PASS: Actor, organization and order boundaries")


def test_uncommitted_attempt_is_rolled_back():
    with extended_sandbox() as (runtime, migrator, fixture):

        with pytest.raises(
            RuntimeError,
            match="synthetic forced rollback",
        ):
            with Session(runtime) as db:
                with db.begin():
                    created = create_sandbox_payment_attempt(
                        db,
                        actor_user_id=fixture["user_id"],
                        organization_id=fixture["organization_id"],
                        order_id=fixture["order_id"],
                    )

                    assert created.attempt_number == 1

                    # Deliberately force transaction rollback.
                    raise RuntimeError(
                        "synthetic forced rollback"
                    )

        # A separate connection must not see the rolled-back row.
        assert count_fixture_attempts(migrator, fixture) == 0

        # A new valid transaction should still be able to
        # create attempt number 1.
        committed = submit_attempt(runtime, fixture)

        assert committed.attempt_number == 1
        assert count_fixture_attempts(migrator, fixture) == 1

        print("PASS: Rollback leaves no attempt residue")
