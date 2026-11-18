"""Rollback-only PostgreSQL atomic attempt-idempotency test.

Uses the approved disposable database only.
Both pending migrations run inside one uncommitted transaction.
One PostgreSQL connection is used; cross-connection concurrency
is intentionally reserved for the next test phase.
"""

import importlib.util
import os
import uuid
from pathlib import Path

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
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
from app.payments.attempt_idempotency import CreateAttemptIntent
from app.payments.contracts import PaymentState
from app.services.payment_attempt_idempotency import (
    AttemptIdempotencyKeyConflict,
    create_sandbox_payment_attempt_idempotent,
)
from app.services.payment_attempts import (
    PaymentAttemptAccessDenied,
    PaymentAttemptConflict,
)


TARGET = "payflow_payment_drill_20261117_020846_9fbac781"
BASE = "b2c1f20a7d31"
INDEX = "ux_payment_attempts_one_live_or_successful"
RECORDS = "payment_attempt_idempotency_records"

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
    os.environ.get("PAYFLOW_IDEMPOTENCY_TEST_DB") != TARGET,
    reason="Explicit disposable database opt-in required",
)


def checked_target_url():
    settings = get_settings()

    assert settings.app_env == "development"

    for source, expected_role in (
        (settings.database_url, "payflow_runtime"),
        (settings.migration_database_url, "payflow_migrator"),
    ):
        url = make_url(source)

        assert url.database == "payflow_db"
        assert url.username == expected_role
        assert url.host in ("localhost", "127.0.0.1")
        assert url.port in (None, 5432)

    return make_url(
        settings.migration_database_url
    ).set(database=TARGET)


def verify_identity(conn):
    database, role = conn.execute(
        text("SELECT current_database(), current_user")
    ).one()

    assert database == TARGET
    assert role == "payflow_migrator"


def relation_exists(conn, name):
    return conn.execute(
        text("SELECT to_regclass(:name)"),
        {"name": "payflow." + name},
    ).scalar_one() is not None


def verify_baseline(conn):
    verify_identity(conn)

    revision = conn.execute(
        text(
            "SELECT version_num FROM payflow.alembic_version"
        )
    ).scalar_one()

    assert revision == BASE

    names = set(
        conn.execute(
            text("""
                SELECT tablename
                FROM pg_catalog.pg_tables
                WHERE schemaname = 'payflow'
            """)
        ).scalars()
    )

    assert names == set(TABLES) | {"alembic_version"}

    assert not relation_exists(conn, RECORDS)
    assert not relation_exists(conn, INDEX)

    for table in TABLES:
        count = conn.exec_driver_sql(
            f"SELECT COUNT(*) FROM payflow.{table}"
        ).scalar_one()

        assert count == 0, (table, count)

    constraint_count = conn.execute(
        text("""
            SELECT COUNT(*)
            FROM pg_catalog.pg_constraint
            WHERE conrelid = 'payflow.payment_orders'::regclass
              AND conname = 'uq_payment_orders_tenant_id'
        """)
    ).scalar_one()

    assert constraint_count == 0


def load_migration(revision, filename):
    path = Path("alembic/versions") / filename

    assert path.is_file()

    spec = importlib.util.spec_from_file_location(
        "attempt_atomicity_" + revision,
        path,
    )

    assert spec is not None
    assert spec.loader is not None

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert module.revision == revision

    return module


def create_fixture(conn):
    with Session(
        bind=conn,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    ) as db:
        with db.begin():
            token = uuid.uuid4().hex

            actor = User(
                email=f"atomic-{token}@example.invalid",
                password_hash="!synthetic-disabled!",
                is_active=True,
            )
            db.add(actor)
            db.flush()

            organization = Organization(
                name="Atomic Idempotency Sandbox",
                slug="atomic-" + token[:16],
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
                business_name="Atomic Test Merchant",
                onboarding_status="approved",
            )

            orders = []

            for label, status in (
                ("main", "open"),
                ("other", "open"),
                ("terminal", "paid"),
            ):
                order = PaymentOrder(
                    organization_id=organization.id,
                    merchant_order_reference=(
                        "atomic-" + label + "-" + token[:16]
                    ),
                    amount_minor_units=149900,
                    currency="INR",
                    status=status,
                )

                orders.append(order)

            db.add_all([membership, merchant, *orders])
            db.flush()

            return {
                "actor": actor.id,
                "org": organization.id,
                "main": orders[0].id,
                "other": orders[1].id,
                "terminal": orders[2].id,
            }


def request(fixture, order, key):
    return CreateAttemptIntent(
        organization_id=fixture["org"],
        order_id=order,
        idempotency_key=key,
    )


def execute_service(conn, fixture, order, key, actor=None):
    with Session(
        bind=conn,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    ) as db:
        with db.begin():
            return create_sandbox_payment_attempt_idempotent(
                db,
                actor_user_id=actor or fixture["actor"],
                intent=request(fixture, order, key),
            )


def counts(conn, fixture, order):
    attempts = conn.execute(
        text("""
            SELECT COUNT(*)
            FROM payflow.payment_attempts
            WHERE organization_id = :org
              AND order_id = :order_id
        """),
        {"org": fixture["org"], "order_id": order},
    ).scalar_one()

    mappings = conn.execute(
        text("""
            SELECT COUNT(*)
            FROM payflow.payment_attempt_idempotency_records
            WHERE organization_id = :org
              AND order_id = :order_id
        """),
        {"org": fixture["org"], "order_id": order},
    ).scalar_one()

    return attempts, mappings


def exercise_service(conn, fixture):
    order = fixture["main"]
    first_key = "ATOMIC_KEY_0001"
    second_key = "ATOMIC_KEY_0002"

    first = execute_service(
        conn, fixture, order, first_key
    )

    assert first.replayed is False
    assert first.attempt.attempt_number == 1
    assert first.attempt.state is PaymentState.CREATED

    assert counts(conn, fixture, order) == (1, 1)

    record = conn.execute(
        text("""
            SELECT status, attempt_number
            FROM payflow.payment_attempt_idempotency_records
            WHERE organization_id = :org
              AND order_id = :order_id
              AND idempotency_key = :key
        """),
        {
            "org": fixture["org"],
            "order_id": order,
            "key": first_key,
        },
    ).one()

    assert record.status == "completed"
    assert record.attempt_number == 1

    print("PASS: Attempt and completed key mapping created")

    replay = execute_service(
        conn, fixture, order, first_key
    )

    assert replay.replayed is True
    assert replay.attempt.id == first.attempt.id
    assert counts(conn, fixture, order) == (1, 1)

    print("PASS: Same key replays without new attempt")

    with pytest.raises(AttemptIdempotencyKeyConflict):
        execute_service(
            conn,
            fixture,
            fixture["other"],
            first_key,
        )

    assert counts(
        conn, fixture, fixture["other"]
    ) == (0, 0)

    print("PASS: Same tenant/key with another order conflicts")

    with pytest.raises(PaymentAttemptAccessDenied):
        execute_service(
            conn,
            fixture,
            order,
            "ATOMIC_KEY_9999",
            actor=uuid.uuid4(),
        )

    print("PASS: Authorization checked before key reservation")

    # Synthetic status change, not a provider callback.
    updated = conn.execute(
        text("""
            UPDATE payflow.payment_attempts
            SET status = 'failed'
            WHERE organization_id = :org
              AND order_id = :order_id
              AND id = :attempt_id
              AND status = 'created'
        """),
        {
            "org": fixture["org"],
            "order_id": order,
            "attempt_id": first.attempt.id,
        },
    )

    assert updated.rowcount == 1

    replay_failed = execute_service(
        conn, fixture, order, first_key
    )

    assert replay_failed.replayed is True
    assert replay_failed.attempt.id == first.attempt.id
    assert replay_failed.attempt.state is PaymentState.FAILED

    print("PASS: Original failed attempt replays with same key")

    second = execute_service(
        conn, fixture, order, second_key
    )

    assert second.replayed is False
    assert second.attempt.attempt_number == 2
    assert second.attempt.id != first.attempt.id

    assert counts(conn, fixture, order) == (2, 2)

    again = execute_service(
        conn, fixture, order, first_key
    )

    assert again.replayed is True
    assert again.attempt.id == first.attempt.id
    assert again.attempt.state is PaymentState.FAILED

    print("PASS: New key retries; old key retains original mapping")

    # If attempt creation fails after reserving a key,
    # the surrounding savepoint must roll back the key.
    with pytest.raises(PaymentAttemptConflict):
        execute_service(
            conn,
            fixture,
            fixture["terminal"],
            "ATOMIC_KEY_0003",
        )

    assert counts(
        conn, fixture, fixture["terminal"]
    ) == (0, 0)

    print("PASS: Failed creation leaves no key reservation")

    # Simulate a caller aborting after successful creation.
    class DeliberateRollback(Exception):
        pass

    with pytest.raises(DeliberateRollback):
        with Session(
            bind=conn,
            join_transaction_mode="create_savepoint",
        ) as db:
            with db.begin():
                result = create_sandbox_payment_attempt_idempotent(
                    db,
                    actor_user_id=fixture["actor"],
                    intent=request(
                        fixture,
                        fixture["other"],
                        "ATOMIC_KEY_0004",
                    ),
                )

                assert result.replayed is False

                raise DeliberateRollback()

    assert counts(
        conn, fixture, fixture["other"]
    ) == (0, 0)

    print("PASS: Caller rollback removes attempt and key")

    rows = conn.execute(
        text("""
            SELECT attempt_number, status,
                   provider_code, provider_payment_id
            FROM payflow.payment_attempts
            WHERE organization_id = :org
              AND order_id = :order_id
            ORDER BY attempt_number
        """),
        {"org": fixture["org"], "order_id": order},
    ).all()

    assert [
        (row.attempt_number, row.status)
        for row in rows
    ] == [
        (1, "failed"),
        (2, "created"),
    ]

    assert all(
        row.provider_code == "sandbox"
        and row.provider_payment_id is None
        for row in rows
    )

    print("PASS: Exact original and retry attempts persisted")
    print("PASS: No provider payment IDs or real payment calls")


def test_atomic_attempt_idempotency_on_postgresql():
    url = checked_target_url()

    engine = create_engine(
        url,
        poolclass=NullPool,
        connect_args={"connect_timeout": 5},
    )

    try:
        try:
            with engine.connect() as conn:
                outer = conn.begin()

                try:
                    conn.exec_driver_sql(
                        "SET LOCAL lock_timeout = '5s'"
                    )
                    conn.exec_driver_sql(
                        "SET LOCAL statement_timeout = '20s'"
                    )

                    verify_baseline(conn)

                    print("PASS: Disposable database baseline")
                    print("PASS: All 11 original application tables empty")

                    first = load_migration(
                        "d7a2f6c8b310",
                        "d7a2f6c8b310_one_live_payment_attempt.py",
                    )
                    second = load_migration(
                        "e4b3c1a8d205",
                        "e4b3c1a8d205_attempt_idempotency_records.py",
                    )

                    assert first.down_revision == BASE
                    assert second.down_revision == first.revision

                    context = MigrationContext.configure(
                        conn,
                        opts={"version_table_schema": "payflow"},
                    )

                    operations = Operations(context)
                    first.op = operations
                    second.op = operations

                    first.upgrade()
                    second.upgrade()

                    assert relation_exists(conn, INDEX)
                    assert relation_exists(conn, RECORDS)

                    print("PASS: Both migrations staged transactionally")

                    fixture = create_fixture(conn)
                    exercise_service(conn, fixture)

                finally:
                    if outer.is_active:
                        outer.rollback()

                    print("PASS: Outer transaction rollback requested")

        finally:
            # Always inspect from a NEW connection after
            # rollback, including when an assertion fails.
            with engine.connect() as conn:
                with conn.begin():
                    conn.exec_driver_sql(
                        "SET TRANSACTION READ ONLY"
                    )

                    verify_baseline(conn)

                    print("PASS: Original Alembic revision unchanged")
                    print("PASS: Both pending migration objects absent")
                    print("PASS: All 11 application tables empty")
                    print("PASS: Final verification read-only")

    finally:
        engine.dispose()

    print("PAYFLOW ATOMIC IDEMPOTENCY POSTGRESQL VERIFIED")
