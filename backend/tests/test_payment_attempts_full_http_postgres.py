"""Full sandbox HTTP -> service -> PostgreSQL integration.

Disposable-only, single-connection, rollback-only test.

The two pending migrations execute in an outer transaction.
Real session authentication, CSRF, tenant RBAC, and sandbox
attempt idempotency are exercised via an isolated FastAPI app.

This does not register a route in app.main or invoke a gateway.
It does not independently retest two-connection concurrency.
"""

import importlib.util
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.api import payment_attempts_sandbox as attempt_api
from app.api import session as session_api
from app.api.dependencies import get_db
from app.core.config import get_settings
from app.core.security import hash_secure_token
from app.models import (
    MerchantProfile,
    Organization,
    OrganizationMembership,
    User,
    UserSession,
)
from app.models.payments import PaymentOrder


TARGET = "payflow_payment_drill_20261117_020846_9fbac781"
BASE = "b2c1f20a7d31"

INDEX = "ux_payment_attempts_one_live_or_successful"
IDEM_TABLE = "payment_attempt_idempotency_records"

KEY_ONE = "FULL_HTTP_ATTEMPT_KEY_0001"
KEY_TWO = "FULL_HTTP_ATTEMPT_KEY_0002"

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
    os.environ.get("PAYFLOW_FULL_HTTP_TEST_DB") != TARGET,
    reason="Explicit disposable PostgreSQL opt-in required",
)


def ensure(condition, explanation):
    if not condition:
        raise AssertionError(explanation)


def target_url():
    settings = get_settings()

    ensure(
        settings.app_env == "development",
        "Development environment required",
    )

    for raw, expected_role in (
        (settings.database_url, "payflow_runtime"),
        (settings.migration_database_url, "payflow_migrator"),
    ):
        url = make_url(raw)

        ensure(
            url.database == "payflow_db",
            "Configured source database mismatch",
        )

        ensure(
            url.username == expected_role,
            "Configured database role mismatch",
        )

        ensure(
            url.host in ("localhost", "127.0.0.1"),
            "Remote PostgreSQL prohibited",
        )

        ensure(
            url.port in (None, 5432),
            "Unexpected PostgreSQL port",
        )

    return make_url(
        settings.migration_database_url
    ).set(database=TARGET)


def assert_identity(conn):
    actual = conn.execute(
        text("SELECT current_database(), current_user")
    ).one()

    ensure(
        actual == (TARGET, "payflow_migrator"),
        "Incorrect database or migration role",
    )


def object_exists(conn, object_name):
    return conn.execute(
        text("SELECT to_regclass(:name)"),
        {"name": "payflow." + object_name},
    ).scalar_one() is not None


def clean_baseline(conn):
    assert_identity(conn)

    version = conn.execute(
        text(
            "SELECT version_num FROM payflow.alembic_version"
        )
    ).scalar_one()

    ensure(version == BASE, "Unexpected installed revision")

    actual_tables = set(
        conn.execute(
            text("""
                SELECT tablename
                FROM pg_catalog.pg_tables
                WHERE schemaname = 'payflow'
            """)
        ).scalars()
    )

    ensure(
        actual_tables == set(TABLES) | {"alembic_version"},
        "Unexpected application table inventory",
    )

    ensure(
        not object_exists(conn, INDEX),
        "Pending partial index exists",
    )

    ensure(
        not object_exists(conn, IDEM_TABLE),
        "Pending idempotency table exists",
    )

    order_constraint = conn.execute(
        text("""
            SELECT COUNT(*)
            FROM pg_catalog.pg_constraint
            WHERE conrelid = 'payflow.payment_orders'::regclass
              AND conname = 'uq_payment_orders_tenant_id'
        """)
    ).scalar_one()

    ensure(
        order_constraint == 0,
        "Pending order constraint exists",
    )

    for table in TABLES:
        count = conn.exec_driver_sql(
            f"SELECT COUNT(*) FROM payflow.{table}"
        ).scalar_one()

        ensure(
            count == 0,
            f"Existing records found in {table}: {count}",
        )


def load_migration(revision, filename):
    path = Path("alembic/versions") / filename

    ensure(path.is_file(), "Migration file missing")

    spec = importlib.util.spec_from_file_location(
        "full_http_" + revision,
        path,
    )

    ensure(
        spec is not None and spec.loader is not None,
        "Unable to load migration",
    )

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    ensure(
        module.revision == revision,
        "Unexpected migration revision",
    )

    return module


def stage_migrations(conn):
    first = load_migration(
        "d7a2f6c8b310",
        "d7a2f6c8b310_one_live_payment_attempt.py",
    )

    second = load_migration(
        "e4b3c1a8d205",
        "e4b3c1a8d205_attempt_idempotency_records.py",
    )

    ensure(
        first.down_revision == BASE,
        "Incorrect first migration predecessor",
    )

    ensure(
        second.down_revision == first.revision,
        "Incorrect second migration predecessor",
    )

    migration_context = MigrationContext.configure(
        conn,
        opts={"version_table_schema": "payflow"},
    )

    operations = Operations(migration_context)

    first.op = operations
    second.op = operations

    first.upgrade()
    second.upgrade()

    ensure(object_exists(conn, INDEX), "Index not staged")
    ensure(
        object_exists(conn, IDEM_TABLE),
        "Idempotency table not staged",
    )

    print("PASS: Both migrations staged without committing")


def create_fixture(conn):
    now = datetime.now(timezone.utc)
    suffix = uuid.uuid4().hex[:16]

    with Session(
        bind=conn,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    ) as db:
        with db.begin():
            users = {}

            for label in ("owner", "viewer", "outsider"):
                user = User(
                    email=(
                        f"full-http-{label}-{suffix}"
                        "@example.invalid"
                    ),
                    password_hash="!synthetic-disabled!",
                    email_verified_at=now,
                    is_active=True,
                )

                users[label] = user
                db.add(user)

            org_a = Organization(
                name="Full HTTP Sandbox A",
                slug="full-http-a-" + suffix,
                status="active",
            )

            org_b = Organization(
                name="Full HTTP Sandbox B",
                slug="full-http-b-" + suffix,
                status="active",
            )

            db.add_all([org_a, org_b])
            db.flush()

            db.add_all([
                MerchantProfile(
                    organization_id=org_a.id,
                    business_name="Synthetic Merchant A",
                    onboarding_status="approved",
                ),
                MerchantProfile(
                    organization_id=org_b.id,
                    business_name="Synthetic Merchant B",
                    onboarding_status="approved",
                ),
                OrganizationMembership(
                    organization_id=org_a.id,
                    user_id=users["owner"].id,
                    role="owner",
                    status="active",
                ),
                OrganizationMembership(
                    organization_id=org_a.id,
                    user_id=users["viewer"].id,
                    role="viewer",
                    status="active",
                ),
                OrganizationMembership(
                    organization_id=org_b.id,
                    user_id=users["outsider"].id,
                    role="owner",
                    status="active",
                ),
            ])

            main_order = PaymentOrder(
                organization_id=org_a.id,
                merchant_order_reference=(
                    "full-http-main-" + suffix
                ),
                amount_minor_units=149900,
                currency="INR",
                status="open",
            )

            other_order = PaymentOrder(
                organization_id=org_a.id,
                merchant_order_reference=(
                    "full-http-other-" + suffix
                ),
                amount_minor_units=149900,
                currency="INR",
                status="open",
            )

            db.add_all([main_order, other_order])
            db.flush()

            tokens = {}

            session_cases = {
                "owner": ("owner", "active"),
                "viewer": ("viewer", "active"),
                "outsider": ("outsider", "active"),
                "expired": ("owner", "expired"),
                "revoked": ("owner", "revoked"),
            }

            for label, (username, state) in session_cases.items():
                raw = secrets.token_urlsafe(48)
                tokens[label] = raw

                created_at = now
                expires_at = now + timedelta(hours=2)
                revoked_at = None

                if state == "expired":
                    created_at = now - timedelta(days=3)
                    expires_at = now - timedelta(days=1)

                if state == "revoked":
                    revoked_at = now

                db.add(
                    UserSession(
                        user_id=users[username].id,
                        token_hash=hash_secure_token(raw),
                        created_at=created_at,
                        expires_at=expires_at,
                        revoked_at=revoked_at,
                    )
                )

            db.flush()

            return {
                "org_a": org_a.id,
                "org_b": org_b.id,
                "main_order": main_order.id,
                "other_order": other_order.id,
                "tokens": tokens,
            }


def attempt_counts(conn, org_id, order_id):
    params = {
        "org": org_id,
        "order_id": order_id,
    }

    attempts = conn.execute(
        text("""
            SELECT COUNT(*)
            FROM payflow.payment_attempts
            WHERE organization_id = :org
              AND order_id = :order_id
        """),
        params,
    ).scalar_one()

    mappings = conn.execute(
        text("""
            SELECT COUNT(*)
            FROM payflow.payment_attempt_idempotency_records
            WHERE organization_id = :org
              AND order_id = :order_id
        """),
        params,
    ).scalar_one()

    return attempts, mappings


def check_http(response, expected, label):
    ensure(
        response.status_code == expected,
        (
            f"{label}: expected HTTP {expected}, "
            f"received {response.status_code}; "
            f"body={response.text[:250]}"
        ),
    )


def exercise_full_http(conn, fixture):
    app = FastAPI()

    # The actual router and actual session endpoint,
    # but mounted ONLY in this isolated test app.
    app.include_router(session_api.router)
    app.include_router(attempt_api.router)

    def disposable_session():
        # Each HTTP request gets a real SQLAlchemy Session.
        # Session commits release SAVEPOINTS, never the
        # migrator-owned outer test transaction.
        with Session(
            bind=conn,
            expire_on_commit=False,
            join_transaction_mode="create_savepoint",
        ) as db:
            yield db

    # Override ONLY the DB factory.
    # Authentication, CSRF, RBAC, and attempt services
    # remain the real implementations.
    app.dependency_overrides[get_db] = disposable_session

    def endpoint(org=None, order=None):
        org = org or fixture["org_a"]
        order = order or fixture["main_order"]

        return (
            f"/api/v1/organizations/{org}"
            f"/payment-orders/{order}/attempts"
        )

    def request_headers(label, key, csrf=None):
        headers = {
            "Idempotency-Key": key,
        }

        if label is not None:
            headers["Cookie"] = (
                "payflow_session="
                + fixture["tokens"][label]
            )

        if csrf is not None:
            headers["X-CSRF-Token"] = csrf

        return headers

    def csrf_for(client, label):
        response = client.get(
            "/api/v1/auth/csrf",
            headers=request_headers(label, KEY_ONE),
        )

        check_http(
            response,
            200,
            "CSRF token for " + label,
        )

        return response.json()["token"]

    def post(
        client,
        label="owner",
        key=KEY_ONE,
        csrf=None,
        org=None,
        order=None,
    ):
        return client.post(
            endpoint(org, order),
            headers=request_headers(label, key, csrf),
        )

    main = fixture["main_order"]
    organization = fixture["org_a"]

    with TestClient(
        app,
        raise_server_exceptions=False,
    ) as client:
        # Authentication must be enforced on the real route.
        check_http(
            post(client, label=None),
            401,
            "Unauthenticated attempt",
        )

        owner_csrf = csrf_for(client, "owner")

        print("PASS: Real stored owner session and CSRF")

        check_http(
            post(client),
            403,
            "Missing CSRF",
        )

        check_http(
            post(
                client,
                csrf="invalid-csrf",
            ),
            403,
            "Invalid CSRF",
        )

        print("PASS: Missing and invalid CSRF rejected")

        # First real sandbox attempt.
        first_response = post(
            client,
            csrf=owner_csrf,
        )

        check_http(
            first_response,
            201,
            "First HTTP payment attempt",
        )

        first = first_response.json()
        first_id = uuid.UUID(first["id"])

        ensure(
            first["replayed"] is False,
            "First request unexpectedly replayed",
        )

        ensure(
            first["attempt_number"] == 1,
            "Incorrect initial attempt number",
        )

        ensure(
            first["status"] == "created",
            "Incorrect initial state",
        )

        ensure(
            first["provider_code"] == "sandbox",
            "Unexpected payment provider",
        )

        ensure(
            first["amount_minor_units"] == 149900
            and first["currency"] == "INR",
            "Amount or currency mismatch",
        )

        ensure(
            attempt_counts(conn, organization, main) == (1, 1),
            "First HTTP request did not persist one mapping",
        )

        print("PASS: Real HTTP request created one payment attempt")

        # Repeat the identical request.
        replay_response = post(
            client,
            csrf=owner_csrf,
        )

        check_http(
            replay_response,
            200,
            "Idempotent HTTP replay",
        )

        replay = replay_response.json()

        ensure(
            replay["replayed"] is True,
            "Replay flag missing",
        )

        ensure(
            uuid.UUID(replay["id"]) == first_id,
            "Replay returned another attempt",
        )

        ensure(
            attempt_counts(conn, organization, main) == (1, 1),
            "Replay created duplicate records",
        )

        print("PASS: Same key returned original persisted attempt")

        # A different key cannot create another active attempt.
        check_http(
            post(
                client,
                key=KEY_TWO,
                csrf=owner_csrf,
            ),
            409,
            "Different key while attempt active",
        )

        ensure(
            attempt_counts(conn, organization, main) == (1, 1),
            "Rejected retry left an idempotency reservation",
        )

        print("PASS: Active attempt blocks different key")

        # The same key cannot be rebound to another order.
        check_http(
            post(
                client,
                key=KEY_ONE,
                csrf=owner_csrf,
                order=fixture["other_order"],
            ),
            409,
            "Same key for another order",
        )

        ensure(
            attempt_counts(
                conn,
                organization,
                fixture["other_order"],
            ) == (0, 0),
            "Key conflict created records for another order",
        )

        print("PASS: Key cannot be rebound to another order")

        # Real persisted role and tenant checks.
        viewer_csrf = csrf_for(client, "viewer")

        check_http(
            post(
                client,
                label="viewer",
                csrf=viewer_csrf,
            ),
            403,
            "Viewer attempt creation",
        )

        check_http(
            post(
                client,
                csrf=owner_csrf,
                org=fixture["org_b"],
            ),
            404,
            "Cross-tenant attempt creation",
        )

        print("PASS: Real PostgreSQL RBAC and tenant isolation")

        # Real invalid-session checks.
        for label in ("expired", "revoked"):
            check_http(
                post(
                    client,
                    label=label,
                    csrf=owner_csrf,
                ),
                401,
                label + " session",
            )

        print("PASS: Expired and revoked sessions rejected")

        # Synthetic lifecycle transition. No gateway call.
        changed = conn.execute(
            text("""
                UPDATE payflow.payment_attempts
                SET status = 'failed'
                WHERE id = :attempt_id
                  AND organization_id = :org
                  AND order_id = :order_id
                  AND status = 'created'
            """),
            {
                "attempt_id": first_id,
                "org": organization,
                "order_id": main,
            },
        )

        ensure(
            changed.rowcount == 1,
            "Unable to stage synthetic failed state",
        )

        failed_replay_response = post(
            client,
            csrf=owner_csrf,
        )

        check_http(
            failed_replay_response,
            200,
            "Replay after failure",
        )

        failed_replay = failed_replay_response.json()

        ensure(
            uuid.UUID(failed_replay["id"]) == first_id,
            "Failed attempt replay changed identity",
        )

        ensure(
            failed_replay["status"] == "failed",
            "Replay did not return persisted failed state",
        )

        print("PASS: Original failed attempt replayed")

        # A NEW key is now eligible for a second attempt.
        second_response = post(
            client,
            key=KEY_TWO,
            csrf=owner_csrf,
        )

        check_http(
            second_response,
            201,
            "New-key retry after failure",
        )

        second = second_response.json()

        ensure(
            second["attempt_number"] == 2,
            "Retry attempt number incorrect",
        )

        ensure(
            uuid.UUID(second["id"]) != first_id,
            "New key returned old attempt",
        )

        ensure(
            second["status"] == "created",
            "Retry state incorrect",
        )

        ensure(
            attempt_counts(conn, organization, main) == (2, 2),
            "Retry did not create exactly two mapped attempts",
        )

        print("PASS: New key created second attempt after failure")

        # Old-key replay must still return attempt 1.
        original_again = post(
            client,
            csrf=owner_csrf,
        )

        check_http(
            original_again,
            200,
            "Original replay after retry",
        )

        original_body = original_again.json()

        ensure(
            uuid.UUID(original_body["id"]) == first_id,
            "Old key no longer maps to original attempt",
        )

        ensure(
            original_body["attempt_number"] == 1
            and original_body["status"] == "failed",
            "Old key no longer preserves attempt 1",
        )

        print("PASS: Old key remains bound after a successful retry")

    # Verify actual persisted rows, not only HTTP payloads.
    rows = conn.execute(
        text("""
            SELECT attempt_number, status,
                   provider_code, provider_payment_id
            FROM payflow.payment_attempts
            WHERE organization_id = :org
              AND order_id = :order_id
            ORDER BY attempt_number
        """),
        {"org": organization, "order_id": main},
    ).all()

    ensure(
        [(r.attempt_number, r.status) for r in rows]
        == [(1, "failed"), (2, "created")],
        "Persisted attempt lifecycle is incorrect",
    )

    ensure(
        all(
            row.provider_code == "sandbox"
            and row.provider_payment_id is None
            for row in rows
        ),
        "Unexpected real payment provider linkage",
    )

    mapped_rows = conn.execute(
        text("""
            SELECT idempotency_key, status, attempt_number
            FROM payflow.payment_attempt_idempotency_records
            WHERE organization_id = :org
              AND order_id = :order_id
            ORDER BY attempt_number
        """),
        {"org": organization, "order_id": main},
    ).all()

    ensure(
        [
            (r.idempotency_key, r.status, r.attempt_number)
            for r in mapped_rows
        ] == [
            (KEY_ONE, "completed", 1),
            (KEY_TWO, "completed", 2),
        ],
        "Stored idempotency mapping incorrect",
    )

    old_order_idem_count = conn.execute(
        text("""
            SELECT COUNT(*)
            FROM payflow.payment_idempotency_records
        """)
    ).scalar_one()

    ensure(
        old_order_idem_count == 0,
        "Unexpected order-idempotency records",
    )

    print("PASS: Actual attempt and mapping rows verified")
    print("PASS: No gateway IDs or actual payment processing")


def test_full_sandbox_http_postgresql_integration():
    url = target_url()

    engine = create_engine(
        url,
        poolclass=NullPool,
        connect_args={"connect_timeout": 5},
    )

    test_error = None
    completed = False

    try:
        with engine.connect() as conn:
            outer = conn.begin()

            try:
                try:
                    conn.exec_driver_sql(
                        "SET LOCAL lock_timeout = '5s'"
                    )

                    conn.exec_driver_sql(
                        "SET LOCAL statement_timeout = '20s'"
                    )

                    clean_baseline(conn)

                    active_clients = conn.execute(
                        text("""
                            SELECT COUNT(*)
                            FROM pg_catalog.pg_stat_activity
                            WHERE datname = current_database()
                              AND pid <> pg_backend_pid()
                              AND backend_type = 'client backend'
                        """)
                    ).scalar_one()

                    ensure(
                        active_clients == 0,
                        "Other disposable DB clients detected",
                    )

                    print("PASS: Disposable database clean and isolated")

                    stage_migrations(conn)

                    fixture = create_fixture(conn)

                    print("PASS: Synthetic sessions and orders staged")

                    exercise_full_http(conn, fixture)

                    completed = True

                except BaseException as exc:
                    test_error = exc

            finally:
                if outer.is_active:
                    outer.rollback()

                print("PASS: Outer transaction rollback requested")

        # Independent read-only connection.
        print("\n=== POST-ROLLBACK INSPECTION ===")

        with engine.connect() as conn:
            with conn.begin():
                conn.exec_driver_sql(
                    "SET TRANSACTION READ ONLY"
                )

                read_only = conn.execute(
                    text("""
                        SELECT current_setting(
                            'transaction_read_only'
                        )
                    """)
                ).scalar_one()

                ensure(
                    read_only == "on",
                    "Final inspection must be read-only",
                )

                clean_baseline(conn)

                print("PASS: Base Alembic revision unchanged")
                print("PASS: Pending migrations absent")
                print("PASS: All 11 application tables empty")
                print("PASS: Final connection read-only")

    finally:
        engine.dispose()

    if test_error is not None:
        raise test_error

    ensure(
        completed,
        "Full HTTP test did not complete",
    )

    print("\n========================================")
    print("PAYFLOW FULL HTTP POSTGRESQL INTEGRATION VERIFIED")
    print("========================================")
