"""Real stored-session and RBAC HTTP test, rollback-only.

Real components:
- PostgreSQL User and UserSession records
- get_authenticated_user
- require_user
- csrf_token_for_session / require_authenticated_csrf
- require_organization_permission
- sandbox FastAPI route and transaction handling

The attempt service is deliberately stubbed: this phase
tests authentication and authorization, not payment writes.

The ONLY database connection targets the approved disposable DB.
All synthetic records are inside one rolled-back transaction.
"""

import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.api import payment_attempts_sandbox as api
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
from app.payments.contracts import Money, PaymentState
from app.services.payment_attempt_idempotency import (
    IdempotentSandboxAttemptResult,
)
from app.services.payment_attempts import (
    CreatedSandboxPaymentAttempt,
)


TARGET = "payflow_payment_drill_20261117_020846_9fbac781"
BASE = "b2c1f20a7d31"

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

KEY = "STORED_SECURITY_KEY_0001"

pytestmark = pytest.mark.skipif(
    os.environ.get("PAYFLOW_STORED_SECURITY_TEST_DB") != TARGET,
    reason="Explicit disposable PostgreSQL authorization required",
)


def ensure(condition, message):
    if not condition:
        raise AssertionError(message)


def authorized_url():
    settings = get_settings()

    ensure(
        settings.app_env == "development",
        "Development mode required",
    )

    for source, role in (
        (settings.database_url, "payflow_runtime"),
        (settings.migration_database_url, "payflow_migrator"),
    ):
        url = make_url(source)

        ensure(
            url.database == "payflow_db",
            "Unexpected configured database",
        )
        ensure(url.username == role, "Unexpected database role")
        ensure(
            url.host in ("localhost", "127.0.0.1"),
            "Remote database prohibited",
        )
        ensure(
            url.port in (None, 5432),
            "Unexpected PostgreSQL port",
        )

    return make_url(
        settings.migration_database_url
    ).set(database=TARGET)


def verify_identity(conn):
    database, role = conn.execute(
        text("SELECT current_database(), current_user")
    ).one()

    ensure(database == TARGET, "Incorrect database")
    ensure(
        role == "payflow_migrator",
        "Incorrect PostgreSQL role",
    )


def verify_clean_baseline(conn):
    verify_identity(conn)

    revision = conn.execute(
        text("SELECT version_num FROM payflow.alembic_version")
    ).scalar_one()

    ensure(revision == BASE, "Unexpected Alembic revision")

    table_names = set(
        conn.execute(
            text("""
                SELECT tablename
                FROM pg_catalog.pg_tables
                WHERE schemaname = 'payflow'
            """)
        ).scalars()
    )

    ensure(
        table_names == set(TABLES) | {"alembic_version"},
        "Unexpected schema inventory",
    )

    for table in TABLES:
        count = conn.exec_driver_sql(
            f"SELECT COUNT(*) FROM payflow.{table}"
        ).scalar_one()

        ensure(
            count == 0,
            f"Unexpected records in {table}: {count}",
        )

    for name in (
        "payflow.payment_attempt_idempotency_records",
        "payflow.ux_payment_attempts_one_live_or_successful",
    ):
        relation = conn.execute(
            text("SELECT to_regclass(:relation)"),
            {"relation": name},
        ).scalar_one()

        ensure(
            relation is None,
            f"Pending migration object exists: {name}",
        )


def create_fixture(conn):
    now = datetime.now(timezone.utc)
    token = uuid.uuid4().hex[:16]

    raw_tokens = {}

    with Session(
        bind=conn,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    ) as db:
        with db.begin():
            users = {}

            for label in (
                "owner",
                "viewer",
                "outsider",
                "inactive",
                "unverified",
            ):
                user = User(
                    email=f"stored-{label}-{token}@example.invalid",
                    password_hash="!synthetic-disabled!",
                    is_active=(label != "inactive"),
                    email_verified_at=(
                        None if label == "unverified" else now
                    ),
                )

                users[label] = user
                db.add(user)

            org_a = Organization(
                name="Stored Security Sandbox A",
                slug="stored-a-" + token,
                status="active",
            )

            org_b = Organization(
                name="Stored Security Sandbox B",
                slug="stored-b-" + token,
                status="active",
            )

            db.add_all([org_a, org_b])
            db.flush()

            db.add_all([
                MerchantProfile(
                    organization_id=org_a.id,
                    business_name="Sandbox Merchant A",
                    onboarding_status="approved",
                ),
                MerchantProfile(
                    organization_id=org_b.id,
                    business_name="Sandbox Merchant B",
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

            order = PaymentOrder(
                organization_id=org_a.id,
                merchant_order_reference="stored-" + token,
                amount_minor_units=149900,
                currency="INR",
                status="open",
            )

            db.add(order)
            db.flush()

            session_cases = {
                "owner": ("owner", "active"),
                "viewer": ("viewer", "active"),
                "outsider": ("outsider", "active"),
                "revoked": ("owner", "revoked"),
                "expired": ("owner", "expired"),
                "inactive": ("inactive", "active"),
                "unverified": ("unverified", "active"),
            }

            for label, (user_label, state) in session_cases.items():
                raw = secrets.token_urlsafe(48)
                raw_tokens[label] = raw

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
                        user_id=users[user_label].id,
                        token_hash=hash_secure_token(raw),
                        created_at=created_at,
                        expires_at=expires_at,
                        revoked_at=revoked_at,
                    )
                )

            db.flush()

            return {
                "owner_id": users["owner"].id,
                "org_a": org_a.id,
                "org_b": org_b.id,
                "order_id": order.id,
                "tokens": raw_tokens,
            }


def check_status(response, expected, label):
    ensure(
        response.status_code == expected,
        (
            f"{label}: expected HTTP {expected}, "
            f"received {response.status_code}; "
            f"body={response.text[:300]}"
        ),
    )


def run_http_security(conn, fixture):
    calls = []
    replay = {"value": False}

    def database_dependency():
        # Real SQLAlchemy sessions and real PostgreSQL.
        # Each API commit releases only its own SAVEPOINT.
        # The migrator-owned outer transaction remains active.
        with Session(
            bind=conn,
            join_transaction_mode="create_savepoint",
            expire_on_commit=False,
        ) as db:
            yield db

    def fake_attempt_service(
        db,
        *,
        actor_user_id,
        intent,
    ):
        calls.append((actor_user_id, intent))

        ensure(
            actor_user_id == fixture["owner_id"],
            "Unexpected actor reached payment service",
        )

        ensure(
            intent.organization_id == fixture["org_a"],
            "Unexpected organization reached payment service",
        )

        ensure(
            intent.order_id == fixture["order_id"],
            "Unexpected order reached payment service",
        )

        return IdempotentSandboxAttemptResult(
            attempt=CreatedSandboxPaymentAttempt(
                id=uuid.UUID(
                    "fa027ff0-0376-4291-bf5f-06179fe44301"
                ),
                organization_id=fixture["org_a"],
                order_id=fixture["order_id"],
                attempt_number=1,
                amount=Money(
                    minor_units=149900,
                    currency="INR",
                ),
                provider_code="sandbox",
                state=PaymentState.CREATED,
            ),
            replayed=replay["value"],
        )

    # Isolated FastAPI app. No modification to app.main.
    app = FastAPI()
    app.include_router(session_api.router)
    app.include_router(api.router)

    # Only the database factory is overridden.
    # require_user, real session lookup, CSRF and RBAC
    # remain unchanged.
    app.dependency_overrides[get_db] = database_dependency

    endpoint = (
        f"/api/v1/organizations/{fixture['org_a']}"
        f"/payment-orders/{fixture['order_id']}/attempts"
    )

    cross_tenant_endpoint = (
        f"/api/v1/organizations/{fixture['org_b']}"
        f"/payment-orders/{fixture['order_id']}/attempts"
    )

    def cookie_header(label):
        return {
            "Cookie": (
                "payflow_session="
                + fixture["tokens"][label]
            )
        }

    def post(client, label, csrf=None, url=endpoint):
        headers = {
            **cookie_header(label),
            "Idempotency-Key": KEY,
        }

        if csrf is not None:
            headers["X-CSRF-Token"] = csrf

        return client.post(url, headers=headers)

    with patch.object(
        api,
        "create_sandbox_payment_attempt_idempotent",
        side_effect=fake_attempt_service,
    ):
        with TestClient(
            app,
            raise_server_exceptions=False,
        ) as client:
            owner_csrf_response = client.get(
                "/api/v1/auth/csrf",
                headers=cookie_header("owner"),
            )

            check_status(
                owner_csrf_response,
                200,
                "Real stored owner session",
            )

            ensure(
                owner_csrf_response.headers.get(
                    "cache-control"
                ) == "no-store",
                "CSRF response caching not disabled",
            )

            csrf = owner_csrf_response.json()["token"]

            print(
                "PASS: Real stored session authenticated"
            )
            print(
                "PASS: Real CSRF endpoint issued token"
            )

            # Authorized owner creates a sandbox response.
            result = post(client, "owner", csrf)

            check_status(
                result,
                201,
                "Authorized owner",
            )

            ensure(
                len(calls) == 1,
                "Expected one service invocation",
            )

            ensure(
                result.json()["replayed"] is False,
                "Unexpected replay result",
            )

            print(
                "PASS: Real PostgreSQL owner membership authorized"
            )

            # The same request may be replayed.
            replay["value"] = True

            result = post(client, "owner", csrf)

            check_status(
                result,
                200,
                "Authorized replay",
            )

            ensure(
                len(calls) == 2,
                "Replay did not reach the service",
            )

            print(
                "PASS: Authorized HTTP replay behavior"
            )

            replay["value"] = False

            # A real authenticated viewer cannot create.
            viewer_csrf_response = client.get(
                "/api/v1/auth/csrf",
                headers=cookie_header("viewer"),
            )

            check_status(
                viewer_csrf_response,
                200,
                "Viewer session",
            )

            viewer_csrf = (
                viewer_csrf_response.json()["token"]
            )

            before = len(calls)

            check_status(
                post(client, "viewer", viewer_csrf),
                403,
                "Viewer cannot create payments",
            )

            ensure(
                len(calls) == before,
                "Viewer reached payment service",
            )

            print(
                "PASS: Viewer denied by real PostgreSQL RBAC"
            )

            # Owner A cannot access organization B.
            check_status(
                post(
                    client,
                    "owner",
                    csrf,
                    url=cross_tenant_endpoint,
                ),
                404,
                "Cross-tenant access",
            )

            ensure(
                len(calls) == before,
                "Cross-tenant request reached service",
            )

            print(
                "PASS: Cross-organization access hidden"
            )

            # Valid session but missing CSRF.
            check_status(
                post(client, "owner"),
                403,
                "Missing CSRF token",
            )

            check_status(
                post(
                    client,
                    "owner",
                    "invalid-csrf",
                ),
                403,
                "Invalid CSRF token",
            )

            check_status(
                post(
                    client,
                    "owner",
                    viewer_csrf,
                ),
                403,
                "Other-session CSRF token",
            )

            ensure(
                len(calls) == before,
                "CSRF failures reached service",
            )

            print(
                "PASS: Missing and mismatched CSRF rejected"
            )

            # Real UserSession query rejects these records.
            for label in (
                "revoked",
                "expired",
                "inactive",
                "unverified",
            ):
                response = post(
                    client,
                    label,
                    csrf,
                )

                check_status(
                    response,
                    401,
                    f"{label} session",
                )

                ensure(
                    len(calls) == before,
                    "Invalid session reached service",
                )

                print(
                    f"PASS: {label} session rejected"
                )

            # The owner membership is changed in PostgreSQL.
            changed = conn.execute(
                text("""
                    UPDATE payflow.organization_memberships
                    SET status = 'revoked'
                    WHERE organization_id = :org
                      AND user_id = :user
                      AND status = 'active'
                """),
                {
                    "org": fixture["org_a"],
                    "user": fixture["owner_id"],
                },
            )

            ensure(
                changed.rowcount == 1,
                "Membership revocation setup failed",
            )

            check_status(
                post(client, "owner", csrf),
                404,
                "Revoked membership",
            )

            print(
                "PASS: Revoked membership immediately denied"
            )

            # Restore membership solely inside test txn.
            changed = conn.execute(
                text("""
                    UPDATE payflow.organization_memberships
                    SET status = 'active'
                    WHERE organization_id = :org
                      AND user_id = :user
                      AND status = 'revoked'
                """),
                {
                    "org": fixture["org_a"],
                    "user": fixture["owner_id"],
                },
            )

            ensure(changed.rowcount == 1, "Membership restore failed")

            # A suspended organization must be hidden.
            changed = conn.execute(
                text("""
                    UPDATE payflow.organizations
                    SET status = 'suspended'
                    WHERE id = :org
                      AND status = 'active'
                """),
                {"org": fixture["org_a"]},
            )

            ensure(
                changed.rowcount == 1,
                "Organization suspension setup failed",
            )

            check_status(
                post(client, "owner", csrf),
                404,
                "Suspended organization",
            )

            print(
                "PASS: Suspended organization immediately denied"
            )

    # The payment service was stubbed throughout.
    # No attempt or payment-idempotency rows may exist.
    attempt_count = conn.execute(
        text("SELECT COUNT(*) FROM payflow.payment_attempts")
    ).scalar_one()

    idem_count = conn.execute(
        text("""
            SELECT COUNT(*)
            FROM payflow.payment_idempotency_records
        """)
    ).scalar_one()

    ensure(attempt_count == 0, "Unexpected payment attempts")
    ensure(idem_count == 0, "Unexpected payment idempotency rows")

    print("PASS: No payment attempts or gateway records created")


def test_real_stored_session_and_rbac_http():
    url = authorized_url()

    engine = create_engine(
        url,
        poolclass=NullPool,
        connect_args={"connect_timeout": 5},
    )

    test_error = None
    completed = False

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

                    verify_clean_baseline(conn)

                    other_clients = conn.execute(
                        text("""
                            SELECT COUNT(*)
                            FROM pg_catalog.pg_stat_activity
                            WHERE datname = current_database()
                              AND pid <> pg_backend_pid()
                              AND backend_type = 'client backend'
                        """)
                    ).scalar_one()

                    ensure(
                        other_clients == 0,
                        "Other database clients detected",
                    )

                    print("PASS: Approved disposable DB baseline")
                    print("PASS: No competing database connections")

                    fixture = create_fixture(conn)

                    print(
                        "PASS: Synthetic sessions and memberships staged"
                    )

                    run_http_security(conn, fixture)

                    completed = True

                finally:
                    if outer.is_active:
                        outer.rollback()

                    print(
                        "PASS: Outer test transaction rollback requested"
                    )

        except Exception as error:
            test_error = error

        # Independent read-only connection to confirm rollback.
        print("\n=== POST-ROLLBACK VERIFICATION ===")

        with engine.connect() as conn:
            with conn.begin():
                conn.exec_driver_sql(
                    "SET TRANSACTION READ ONLY"
                )

                readonly = conn.execute(
                    text(
                        "SELECT current_setting("
                        "'transaction_read_only')"
                    )
                ).scalar_one()

                ensure(
                    readonly == "on",
                    "Final inspection must be read-only",
                )

                verify_clean_baseline(conn)

                print(
                    "PASS: Original Alembic revision preserved"
                )

                print(
                    "PASS: All 11 application tables empty"
                )

                print(
                    "PASS: Pending migration objects absent"
                )

                print(
                    "PASS: Final verification read-only"
                )

    finally:
        engine.dispose()

    if test_error is not None:
        raise test_error

    ensure(
        completed,
        "Stored security verification did not complete",
    )

    print("\n========================================")
    print("PAYFLOW STORED HTTP SECURITY DB VERIFIED")
    print("========================================")
