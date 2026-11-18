"""Real PostgreSQL RBAC integration for the sandbox orchestrator.

Explicit opt-in only. Uses the established clean, disposable
local PostgreSQL test database and an outer rollback transaction.

Real:
- PostgreSQL users, organizations, memberships and sessions
- Stored session lookup and role-based authorization
- Tenant isolation, revocation, suspension and role changes

Simulated:
- Provider payment operations and reconciliation
- Development feature flag enabled only via isolated patch

No HTTP endpoint registration, gateway calls, payment writes,
production database access or permanent database changes.
"""

import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

import app.payments.sandbox_orchestrator as orchestration_module

from app.core.config import get_settings
from app.core.security import hash_secure_token
from app.models import (
    Organization,
    OrganizationMembership,
    User,
    UserSession,
)
from app.payments.contracts import (
    CreatePaymentCommand,
    CreateRefundCommand,
    FetchPaymentCommand,
    Money,
    PaymentState,
    ProviderErrorKind,
    RefundState,
)
from app.payments.provider_recovery import RecoveryAction
from app.payments.provider_registry import (
    ProviderRegistry,
    RegistryPolicy,
)
from app.payments.sandbox_orchestrator import (
    SandboxOrchestrationAccessDenied,
    SandboxPaymentOrchestrator,
)
from app.payments.sandbox_provider import SandboxScenario
from app.services.session_identity import get_authenticated_user


TARGET = "payflow_payment_drill_20261117_020846_9fbac781"
BASE_REVISION = "b2c1f20a7d31"

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
    os.environ.get("PAYFLOW_ORCH_RBAC_TEST_DB") != TARGET,
    reason="Explicit disposable PostgreSQL opt-in required",
)


def ensure(condition, message):
    if not condition:
        raise AssertionError(message)


def approved_url():
    settings = get_settings()

    ensure(
        settings.app_env == "development",
        "Development environment required",
    )

    for value, role in (
        (settings.database_url, "payflow_runtime"),
        (settings.migration_database_url, "payflow_migrator"),
    ):
        url = make_url(value)

        ensure(
            url.database == "payflow_db",
            "Unexpected configured source database",
        )
        ensure(
            url.username == role,
            "Unexpected PostgreSQL role",
        )
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


def clean_baseline(connection):
    database, role = connection.execute(
        text("SELECT current_database(), current_user")
    ).one()

    ensure(database == TARGET, "Wrong database")
    ensure(role == "payflow_migrator", "Wrong database role")

    revision = connection.execute(
        text("SELECT version_num FROM payflow.alembic_version")
    ).scalar_one()

    ensure(
        revision == BASE_REVISION,
        "Unexpected database migration revision",
    )

    actual_tables = set(
        connection.execute(
            text("""
                SELECT tablename
                FROM pg_catalog.pg_tables
                WHERE schemaname = 'payflow'
            """)
        ).scalars()
    )

    ensure(
        actual_tables == set(TABLES) | {"alembic_version"},
        "Unexpected database schema",
    )

    for table in TABLES:
        count = connection.exec_driver_sql(
            f"SELECT COUNT(*) FROM payflow.{table}"
        ).scalar_one()

        ensure(
            count == 0,
            f"Disposable database is not empty: {table}",
        )

    ensure(
        connection.execute(
            text("""
                SELECT to_regclass(
                    'payflow.payment_attempt_idempotency_records'
                )
            """)
        ).scalar_one() is None,
        "Unexpected newer migration object",
    )


def create_fixture(db):
    now = datetime.now(timezone.utc)
    suffix = uuid.uuid4().hex[:12]

    users = {}

    for role in ("owner", "viewer", "finance", "other_owner"):
        user = User(
            email=f"orchestrator-{role}-{suffix}@example.invalid",
            password_hash="!synthetic-disabled!",
            is_active=True,
            email_verified_at=now,
        )
        db.add(user)
        users[role] = user

    org_a = Organization(
        name="Orchestrator Integration A",
        slug=f"orch-a-{suffix}",
        status="active",
    )

    org_b = Organization(
        name="Orchestrator Integration B",
        slug=f"orch-b-{suffix}",
        status="active",
    )

    db.add_all([org_a, org_b])
    db.flush()

    memberships = {}

    for role in ("owner", "viewer", "finance"):
        membership = OrganizationMembership(
            organization_id=org_a.id,
            user_id=users[role].id,
            role=role,
            status="active",
        )
        db.add(membership)
        memberships[role] = membership

    db.add(
        OrganizationMembership(
            organization_id=org_b.id,
            user_id=users["other_owner"].id,
            role="owner",
            status="active",
        )
    )

    tokens = {}

    for role, user in users.items():
        raw_token = secrets.token_urlsafe(48)

        db.add(
            UserSession(
                user_id=user.id,
                token_hash=hash_secure_token(raw_token),
                created_at=now,
                expires_at=now + timedelta(hours=2),
            )
        )

        tokens[role] = raw_token

    db.flush()

    return org_a, org_b, memberships, tokens


def payment(organization_id, key="orch_payment_key_001"):
    return CreatePaymentCommand(
        organization_id=organization_id,
        order_reference="orchestrator_order_001",
        amount=Money(12000, "INR"),
        idempotency_key=key,
    )


def actor_from_session(db, raw_token):
    """Use the actual stored-session query for test callers."""
    user = get_authenticated_user(db, raw_token)

    if user is None:
        raise SandboxOrchestrationAccessDenied(
            "Authentication required"
        )

    return user.id


def exercise_real_authorization(db, monkeypatch):
    # Enable simulation only inside this test module's
    # orchestrator setting lookup. No .env changes.
    monkeypatch.setattr(
        orchestration_module,
        "get_settings",
        lambda: SimpleNamespace(
            app_env="development",
            sandbox_payment_attempts_enabled=True,
        ),
    )

    org_a, org_b, memberships, tokens = create_fixture(db)

    registry = ProviderRegistry(
        policy=RegistryPolicy(
            environment="development",
            sandbox_enabled=True,
        )
    )

    registry.register_sandbox(organization_id=org_a.id)
    registry.register_sandbox(
        organization_id=org_b.id,
        payment_scenario=SandboxScenario.TIMEOUT_AFTER_ACCEPT,
    )

    orchestrator = SandboxPaymentOrchestrator(
        registry=registry
    )

    owner_id = actor_from_session(db, tokens["owner"])
    viewer_id = actor_from_session(db, tokens["viewer"])
    finance_id = actor_from_session(db, tokens["finance"])
    other_id = actor_from_session(db, tokens["other_owner"])

    command_a = payment(org_a.id)

    # Authorized owner creates one synthetic payment.
    created = orchestrator.create_payment(
        db,
        actor_user_id=owner_id,
        command=command_a,
    )

    ensure(
        created.result is not None
        and created.result.state is PaymentState.SUCCEEDED,
        "Authorized payment simulation failed",
    )

    # Same request replays its original synthetic result.
    replay = orchestrator.create_payment(
        db,
        actor_user_id=owner_id,
        command=command_a,
    )

    ensure(replay == created, "Idempotent replay mismatch")
    print("PASS: Stored owner session and payment permission")

    fetch_a = FetchPaymentCommand(
        organization_id=org_a.id,
        provider_payment_id=created.result.provider_payment_id,
    )

    read = orchestrator.fetch_payment(
        db,
        actor_user_id=viewer_id,
        command=fetch_a,
    )

    ensure(read.result == created.result, "Viewer read failed")

    with pytest.raises(SandboxOrchestrationAccessDenied):
        orchestrator.create_payment(
            db,
            actor_user_id=viewer_id,
            command=command_a,
        )

    refund_a = CreateRefundCommand(
        organization_id=org_a.id,
        provider_payment_id=created.result.provider_payment_id,
        amount=Money(1000, "INR"),
        idempotency_key="orch_refund_key_001",
    )

    with pytest.raises(SandboxOrchestrationAccessDenied):
        orchestrator.create_refund(
            db,
            actor_user_id=viewer_id,
            command=refund_a,
        )

    print("PASS: Viewer may read but cannot create or refund")

    refunded = orchestrator.create_refund(
        db,
        actor_user_id=finance_id,
        command=refund_a,
    )

    ensure(
        refunded.result is not None
        and refunded.result.state is RefundState.SUCCEEDED,
        "Finance refund authorization failed",
    )

    print("PASS: Finance refund permission verified")

    # The other organization's owner cannot read tenant A.
    with pytest.raises(SandboxOrchestrationAccessDenied):
        orchestrator.fetch_payment(
            db,
            actor_user_id=other_id,
            command=fetch_a,
        )

    with pytest.raises(SandboxOrchestrationAccessDenied):
        orchestrator.create_payment(
            db,
            actor_user_id=owner_id,
            command=payment(org_b.id),
        )

    print("PASS: Cross-tenant access denied by PostgreSQL")

    # Tenant B simulates timeout-after-accept.
    command_b = payment(org_b.id)

    timeout = orchestrator.create_payment(
        db,
        actor_user_id=other_id,
        command=command_b,
    )

    ensure(
        timeout.result is None
        and timeout.provider_error is ProviderErrorKind.TIMEOUT
        and timeout.next_action is RecoveryAction.RECONCILE,
        "Timeout recovery decision incorrect",
    )

    original = orchestrator.reconcile_payment(
        db,
        actor_user_id=other_id,
        command=command_b,
    )

    ensure(
        original is not None
        and original.state is PaymentState.PROCESSING,
        "Timeout reconciliation failed",
    )

    print("PASS: Unknown payment outcome requires reconciliation")

    # Change the actual PostgreSQL membership role.
    memberships["owner"].role = "viewer"
    db.flush()

    with pytest.raises(SandboxOrchestrationAccessDenied):
        orchestrator.create_payment(
            db,
            actor_user_id=owner_id,
            command=command_a,
        )

    with pytest.raises(SandboxOrchestrationAccessDenied):
        orchestrator.create_refund(
            db,
            actor_user_id=owner_id,
            command=refund_a,
        )

    read = orchestrator.fetch_payment(
        db,
        actor_user_id=owner_id,
        command=fetch_a,
    )

    ensure(
        read.result == created.result,
        "Downgraded viewer should retain read access",
    )

    print("PASS: Live PostgreSQL role downgrade enforced")

    memberships["owner"].status = "revoked"
    db.flush()

    with pytest.raises(SandboxOrchestrationAccessDenied):
        orchestrator.fetch_payment(
            db,
            actor_user_id=owner_id,
            command=fetch_a,
        )

    with pytest.raises(SandboxOrchestrationAccessDenied):
        orchestrator.reconcile_payment(
            db,
            actor_user_id=owner_id,
            command=command_a,
        )

    print("PASS: Revoked membership denied")

    org_a.status = "suspended"
    db.flush()

    with pytest.raises(SandboxOrchestrationAccessDenied):
        orchestrator.fetch_payment(
            db,
            actor_user_id=viewer_id,
            command=fetch_a,
        )

    with pytest.raises(SandboxOrchestrationAccessDenied):
        orchestrator.create_refund(
            db,
            actor_user_id=finance_id,
            command=refund_a,
        )

    print("PASS: Suspended organization denied")

    # A revoked stored session must not supply an actor.
    other_session = db.query(UserSession).filter(
        UserSession.token_hash
        == hash_secure_token(tokens["other_owner"])
    ).one()

    other_session.revoked_at = datetime.now(timezone.utc)
    db.flush()

    ensure(
        get_authenticated_user(
            db,
            tokens["other_owner"],
        ) is None,
        "Revoked session remained authenticated",
    )

    with pytest.raises(SandboxOrchestrationAccessDenied):
        actor_from_session(db, tokens["other_owner"])

    print("PASS: Stored session revocation enforced")

    # The orchestrator must not persist any simulated money.
    for table in (
        "payment_orders",
        "payment_attempts",
        "payment_idempotency_records",
    ):
        count = db.execute(
            text(f"SELECT COUNT(*) FROM payflow.{table}")
        ).scalar_one()

        ensure(count == 0, f"Unexpected payment rows: {table}")

    print("PASS: No payment persistence or real gateway calls")


def test_real_postgresql_orchestrator_authorization(monkeypatch):
    url = approved_url()

    engine = create_engine(
        url,
        poolclass=NullPool,
        connect_args={"connect_timeout": 5},
    )

    test_error = None
    completed = False

    try:
        with engine.connect() as connection:
            outer = connection.begin()

            try:
                try:
                    connection.exec_driver_sql(
                        "SET LOCAL lock_timeout = '5s'"
                    )
                    connection.exec_driver_sql(
                        "SET LOCAL statement_timeout = '20s'"
                    )

                    clean_baseline(connection)

                    competitors = connection.execute(
                        text("""
                            SELECT COUNT(*)
                            FROM pg_catalog.pg_stat_activity
                            WHERE datname = current_database()
                              AND pid <> pg_backend_pid()
                              AND backend_type = 'client backend'
                        """)
                    ).scalar_one()

                    ensure(
                        competitors == 0,
                        "Other disposable DB clients detected",
                    )

                    print("PASS: Disposable PostgreSQL preflight")

                    with Session(
                        bind=connection,
                        expire_on_commit=False,
                        join_transaction_mode="create_savepoint",
                    ) as db:
                        with db.begin():
                            exercise_real_authorization(
                                db, monkeypatch
                            )

                    completed = True

                except BaseException as error:
                    test_error = error

            finally:
                if outer.is_active:
                    outer.rollback()

                print("PASS: Outer test transaction rolled back")

        # Separate connection verifies permanent DB unchanged.
        with engine.connect() as connection:
            with connection.begin():
                connection.exec_driver_sql(
                    "SET TRANSACTION READ ONLY"
                )

                read_only = connection.execute(
                    text("""
                        SELECT current_setting(
                            'transaction_read_only'
                        )
                    """)
                ).scalar_one()

                ensure(
                    read_only == "on",
                    "Final verification must be read-only",
                )

                clean_baseline(connection)

                print("PASS: Original schema and empty tables intact")
                print("PASS: Post-rollback read-only verification")

    finally:
        engine.dispose()

    if test_error is not None:
        raise test_error

    ensure(completed, "Integration did not complete")

    print("PAYFLOW PHASE 3B.5 POSTGRESQL RBAC VERIFIED")
