"""Real PostgreSQL audit-schema and privilege verification.

Explicit opt-in only, against the approved local disposable DB.

The existing, validated PostgreSQL harness provisions the
previous migration chain and synthetic organizations.

This test independently applies the audit-only migration and
later removes it before running the established cleanup.

All audit INSERT probes occur in a transaction that is always
rolled back. No permanent audit records or inbox transitions.

No real payments, gateway calls, public routes, refund
processing, financial-state changes or worker activation.

If interrupted or cleanup fails, inspect the disposable
database before another run.
"""

import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

import app.services.webhook_inbox as webhook_inbox


TARGET = "payflow_payment_drill_20261117_020846_9fbac781"

pytestmark = pytest.mark.skipif(
    os.environ.get("PAYFLOW_QUARANTINE_AUDIT_TEST_DB") != TARGET,
    reason="Explicit disposable PostgreSQL audit opt-in required",
)

AUDIT_INSERT = text("""
    INSERT INTO payflow.webhook_quarantine_audit (
        organization_id,
        provider_code,
        event_id,
        reason_code,
        processor_identity,
        from_status,
        to_status
    )
    VALUES (
        :organization_id,
        :provider_code,
        :event_id,
        :reason_code,
        :processor_identity,
        :from_status,
        :to_status
    )
    RETURNING id, transitioned_at
""")


def ensure(condition, message):
    if not condition:
        raise AssertionError(message)


def load_module(path, name):
    ensure(path.is_file(), f"Required file missing: {path.name}")

    spec = importlib.util.spec_from_file_location(name, path)

    ensure(
        spec is not None and spec.loader is not None,
        "Unable to load local test dependency",
    )

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


def load_harness():
    return load_module(
        Path(__file__).with_name(
            "test_webhook_inbox_concurrency_postgres.py"
        ),
        "payflow_audit_postgres_harness",
    )


def load_migration():
    return load_module(
        Path(__file__).resolve().parents[1]
        / "alembic"
        / "versions"
        / "a7c4e91d2b30_webhook_quarantine_audit.py",
        "payflow_audit_postgres_migration",
    )


def bind_migration(migration, conn):
    context = MigrationContext.configure(
        conn,
        opts={"version_table_schema": "payflow"},
    )

    migration.op = Operations(context)


def enable_synthetic_inbox(monkeypatch):
    settings = SimpleNamespace(
        app_env="development",
        sandbox_payment_attempts_enabled=True,
    )

    monkeypatch.setattr(
        webhook_inbox,
        "get_settings",
        lambda: settings,
    )


def insert_verified_events(runtime, harness, org_a, org_b):
    events = (
        (
            "a",
            org_a,
            "evt_audit_only_org_a_001",
        ),
        (
            "b",
            org_b,
            "evt_audit_only_org_b_001",
        ),
    )

    results = {}

    with Session(runtime, expire_on_commit=False) as db:
        with db.begin():
            for key, organization_id, event_id in events:
                result = webhook_inbox.receive_sandbox_webhook(
                    db,
                    **harness.signed_event(
                        organization_id,
                        event_id,
                    ),
                )

                ensure(
                    result.replayed is False,
                    "Unexpected synthetic event replay",
                )

                results[key] = {
                    "organization_id": organization_id,
                    "event_id": event_id,
                    "record_id": result.record_id,
                }

    return results


def verify_runtime_permissions(runtime, harness):
    with runtime.connect() as conn:
        harness.verify_identity(conn, "payflow_runtime")

        for privilege in (
            "SELECT",
            "INSERT",
            "UPDATE",
            "DELETE",
            "TRUNCATE",
            "REFERENCES",
            "TRIGGER",
        ):
            permitted = conn.execute(
                text("""
                    SELECT has_table_privilege(
                        current_user,
                        'payflow.webhook_quarantine_audit',
                        :privilege
                    )
                """),
                {"privilege": privilege},
            ).scalar_one()

            ensure(
                permitted is False,
                f"Runtime unexpectedly has audit {privilege}",
            )

        for privilege in ("SELECT", "INSERT"):
            permitted = conn.execute(
                text("""
                    SELECT has_table_privilege(
                        current_user,
                        'payflow.provider_event_inbox',
                        :privilege
                    )
                """),
                {"privilege": privilege},
            ).scalar_one()

            ensure(
                permitted is True,
                f"Runtime inbox {privilege} privilege changed",
            )

        for privilege in ("UPDATE", "DELETE", "TRUNCATE"):
            permitted = conn.execute(
                text("""
                    SELECT has_table_privilege(
                        current_user,
                        'payflow.provider_event_inbox',
                        :privilege
                    )
                """),
                {"privilege": privilege},
            ).scalar_one()

            ensure(
                permitted is False,
                f"Runtime unexpectedly has inbox {privilege}",
            )

    print("PASS: Audit table inaccessible to runtime role")
    print("PASS: Existing inbox runtime privileges preserved")


def snapshot(migrator, harness):
    """Independently capture all relevant persisted state."""

    with migrator.connect() as conn:
        with conn.begin():
            conn.exec_driver_sql("SET TRANSACTION READ ONLY")

            harness.verify_identity(
                conn,
                "payflow_migrator",
            )

            inbox_rows = tuple(
                tuple(row)
                for row in conn.execute(
                    text("""
                        SELECT
                            id,
                            organization_id,
                            provider_code,
                            event_id,
                            event_type,
                            provider_object_id,
                            occurred_at,
                            signed_at,
                            payload_sha256,
                            status,
                            received_at,
                            processed_at
                        FROM payflow.provider_event_inbox
                        ORDER BY id
                    """)
                ).all()
            )

            counts = {}

            tables = (
                "payment_orders",
                "payment_attempts",
                "payment_idempotency_records",
                "payment_attempt_idempotency_records",
                "webhook_quarantine_audit",
            )

            for table in tables:
                counts[table] = conn.exec_driver_sql(
                    f"SELECT COUNT(*) FROM payflow.{table}"
                ).scalar_one()

            return inbox_rows, counts


def audit_values(organization_id, event_id):
    return {
        "organization_id": organization_id,
        "provider_code": "sandbox_sim",
        "event_id": event_id,
        "reason_code": "unlinked_payment",
        "processor_identity": "sandbox_audit_test_worker",
        "from_status": "received",
        "to_status": "quarantined",
    }


def expect_constraint_failure(conn, values, constraint_name):
    """An invalid INSERT must fail inside a rollback savepoint."""

    savepoint = conn.begin_nested()

    try:
        conn.execute(AUDIT_INSERT, values)

    except IntegrityError as error:
        savepoint.rollback()

        ensure(
            constraint_name in str(error.orig),
            f"Unexpected constraint failure: {constraint_name}",
        )

    else:
        savepoint.rollback()

        raise AssertionError(
            f"Constraint did not reject invalid data: {constraint_name}"
        )


def verify_database_constraints(
    migrator,
    harness,
    migration,
    events,
):
    """Exercise constraints without committing any audit record."""

    with migrator.connect() as conn:
        transaction = conn.begin()

        try:
            harness.verify_identity(
                conn,
                "payflow_migrator",
            )

            a = events["a"]
            b = events["b"]

            valid_a = audit_values(
                a["organization_id"],
                a["event_id"],
            )

            valid_b = audit_values(
                b["organization_id"],
                b["event_id"],
            )

            # Two different tenants can each have a valid
            # audit identity in the same transaction.
            first = conn.execute(
                AUDIT_INSERT,
                valid_a,
            ).one()

            second = conn.execute(
                AUDIT_INSERT,
                valid_b,
            ).one()

            ensure(
                first.id != second.id,
                "Audit identities are not distinct",
            )

            ensure(
                first.transitioned_at is not None
                and second.transitioned_at is not None,
                "Database audit timestamps missing",
            )

            print("PASS: Tenant-specific audit references accepted")
            print("PASS: Database-generated audit timestamps")

            # One audit record per event identity.
            expect_constraint_failure(
                conn,
                valid_a,
                "uq_webhook_quarantine_audit_event",
            )

            print("PASS: Duplicate audit prevented")

            # Organization B cannot claim organization A's
            # event identity.
            cross_tenant = audit_values(
                b["organization_id"],
                a["event_id"],
            )

            expect_constraint_failure(
                conn,
                cross_tenant,
                "fk_webhook_quarantine_audit_event_identity",
            )

            print("PASS: Cross-tenant event reference denied")

            unknown = audit_values(
                a["organization_id"],
                "evt_nonexistent_audit_999",
            )

            expect_constraint_failure(
                conn,
                unknown,
                "fk_webhook_quarantine_audit_event_identity",
            )

            print("PASS: Nonexistent event reference denied")

            invalid_reason = dict(valid_a)
            invalid_reason["reason_code"] = "confirmed_paid"

            expect_constraint_failure(
                conn,
                invalid_reason,
                "ck_webhook_quarantine_audit_reason_valid",
            )

            invalid_processor = dict(valid_a)
            invalid_processor["processor_identity"] = "invalid actor"

            expect_constraint_failure(
                conn,
                invalid_processor,
                "ck_webhook_quarantine_audit_processor_identity_valid",
            )

            invalid_provider = dict(valid_a)
            invalid_provider["provider_code"] = "live_provider"

            expect_constraint_failure(
                conn,
                invalid_provider,
                "ck_webhook_quarantine_audit_sandbox_only",
            )

            invalid_transition = dict(valid_a)
            invalid_transition["from_status"] = "processed"

            expect_constraint_failure(
                conn,
                invalid_transition,
                "ck_webhook_quarantine_audit_transition_valid",
            )

            print("PASS: Audit reason and processor constraints")
            print("PASS: Sandbox-only provider constraint")
            print("PASS: Restricted transition representation")

            # A downgrade must never discard audit history.
            bind_migration(migration, conn)

            with pytest.raises(
                RuntimeError,
                match="Refusing to drop non-empty",
            ):
                migration.downgrade()

            print("PASS: Nonempty audit downgrade rejected")

        finally:
            # Even the valid audit INSERTs are rolled back.
            transaction.rollback()

    print("PASS: Constraint probes committed no audit records")


def test_real_postgres_quarantine_audit_schema(monkeypatch):
    harness = load_harness()
    migration = load_migration()

    ensure(
        migration.revision == "a7c4e91d2b30"
        and migration.down_revision == "f3c2a119b607",
        "Unexpected audit migration revision",
    )

    runtime_url, migrator_url = harness.approved_urls()

    ensure(
        runtime_url.database == TARGET
        and migrator_url.database == TARGET,
        "Unapproved database target",
    )

    runtime = create_engine(
        runtime_url,
        poolclass=NullPool,
        connect_args={"connect_timeout": 5},
    )

    migrator = create_engine(
        migrator_url,
        poolclass=NullPool,
        connect_args={"connect_timeout": 5},
    )

    organizations = None
    audit_installed = False

    enable_synthetic_inbox(monkeypatch)

    try:
        # Existing harness verifies DB identity, empty baseline,
        # approved credentials and absence of other clients.
        organizations = harness.provision(migrator)

        org_a, org_b = organizations

        print("PASS: Approved disposable database provisioned")

        with migrator.begin() as conn:
            harness.verify_identity(
                conn,
                "payflow_migrator",
            )

            bind_migration(migration, conn)
            migration.upgrade()

            relation = conn.execute(
                text("""
                    SELECT to_regclass(
                        'payflow.webhook_quarantine_audit'
                    )
                """)
            ).scalar_one()

            ensure(
                relation is not None,
                "Audit schema was not created",
            )

        audit_installed = True

        print("PASS: Audit-only migration applied")

        verify_runtime_permissions(
            runtime,
            harness,
        )

        events = insert_verified_events(
            runtime,
            harness,
            org_a,
            org_b,
        )

        print("PASS: Two HMAC-verified inbox events stored")

        before = snapshot(
            migrator,
            harness,
        )

        ensure(
            len(before[0]) == 2,
            "Unexpected synthetic inbox count",
        )

        ensure(
            all(
                row[9] == "received"
                and row[11] is None
                for row in before[0]
            ),
            "Unexpected inbox lifecycle",
        )

        ensure(
            all(count == 0 for count in before[1].values()),
            "Unexpected financial or audit records",
        )

        verify_database_constraints(
            migrator,
            harness,
            migration,
            events,
        )

        after = snapshot(
            migrator,
            harness,
        )

        ensure(
            before == after,
            "Audit verification changed persisted data",
        )

        print("PASS: Independent before/after snapshots match")
        print("PASS: Inbox lifecycle unchanged")
        print("PASS: Financial tables unchanged")
        print("PASS: No audit records persisted")

    finally:
        try:
            if audit_installed:
                # Only remove a verified empty audit table.
                # The migration itself refuses to downgrade
                # when audit records exist.
                with migrator.begin() as conn:
                    harness.verify_identity(
                        conn,
                        "payflow_migrator",
                    )

                    count = conn.execute(
                        text("""
                            SELECT COUNT(*)
                            FROM payflow.webhook_quarantine_audit
                        """)
                    ).scalar_one()

                    ensure(
                        count == 0,
                        "Unexpected audit records: inspect database",
                    )

                    bind_migration(migration, conn)
                    migration.downgrade()

                print("PASS: Empty audit migration reversed")

            if organizations is not None:
                harness.cleanup(
                    migrator,
                    *organizations,
                )

        finally:
            runtime.dispose()
            migrator.dispose()

    # Independently inspect the original baseline after cleanup.
    verification = create_engine(
        migrator_url,
        poolclass=NullPool,
        connect_args={"connect_timeout": 5},
    )

    try:
        with verification.connect() as conn:
            with conn.begin():
                conn.exec_driver_sql(
                    "SET TRANSACTION READ ONLY"
                )

                harness.verify_baseline(conn)

                audit_relation = conn.execute(
                    text("""
                        SELECT to_regclass(
                            'payflow.webhook_quarantine_audit'
                        )
                    """)
                ).scalar_one()

                ensure(
                    audit_relation is None,
                    "Audit table remains after rollback",
                )

        print("PASS: Original disposable database baseline restored")

    finally:
        verification.dispose()

    print(
        "PAYFLOW PHASE 3C.3E.2B POSTGRESQL AUDIT VERIFIED"
    )
