"""Real PostgreSQL concurrency tests for the sandbox event inbox.

Explicit opt-in only. Uses the established empty disposable
PostgreSQL database, never the main development or production DB.

Synthetic organizations and migrations are temporarily committed
so independent database connections can observe each other.

Cleanup removes only synthetic data and reverses staged migrations.
If interrupted, inspect the disposable DB before running again.

No real payments, HTTP endpoints or provider integrations.
"""

import hashlib
import hmac
import importlib.util
import json
import os
import threading
import time
import uuid

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

import app.services.webhook_inbox as inbox
from app.core.config import get_settings


TARGET = "payflow_payment_drill_20261117_020846_9fbac781"
BASE = "b2c1f20a7d31"

NOW = 2_000_000_000
SECRET = b"synthetic-webhook-race-test-key-" + b"x" * 32

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

MIGRATIONS = (
    (
        "d7a2f6c8b310",
        "d7a2f6c8b310_one_live_payment_attempt.py",
    ),
    (
        "e4b3c1a8d205",
        "e4b3c1a8d205_attempt_idempotency_records.py",
    ),
    (
        "f3c2a119b607",
        "f3c2a119b607_verified_webhook_inbox.py",
    ),
)

pytestmark = pytest.mark.skipif(
    os.environ.get("PAYFLOW_WEBHOOK_RACE_TEST_DB") != TARGET,
    reason="Explicit disposable PostgreSQL opt-in required",
)


def ensure(condition, message):
    if not condition:
        raise AssertionError(message)


def approved_urls():
    settings = get_settings()

    ensure(
        settings.app_env == "development",
        "Development environment required",
    )

    urls = []

    for raw, username in (
        (settings.database_url, "payflow_runtime"),
        (settings.migration_database_url, "payflow_migrator"),
    ):
        url = make_url(raw)

        ensure(
            url.database == "payflow_db",
            "Unexpected configured source database",
        )

        ensure(
            url.username == username,
            "Unexpected database role",
        )

        ensure(
            url.host in ("localhost", "127.0.0.1"),
            "Remote database prohibited",
        )

        ensure(
            url.port in (None, 5432),
            "Unexpected PostgreSQL port",
        )

        urls.append(url.set(database=TARGET))

    return urls


def verify_identity(conn, expected_role):
    database, role = conn.execute(
        text("SELECT current_database(), current_user")
    ).one()

    ensure(
        database == TARGET and role == expected_role,
        "Unexpected database identity",
    )


def verify_baseline(conn):
    verify_identity(conn, "payflow_migrator")

    revision = conn.execute(
        text("SELECT version_num FROM payflow.alembic_version")
    ).scalar_one()

    ensure(
        revision == BASE,
        "Unexpected migration revision",
    )

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

    actual_tables = {name for name, _ in catalog}

    ensure(
        actual_tables == set(TABLES) | {"alembic_version"},
        "Unexpected disposable database schema",
    )

    ensure(
        not any(rls for _, rls in catalog),
        "Unexpected row-level security configuration",
    )

    for table in TABLES:
        count = conn.exec_driver_sql(
            f"SELECT COUNT(*) FROM payflow.{table}"
        ).scalar_one()

        ensure(
            count == 0,
            f"Disposable database contains records: {table}",
        )

    for relation in (
        "payflow.provider_event_inbox",
        "payflow.payment_attempt_idempotency_records",
        "payflow.ux_payment_attempts_one_live_or_successful",
    ):
        value = conn.execute(
            text("SELECT to_regclass(:relation)"),
            {"relation": relation},
        ).scalar_one()

        ensure(
            value is None,
            "Pending migration objects already exist",
        )


def verify_no_other_clients(conn):
    count = conn.execute(
        text("""
            SELECT COUNT(*)
            FROM pg_catalog.pg_stat_activity
            WHERE datname = current_database()
              AND pid <> pg_backend_pid()
              AND backend_type = 'client backend'
        """)
    ).scalar_one()

    ensure(
        count == 0,
        "Other disposable database clients detected",
    )


def load_migration(revision, filename):
    directory = (
        Path(__file__).resolve().parents[1]
        / "alembic"
        / "versions"
    )

    spec = importlib.util.spec_from_file_location(
        "webhook_concurrency_" + revision,
        directory / filename,
    )

    ensure(
        spec is not None and spec.loader is not None,
        "Migration file missing",
    )

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


def apply_migrations(conn, *, downgrade=False):
    context = MigrationContext.configure(
        conn,
        opts={"version_table_schema": "payflow"},
    )

    operations = Operations(context)

    migrations = [
        load_migration(revision, filename)
        for revision, filename in MIGRATIONS
    ]

    previous = BASE

    for migration in migrations:
        ensure(
            migration.down_revision == previous,
            "Migration revision chain mismatch",
        )
        previous = migration.revision

    ordered = (
        reversed(migrations)
        if downgrade
        else migrations
    )

    for migration in ordered:
        migration.op = operations

        if downgrade:
            migration.downgrade()
        else:
            migration.upgrade()


def provision(migrator):
    # Commit only inside the approved disposable database.
    with migrator.begin() as conn:
        verify_baseline(conn)
        verify_no_other_clients(conn)

        apply_migrations(conn)

        organization_a = uuid.uuid4()
        organization_b = uuid.uuid4()

        suffix = uuid.uuid4().hex[:12]

        conn.execute(
            text("""
                INSERT INTO payflow.organizations
                    (id, name, slug, status)
                VALUES
                    (:a, 'Webhook Race A', :slug_a, 'active'),
                    (:b, 'Webhook Race B', :slug_b, 'active')
            """),
            {
                "a": organization_a,
                "b": organization_b,
                "slug_a": "webhook-race-a-" + suffix,
                "slug_b": "webhook-race-b-" + suffix,
            },
        )

        count = conn.execute(
            text("""
                SELECT COUNT(*)
                FROM payflow.organizations
                WHERE id IN (:a, :b)
            """),
            {
                "a": organization_a,
                "b": organization_b,
            },
        ).scalar_one()

        ensure(
            count == 2,
            "Synthetic organization creation failed",
        )

    return organization_a, organization_b


def cleanup(migrator, organization_a, organization_b):
    # Cleanup is limited to generated organization IDs.
    with migrator.begin() as conn:
        verify_identity(conn, "payflow_migrator")

        total_events = conn.execute(
            text("""
                SELECT COUNT(*)
                FROM payflow.provider_event_inbox
            """)
        ).scalar_one()

        owned_events = conn.execute(
            text("""
                SELECT COUNT(*)
                FROM payflow.provider_event_inbox
                WHERE organization_id IN (:a, :b)
            """),
            {
                "a": organization_a,
                "b": organization_b,
            },
        ).scalar_one()

        ensure(
            total_events == owned_events,
            "Unexpected webhook events: manual inspection required",
        )

        unexpected_organizations = conn.execute(
            text("""
                SELECT COUNT(*)
                FROM payflow.organizations
                WHERE id NOT IN (:a, :b)
            """),
            {
                "a": organization_a,
                "b": organization_b,
            },
        ).scalar_one()

        ensure(
            unexpected_organizations == 0,
            "Unexpected organizations: manual inspection required",
        )

        conn.execute(
            text("""
                DELETE FROM payflow.provider_event_inbox
                WHERE organization_id IN (:a, :b)
            """),
            {
                "a": organization_a,
                "b": organization_b,
            },
        )

        removed = conn.execute(
            text("""
                DELETE FROM payflow.organizations
                WHERE id IN (:a, :b)
            """),
            {
                "a": organization_a,
                "b": organization_b,
            },
        )

        ensure(
            removed.rowcount == 2,
            "Synthetic organization cleanup mismatch",
        )

        apply_migrations(conn, downgrade=True)

        verify_baseline(conn)

    print("PASS: Synthetic data and staged migrations removed")


def signed_event(
    organization_id,
    event_id,
    event_type="payment.succeeded",
):
    payload = {
        "event_id": event_id,
        "organization_id": str(organization_id),
        "provider_code": "sandbox_sim",
        "event_type": event_type,
        "provider_object_id": "sim_pay_" + "a" * 32,
        "occurred_at": NOW - 5,
    }

    body = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    timestamp = str(NOW)

    signed = (
        b"v1."
        + timestamp.encode()
        + b"."
        + body
    )

    signature = "v1=" + hmac.new(
        SECRET,
        signed,
        hashlib.sha256,
    ).hexdigest()

    return {
        "expected_organization_id": organization_id,
        "signing_secret": SECRET,
        "timestamp": timestamp,
        "signature": signature,
        "raw_body": body,
        "now": NOW,
    }


class ExpectedRollback(Exception):
    pass


def observe_postgres_blocking(migrator, first_pid, second_pid):
    deadline = time.monotonic() + 6

    with migrator.connect() as conn:
        verify_identity(conn, "payflow_migrator")

        while time.monotonic() < deadline:
            blockers = conn.execute(
                text("SELECT pg_blocking_pids(:pid)"),
                {"pid": second_pid},
            ).scalar_one()

            if first_pid in blockers:
                return

            time.sleep(0.05)

    raise AssertionError(
        "PostgreSQL conflict blocking was not observed"
    )


def run_race(
    runtime,
    migrator,
    first_event,
    second_event,
    *,
    rollback_first=False,
    expect_block=True,
):
    first_ready = threading.Event()
    second_started = threading.Event()
    release_first = threading.Event()

    pids = {}

    def worker_one():
        try:
            with Session(runtime, expire_on_commit=False) as db:
                try:
                    with db.begin():
                        db.execute(
                            text("SET LOCAL lock_timeout = '12s'")
                        )

                        pids["first"] = db.execute(
                            text("SELECT pg_backend_pid()")
                        ).scalar_one()

                        result = inbox.receive_sandbox_webhook(
                            db,
                            **first_event,
                        )

                        first_ready.set()

                        if not release_first.wait(timeout=15):
                            raise TimeoutError(
                                "First transaction release timed out"
                            )

                        if rollback_first:
                            raise ExpectedRollback()

                    return result

                except ExpectedRollback:
                    return "rolled_back"

        finally:
            first_ready.set()

    def worker_two():
        try:
            with Session(runtime, expire_on_commit=False) as db:
                with db.begin():
                    db.execute(
                        text("SET LOCAL lock_timeout = '12s'")
                    )

                    pids["second"] = db.execute(
                        text("SELECT pg_backend_pid()")
                    ).scalar_one()

                    second_started.set()

                    return inbox.receive_sandbox_webhook(
                        db,
                        **second_event,
                    )

        except inbox.WebhookInboxConflict:
            return "conflict"

        finally:
            second_started.set()

    with ThreadPoolExecutor(max_workers=2) as pool:
        future_one = pool.submit(worker_one)

        try:
            ensure(
                first_ready.wait(timeout=9),
                "First worker did not become ready",
            )

            if future_one.done():
                future_one.result()
                raise AssertionError(
                    "First worker ended before second started"
                )

            future_two = pool.submit(worker_two)

            ensure(
                second_started.wait(timeout=9),
                "Second worker did not start",
            )

            if expect_block:
                observe_postgres_blocking(
                    migrator,
                    pids["first"],
                    pids["second"],
                )

                ensure(
                    not future_two.done(),
                    "Second worker completed unexpectedly early",
                )

                second_result = None

            else:
                second_result = future_two.result(timeout=8)

            release_first.set()

            first_result = future_one.result(timeout=20)

            if expect_block:
                second_result = future_two.result(timeout=20)

        finally:
            release_first.set()

    return first_result, second_result


def verify_results(migrator, organization_a, organization_b):
    with migrator.connect() as conn:
        verify_identity(conn, "payflow_migrator")

        rows = conn.execute(
            text("""
                SELECT organization_id, event_id, event_type,
                       status, processed_at
                FROM payflow.provider_event_inbox
                WHERE organization_id IN (:a, :b)
                ORDER BY event_id, organization_id
            """),
            {
                "a": organization_a,
                "b": organization_b,
            },
        ).all()

        ensure(
            len(rows) == 5,
            f"Expected 5 unique events, found {len(rows)}",
        )

        ensure(
            all(
                row.status == "received"
                and row.processed_at is None
                for row in rows
            ),
            "Unexpected event-processing status",
        )

        conflicts = [
            row for row in rows
            if row.event_id == "evt_concurrent_conflict_002"
        ]

        ensure(
            len(conflicts) == 1
            and conflicts[0].event_type == "payment.succeeded",
            "Conflicting event replaced original event",
        )

        for table in (
            "payment_orders",
            "payment_attempts",
            "payment_idempotency_records",
            "payment_attempt_idempotency_records",
        ):
            count = conn.exec_driver_sql(
                f"SELECT COUNT(*) FROM payflow.{table}"
            ).scalar_one()

            ensure(
                count == 0,
                f"Unexpected financial records in {table}",
            )

    print("PASS: Exactly five unique event records")
    print("PASS: Original event content preserved")
    print("PASS: No financial writes or event processing")


def test_concurrent_verified_webhook_ingestion(monkeypatch):
    runtime_url, migrator_url = approved_urls()

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

    fixture = None

    monkeypatch.setattr(
        inbox,
        "get_settings",
        lambda: SimpleNamespace(
            app_env="development",
            sandbox_payment_attempts_enabled=True,
        ),
    )

    try:
        with runtime.connect() as conn:
            verify_identity(conn, "payflow_runtime")

        fixture = provision(migrator)
        organization_a, organization_b = fixture

        print("PASS: Approved disposable database provisioned")

        with runtime.connect() as conn:
            verify_identity(conn, "payflow_runtime")

            for privilege in ("UPDATE", "DELETE", "TRUNCATE"):
                allowed = conn.execute(
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
                    not allowed,
                    f"Runtime unexpectedly has {privilege}",
                )

        print("PASS: Runtime privileges restricted")

        # 1. Two identical concurrent deliveries.
        original = signed_event(
            organization_a,
            "evt_concurrent_duplicate_001",
        )

        first, second = run_race(
            runtime,
            migrator,
            original,
            original,
        )

        ensure(
            first.replayed is False,
            "First event not inserted",
        )

        ensure(
            second.replayed is True,
            "Second delivery not recognized as replay",
        )

        ensure(
            first.record_id == second.record_id,
            "Duplicate created a different record",
        )

        print("PASS: Concurrent duplicate creates one record")
        print("PASS: PostgreSQL conflict blocking observed")

        # 2. Concurrent conflicting authenticated content.
        successful = signed_event(
            organization_a,
            "evt_concurrent_conflict_002",
        )

        failed = signed_event(
            organization_a,
            "evt_concurrent_conflict_002",
            event_type="payment.failed",
        )

        first, second = run_race(
            runtime,
            migrator,
            successful,
            failed,
        )

        ensure(
            first.replayed is False,
            "Original event not inserted",
        )

        ensure(
            second == "conflict",
            "Conflicting payload was not rejected",
        )

        print("PASS: Concurrent payload conflict rejected")

        # 3. First transaction aborts before commit.
        rollback_event = signed_event(
            organization_a,
            "evt_concurrent_rollback_003",
        )

        first, second = run_race(
            runtime,
            migrator,
            rollback_event,
            rollback_event,
            rollback_first=True,
        )

        ensure(
            first == "rolled_back",
            "First transaction did not roll back",
        )

        ensure(
            second.replayed is False,
            "Second worker could not claim rolled-back event",
        )

        print("PASS: Rollback releases event claim")

        # 4. Different tenants use the same event ID.
        tenant_a = signed_event(
            organization_a,
            "evt_concurrent_tenant_004",
        )

        tenant_b = signed_event(
            organization_b,
            "evt_concurrent_tenant_004",
        )

        first, second = run_race(
            runtime,
            migrator,
            tenant_a,
            tenant_b,
            expect_block=False,
        )

        ensure(
            first.replayed is False
            and second.replayed is False,
            "Tenant-scoped deduplication failed",
        )

        ensure(
            first.record_id != second.record_id,
            "Different tenants share an event record",
        )

        print("PASS: Independent tenant event identities")

        verify_results(
            migrator,
            organization_a,
            organization_b,
        )

    finally:
        try:
            if fixture is not None:
                cleanup(migrator, *fixture)
        finally:
            runtime.dispose()
            migrator.dispose()

    # Independent read-only verification after cleanup.
    inspection = create_engine(
        migrator_url,
        poolclass=NullPool,
        connect_args={"connect_timeout": 5},
    )

    try:
        with inspection.connect() as conn:
            with conn.begin():
                conn.exec_driver_sql(
                    "SET TRANSACTION READ ONLY"
                )

                ensure(
                    conn.execute(
                        text("""
                            SELECT current_setting(
                                'transaction_read_only'
                            )
                        """)
                    ).scalar_one() == "on",
                    "Final inspection must be read-only",
                )

                verify_baseline(conn)

        print("PASS: Original database baseline restored")
        print("PASS: Independent read-only verification")

    finally:
        inspection.dispose()

    print("PAYFLOW PHASE 3C.2C CONCURRENCY VERIFIED")
