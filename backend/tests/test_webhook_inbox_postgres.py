"""Rollback-only PostgreSQL integration for webhook ingestion.

EXPLICIT OPT-IN REQUIRED. Only the established, empty,
local disposable PostgreSQL database is permitted.

Three previously merged migrations are staged inside an
outer transaction. Neither schema nor data is committed.

This test verifies sequential database idempotency and
conflicting identities. True multi-connection race testing
requires a separate controlled database exercise.
"""

import hashlib
import hmac
import importlib.util
import json
import os
import uuid
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
from app.models import Organization
from app.payments.webhook_contracts import (
    WebhookVerificationError,
)


TARGET = "payflow_payment_drill_20261117_020846_9fbac781"
BASE = "b2c1f20a7d31"

SECRET = b"synthetic-inbox-postgres-key-" + b"x" * 32
NOW = 2_000_000_000

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
    os.environ.get("PAYFLOW_WEBHOOK_INBOX_TEST_DB") != TARGET,
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

    for raw, expected_user in (
        (settings.database_url, "payflow_runtime"),
        (settings.migration_database_url, "payflow_migrator"),
    ):
        parsed = make_url(raw)

        ensure(
            parsed.database == "payflow_db",
            "Unexpected source database",
        )
        ensure(
            parsed.username == expected_user,
            "Unexpected PostgreSQL role",
        )
        ensure(
            parsed.host in ("localhost", "127.0.0.1"),
            "Remote database prohibited",
        )
        ensure(
            parsed.port in (None, 5432),
            "Unexpected PostgreSQL port",
        )

    return make_url(
        settings.migration_database_url
    ).set(database=TARGET)


def verify_clean_baseline(conn):
    database, role = conn.execute(
        text("SELECT current_database(), current_user")
    ).one()

    ensure(database == TARGET, "Incorrect database")
    ensure(role == "payflow_migrator", "Incorrect role")

    revision = conn.execute(
        text("SELECT version_num FROM payflow.alembic_version")
    ).scalar_one()

    ensure(revision == BASE, "Unexpected Alembic revision")

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
        "Unexpected schema inventory",
    )

    for table in TABLES:
        count = conn.exec_driver_sql(
            f"SELECT COUNT(*) FROM payflow.{table}"
        ).scalar_one()

        ensure(count == 0, f"Unexpected existing records: {table}")

    for relation in (
        "payflow.provider_event_inbox",
        "payflow.payment_attempt_idempotency_records",
        "payflow.ux_payment_attempts_one_live_or_successful",
    ):
        ensure(
            conn.execute(
                text("SELECT to_regclass(:name)"),
                {"name": relation},
            ).scalar_one() is None,
            "Pending migration object exists",
        )


def load_migration(revision, filename):
    root = (
        Path(__file__).resolve().parents[1]
        / "alembic"
        / "versions"
    )

    spec = importlib.util.spec_from_file_location(
        f"webhook_inbox_{revision}",
        root / filename,
    )

    ensure(
        spec is not None and spec.loader is not None,
        "Migration source missing",
    )

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


def stage_migrations(conn):
    migrations = (
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

    context = MigrationContext.configure(
        conn,
        opts={"version_table_schema": "payflow"},
    )

    operations = Operations(context)
    previous = BASE

    for revision, filename in migrations:
        migration = load_migration(revision, filename)

        ensure(
            migration.revision == revision
            and migration.down_revision == previous,
            "Migration chain mismatch",
        )

        migration.op = operations
        migration.upgrade()
        previous = revision

    ensure(
        conn.execute(
            text("SELECT to_regclass('payflow.provider_event_inbox')")
        ).scalar_one() is not None,
        "Webhook inbox table not staged",
    )

    for privilege in ("UPDATE", "DELETE", "TRUNCATE"):
        granted = conn.execute(
            text("""
                SELECT has_table_privilege(
                    'payflow_runtime',
                    'payflow.provider_event_inbox',
                    :privilege
                )
            """),
            {"privilege": privilege},
        ).scalar_one()

        ensure(
            granted is False,
            f"Runtime privilege unexpectedly granted: {privilege}",
        )


def sign_event(organization_id, *, event_type="payment.succeeded",
               event_id="evt_inbox_001", timestamp=NOW):
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
    ).encode()

    signed = (
        b"v1."
        + str(timestamp).encode()
        + b"."
        + body
    )

    signature = "v1=" + hmac.new(
        SECRET, signed, hashlib.sha256
    ).hexdigest()

    return {
        "expected_organization_id": organization_id,
        "signing_secret": SECRET,
        "timestamp": str(timestamp),
        "signature": signature,
        "raw_body": body,
        "now": NOW,
    }


def count_inbox(db):
    return db.execute(
        text("SELECT COUNT(*) FROM payflow.provider_event_inbox")
    ).scalar_one()


def exercise_ingestion(conn, monkeypatch):
    monkeypatch.setattr(
        inbox,
        "get_settings",
        lambda: SimpleNamespace(
            app_env="development",
            sandbox_payment_attempts_enabled=True,
        ),
    )

    with Session(
        bind=conn,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    ) as db:
        with db.begin():
            suffix = uuid.uuid4().hex[:12]

            org_a = Organization(
                name="Webhook Inbox Test A",
                slug="webhook-inbox-a-" + suffix,
                status="active",
            )

            org_b = Organization(
                name="Webhook Inbox Test B",
                slug="webhook-inbox-b-" + suffix,
                status="active",
            )

            db.add_all([org_a, org_b])
            db.flush()

            original_request = sign_event(org_a.id)

            # Invalid signature must not create a row.
            invalid = dict(original_request)
            invalid["signature"] = "v1=" + "0" * 64

            with pytest.raises(WebhookVerificationError):
                inbox.receive_sandbox_webhook(db, **invalid)

            ensure(count_inbox(db) == 0, "Unverified event stored")
            print("PASS: Invalid signature rejected before insertion")

            # First valid delivery creates one durable row.
            first = inbox.receive_sandbox_webhook(
                db, **original_request
            )

            ensure(not first.replayed, "First delivery was replayed")
            ensure(first.status == "received", "Wrong inbox status")
            ensure(count_inbox(db) == 1, "First insertion failed")

            print("PASS: First verified event stored")

            # Identical delivery must reuse the same row.
            replay = inbox.receive_sandbox_webhook(
                db, **original_request
            )

            ensure(replay.replayed, "Duplicate not detected")
            ensure(
                replay.record_id == first.record_id,
                "Duplicate created another record",
            )
            ensure(count_inbox(db) == 1, "Duplicate row created")

            print("PASS: Exact duplicate returns original record")

            # A re-signed identical payload is still a duplicate.
            resigned = sign_event(
                org_a.id, timestamp=NOW - 1
            )

            replay_again = inbox.receive_sandbox_webhook(
                db, **resigned
            )

            ensure(
                replay_again.replayed
                and replay_again.record_id == first.record_id,
                "Re-signed delivery was not deduplicated",
            )

            ensure(
                count_inbox(db) == 1,
                "Re-signed delivery created another record",
            )

            print("PASS: Re-signed duplicate remains idempotent")

            # Same identity with different signed business content
            # must fail closed and preserve the original record.
            conflicting = sign_event(
                org_a.id,
                event_type="payment.failed",
            )

            with pytest.raises(inbox.WebhookInboxConflict):
                inbox.receive_sandbox_webhook(
                    db, **conflicting
                )

            ensure(
                count_inbox(db) == 1,
                "Conflicting event created another record",
            )

            stored_type = db.execute(
                text("""
                    SELECT event_type
                    FROM payflow.provider_event_inbox
                    WHERE id = :record_id
                """),
                {"record_id": first.record_id},
            ).scalar_one()

            ensure(
                stored_type == "payment.succeeded",
                "Conflict changed original content",
            )

            print("PASS: Event ID fingerprint conflict rejected")

            # Same event ID in a different organization is a
            # distinct namespace, not a cross-tenant duplicate.
            tenant_b_request = sign_event(org_b.id)

            with pytest.raises(WebhookVerificationError):
                inbox.receive_sandbox_webhook(
                    db,
                    **{
                        **tenant_b_request,
                        "expected_organization_id": org_a.id,
                    },
                )

            tenant_b_result = inbox.receive_sandbox_webhook(
                db, **tenant_b_request
            )

            ensure(
                not tenant_b_result.replayed,
                "Different tenant incorrectly deduplicated",
            )
            ensure(
                tenant_b_result.record_id != first.record_id,
                "Tenants share inbox record",
            )
            ensure(count_inbox(db) == 2, "Tenant isolation failure")

            print("PASS: Organization-scoped event identity")

            # Simulated ingestion never writes financial records.
            for table in (
                "payment_orders",
                "payment_attempts",
                "payment_idempotency_records",
                "payment_attempt_idempotency_records",
            ):
                count = db.execute(
                    text(f"SELECT COUNT(*) FROM payflow.{table}")
                ).scalar_one()

                ensure(
                    count == 0,
                    f"Unexpected financial record: {table}",
                )

            print("PASS: No payment status or financial writes")


def test_verified_webhook_inbox_postgresql(monkeypatch):
    url = approved_url()

    engine = create_engine(
        url,
        poolclass=NullPool,
        connect_args={"connect_timeout": 5},
    )

    error = None
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

                    verify_clean_baseline(conn)

                    competitors = conn.execute(
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
                        "Competing disposable database connections",
                    )

                    print("PASS: Disposable database preflight")

                    stage_migrations(conn)
                    print("PASS: Migrations staged without commit")
                    print("PASS: Runtime privilege restrictions verified")

                    exercise_ingestion(conn, monkeypatch)
                    completed = True

                except BaseException as exc:
                    error = exc

            finally:
                if outer.is_active:
                    outer.rollback()

                print("PASS: Outer transaction rolled back")

        # Independently prove that no new schema or records
        # survived using a fresh read-only connection.
        with engine.connect() as conn:
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
                    "Post-test inspection must be read-only",
                )

                verify_clean_baseline(conn)

                print("PASS: Original schema and records unchanged")
                print("PASS: Independent read-only inspection")

    finally:
        engine.dispose()

    if error is not None:
        raise error

    ensure(completed, "Webhook inbox verification incomplete")

    print("PAYFLOW WEBHOOK INBOX POSTGRESQL VERIFIED")
