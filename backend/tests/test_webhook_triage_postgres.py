"""Real PostgreSQL advisory-lock tests for sandbox webhook triage.

Explicit opt-in only. Runs against the existing approved, empty,
local disposable PostgreSQL database.

This module reuses the already-tested concurrency fixture harness,
which stages migrations and synthetic organizations only within
the approved disposable database.

The fixture is temporarily committed so two independent PostgreSQL
connections can exercise transaction-scoped advisory locks.

All generated data and staged migrations are removed in finally.
An interrupted test may leave synthetic state behind. Never rerun
without inspecting the disposable database after such an interruption.

No real payment operations, gateway calls, HTTP routes, financial
status mutations, or persistent quarantine transitions.

This test does not establish RBAC authorization for a public API.
The triage service remains an internal, development-only component.
"""

import importlib.util
import os
import threading
import time

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

import app.services.webhook_inbox as webhook_inbox
import app.services.webhook_triage as webhook_triage

from app.payments.webhook_processing_policy import (
    TriageAction,
    TriageReason,
)


TARGET = "payflow_payment_drill_20261117_020846_9fbac781"

pytestmark = pytest.mark.skipif(
    os.environ.get("PAYFLOW_TRIAGE_LOCK_TEST_DB") != TARGET,
    reason="Explicit disposable PostgreSQL triage-lock opt-in required",
)


def ensure(condition, message):
    if not condition:
        raise AssertionError(message)


def load_existing_disposable_harness():
    """Reuse the established database identity and cleanup guards."""

    path = Path(__file__).with_name(
        "test_webhook_inbox_concurrency_postgres.py"
    )

    ensure(path.is_file(), "Disposable test harness missing")

    spec = importlib.util.spec_from_file_location(
        "payflow_triage_disposable_harness",
        path,
    )

    ensure(
        spec is not None and spec.loader is not None,
        "Unable to load disposable database test harness",
    )

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    required = (
        "approved_urls",
        "verify_identity",
        "verify_baseline",
        "provision",
        "cleanup",
        "signed_event",
    )

    for name in required:
        ensure(
            callable(getattr(module, name, None)),
            f"Required disposable test helper unavailable: {name}",
        )

    return module


def enable_synthetic_test_services(monkeypatch):
    settings = SimpleNamespace(
        app_env="development",
        sandbox_payment_attempts_enabled=True,
    )

    monkeypatch.setattr(
        webhook_inbox,
        "get_settings",
        lambda: settings,
    )

    monkeypatch.setattr(
        webhook_triage,
        "get_settings",
        lambda: settings,
    )


def create_inbox_events(runtime, harness, org_a, org_b):
    """Create three authenticated events through the inbox service.

    This transaction commits only to the approved disposable DB.
    The returned records are not payment settlement confirmations.
    """

    with Session(runtime, expire_on_commit=False) as db:
        with db.begin():
            first = webhook_inbox.receive_sandbox_webhook(
                db,
                **harness.signed_event(
                    org_a,
                    "evt_triage_lock_a_001",
                ),
            )

            same_tenant_other = (
                webhook_inbox.receive_sandbox_webhook(
                    db,
                    **harness.signed_event(
                        org_a,
                        "evt_triage_lock_a_002",
                    ),
                )
            )

            other_tenant = (
                webhook_inbox.receive_sandbox_webhook(
                    db,
                    **harness.signed_event(
                        org_b,
                        "evt_triage_lock_b_001",
                    ),
                )
            )

            ensure(
                not first.replayed
                and not same_tenant_other.replayed
                and not other_tenant.replayed,
                "Unexpected duplicate while staging test events",
            )

            ensure(
                len({
                    first.record_id,
                    same_tenant_other.record_id,
                    other_tenant.record_id,
                }) == 3,
                "Test event record IDs are not distinct",
            )

            return {
                "first": first,
                "same_tenant_other": same_tenant_other,
                "other_tenant": other_tenant,
            }


def inspect(db, record):
    return webhook_triage.inspect_sandbox_webhook(
        db,
        organization_id=record.organization_id,
        record_id=record.record_id,
    )


def assert_review_only(result, record):
    ensure(
        result.record_id == record.record_id,
        "Triage returned incorrect inbox record",
    )

    ensure(
        result.organization_id == record.organization_id,
        "Triage returned incorrect organization",
    )

    ensure(
        result.action is TriageAction.QUARANTINE,
        "Unlinked sandbox event was not recommended for quarantine",
    )

    ensure(
        result.reason is TriageReason.UNKNOWN_OBJECT,
        "Unexpected triage reason",
    )

    ensure(
        result.persisted is False,
        "Read-only inspection claimed a persisted transition",
    )


def observe_database_blocking(
    migrator,
    harness,
    blocker_pid,
    waiting_pid,
):
    """Require evidence of actual PostgreSQL lock contention."""

    deadline = time.monotonic() + 7.0

    with migrator.connect() as conn:
        harness.verify_identity(
            conn,
            "payflow_migrator",
        )

        while time.monotonic() < deadline:
            blocking_pids = conn.execute(
                text("SELECT pg_blocking_pids(:pid)"),
                {"pid": waiting_pid},
            ).scalar_one()

            if blocker_pid in blocking_pids:
                return

            time.sleep(0.05)

    raise AssertionError(
        "Expected PostgreSQL advisory-lock blocking not observed"
    )


class IntentionalRollback(Exception):
    """Rollback marker for the test only."""


def exercise_two_inspectors(
    runtime,
    migrator,
    harness,
    first_record,
    second_record,
    *,
    expect_block,
    rollback_first=False,
):
    """Run two real sessions with separate PostgreSQL connections."""

    first_locked = threading.Event()
    second_started = threading.Event()
    release_first = threading.Event()

    pids = {}

    def first_worker():
        try:
            with Session(runtime, expire_on_commit=False) as db:
                try:
                    with db.begin():
                        db.execute(
                            text("SET LOCAL lock_timeout = '12s'")
                        )

                        db.execute(
                            text("SET LOCAL statement_timeout = '25s'")
                        )

                        pids["first"] = db.execute(
                            text("SELECT pg_backend_pid()")
                        ).scalar_one()

                        result = inspect(db, first_record)

                        assert_review_only(
                            result,
                            first_record,
                        )

                        first_locked.set()

                        if not release_first.wait(timeout=15):
                            raise TimeoutError(
                                "First inspector release timed out"
                            )

                        if rollback_first:
                            raise IntentionalRollback()

                    return result

                except IntentionalRollback:
                    return "rolled_back"

        finally:
            first_locked.set()

    def second_worker():
        try:
            with Session(runtime, expire_on_commit=False) as db:
                with db.begin():
                    db.execute(
                        text("SET LOCAL lock_timeout = '12s'")
                    )

                    db.execute(
                        text("SET LOCAL statement_timeout = '25s'")
                    )

                    pids["second"] = db.execute(
                        text("SELECT pg_backend_pid()")
                    ).scalar_one()

                    second_started.set()

                    result = inspect(db, second_record)

                    assert_review_only(
                        result,
                        second_record,
                    )

                    return result

        finally:
            second_started.set()

    with ThreadPoolExecutor(max_workers=2) as pool:
        first_future = pool.submit(first_worker)

        try:
            ensure(
                first_locked.wait(timeout=9),
                "First inspector never acquired a lock",
            )

            if first_future.done():
                first_future.result()

                raise AssertionError(
                    "First inspector exited before second started"
                )

            second_future = pool.submit(second_worker)

            ensure(
                second_started.wait(timeout=9),
                "Second inspector did not start",
            )

            if expect_block:
                observe_database_blocking(
                    migrator,
                    harness,
                    pids["first"],
                    pids["second"],
                )

                ensure(
                    not second_future.done(),
                    "Second inspector did not wait for the lock",
                )

                second_result = None

            else:
                # A distinct lock key must allow the second
                # inspector to finish while the first holds
                # its own transaction open.
                second_result = second_future.result(timeout=8)

            release_first.set()

            first_result = first_future.result(timeout=20)

            if expect_block:
                second_result = second_future.result(timeout=20)

        finally:
            release_first.set()

    return first_result, second_result


def assert_runtime_least_privilege(runtime, harness):
    with runtime.connect() as conn:
        harness.verify_identity(
            conn,
            "payflow_runtime",
        )

        for privilege in (
            "UPDATE",
            "DELETE",
            "TRUNCATE",
        ):
            granted = conn.execute(
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
                granted is False,
                f"Runtime unexpectedly has {privilege} privilege",
            )


def assert_inbox_unchanged(migrator, harness, records):
    with migrator.connect() as conn:
        harness.verify_identity(
            conn,
            "payflow_migrator",
        )

        rows = conn.execute(
            text("""
                SELECT id, organization_id, event_id,
                       event_type, status, processed_at
                FROM payflow.provider_event_inbox
            """)
        ).all()

        ensure(
            len(rows) == 3,
            f"Expected three inbox events, found {len(rows)}",
        )

        expected = {
            record.record_id: record.organization_id
            for record in records.values()
        }

        ensure(
            {row.id for row in rows} == set(expected),
            "Unexpected inbox record identity",
        )

        for row in rows:
            ensure(
                row.organization_id == expected[row.id],
                "Inbox organization changed",
            )

            ensure(
                row.status == "received",
                "Triage mutated inbox lifecycle",
            )

            ensure(
                row.processed_at is None,
                "Triage incorrectly marked event processed",
            )

            ensure(
                row.event_type == "payment.succeeded",
                "Triage modified event content",
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
                f"Financial table unexpectedly changed: {table}",
            )


def test_real_postgres_triage_locks(monkeypatch):
    harness = load_existing_disposable_harness()

    runtime_url, migrator_url = harness.approved_urls()

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

    enable_synthetic_test_services(monkeypatch)

    try:
        with runtime.connect() as conn:
            harness.verify_identity(
                conn,
                "payflow_runtime",
            )

        # Existing harness checks the expected empty baseline,
        # stages the migrations and creates two synthetic orgs.
        fixture = harness.provision(migrator)

        org_a, org_b = fixture

        print("PASS: Approved disposable database provisioned")

        assert_runtime_least_privilege(
            runtime,
            harness,
        )

        print("PASS: Runtime database permissions restricted")

        records = create_inbox_events(
            runtime,
            harness,
            org_a,
            org_b,
        )

        first = records["first"]
        same_tenant_other = records["same_tenant_other"]
        other_tenant = records["other_tenant"]

        print("PASS: Three authenticated synthetic events inserted")

        # ----------------------------------------------------
        # TEST 1 — SAME RECORD, TWO INDEPENDENT TRANSACTIONS
        # ----------------------------------------------------

        first_result, second_result = exercise_two_inspectors(
            runtime,
            migrator,
            harness,
            first,
            first,
            expect_block=True,
        )

        assert_review_only(first_result, first)
        assert_review_only(second_result, first)

        print("PASS: Same-record inspectors serialized")
        print("PASS: PostgreSQL blocking observed")
        print("PASS: Commit released the advisory lock")

        # ----------------------------------------------------
        # TEST 2 — TRANSACTION ROLLBACK RELEASES LOCK
        # ----------------------------------------------------

        first_result, second_result = exercise_two_inspectors(
            runtime,
            migrator,
            harness,
            first,
            first,
            expect_block=True,
            rollback_first=True,
        )

        ensure(
            first_result == "rolled_back",
            "Intentional rollback did not occur",
        )

        assert_review_only(second_result, first)

        print("PASS: Rollback releases advisory lock")

        # ----------------------------------------------------
        # TEST 3 — DIFFERENT RECORDS, SAME ORGANIZATION
        # ----------------------------------------------------

        first_result, second_result = exercise_two_inspectors(
            runtime,
            migrator,
            harness,
            first,
            same_tenant_other,
            expect_block=False,
        )

        assert_review_only(first_result, first)
        assert_review_only(
            second_result,
            same_tenant_other,
        )

        print("PASS: Independent records in same tenant do not block")

        # ----------------------------------------------------
        # TEST 4 — DIFFERENT ORGANIZATIONS
        # ----------------------------------------------------

        first_result, second_result = exercise_two_inspectors(
            runtime,
            migrator,
            harness,
            first,
            other_tenant,
            expect_block=False,
        )

        assert_review_only(first_result, first)
        assert_review_only(second_result, other_tenant)

        print("PASS: Independent tenants do not block")

        # ----------------------------------------------------
        # TEST 5 — CROSS-TENANT ROW LOOKUP MUST FAIL
        # ----------------------------------------------------

        with Session(runtime, expire_on_commit=False) as db:
            with db.begin():
                with pytest.raises(
                    webhook_triage.WebhookTriageNotFound
                ):
                    webhook_triage.inspect_sandbox_webhook(
                        db,
                        organization_id=org_b,
                        record_id=first.record_id,
                    )

        print("PASS: Cross-tenant inbox lookup denied")

        # ----------------------------------------------------
        # TEST 6 — TWO INSPECTIONS IN SAME TRANSACTION
        # ----------------------------------------------------

        with Session(runtime, expire_on_commit=False) as db:
            with db.begin():
                initial = inspect(db, first)
                repeated = inspect(db, first)

                assert_review_only(initial, first)
                assert_review_only(repeated, first)

                ensure(
                    initial == repeated,
                    "Repeated inspection changed decision",
                )

        print("PASS: Repeated inspection is read-only and stable")

        # ----------------------------------------------------
        # TEST 7 — VERIFY STORED STATE IS UNCHANGED
        # ----------------------------------------------------

        assert_inbox_unchanged(
            migrator,
            harness,
            records,
        )

        print("PASS: Inbox status and timestamps unchanged")
        print("PASS: No financial state mutations")

    finally:
        try:
            if fixture is not None:
                harness.cleanup(
                    migrator,
                    *fixture,
                )
        finally:
            runtime.dispose()
            migrator.dispose()

    # Independent read-only verification using fresh connection.
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

                mode = conn.execute(
                    text("""
                        SELECT current_setting(
                            'transaction_read_only'
                        )
                    """)
                ).scalar_one()

                ensure(
                    mode == "on",
                    "Final inspection must be read-only",
                )

                harness.verify_baseline(conn)

        print("PASS: Original database baseline restored")
        print("PASS: Independent read-only inspection")

    finally:
        inspection.dispose()

    print("PAYFLOW PHASE 3C.3B.2 POSTGRESQL LOCKS VERIFIED")
