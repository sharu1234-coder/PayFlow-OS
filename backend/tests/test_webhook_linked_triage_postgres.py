"""Real PostgreSQL integration test for read-only linked webhook triage.

EXPLICIT OPT-IN REQUIRED.

Uses only the previously approved, empty, local disposable
PostgreSQL database and its established fixture/cleanup helpers.

Synthetic payment references and authenticated sandbox webhook
events are temporarily committed to allow independent connections
to inspect them.

No real provider calls, money movement, refunds, public endpoints,
payment-state updates, or inbox processing transitions.

The test verifies exact before/after database snapshots, removes
synthetic fixtures and restores the original migration baseline.

On interruption or cleanup error, inspect the disposable database
before retrying.
"""

import importlib.util
import os
import uuid

from pathlib import Path
from types import SimpleNamespace

import pytest

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

import app.services.webhook_linked_triage as combined
import app.services.webhook_triage as base_triage

from app.payments.webhook_processing_policy import (
    TriageAction,
    TriageReason,
)
from app.services.webhook_payment_linkage import PaymentLinkKind
from app.services.webhook_triage import WebhookTriageNotFound


TARGET = "payflow_payment_drill_20261117_020846_9fbac781"

pytestmark = pytest.mark.skipif(
    os.environ.get("PAYFLOW_LINKED_TRIAGE_TEST_DB") != TARGET,
    reason="Explicit disposable PostgreSQL opt-in required",
)


def ensure(condition, message):
    if not condition:
        raise AssertionError(message)


def load_existing_fixture():
    """Reuse the already verified payment-linkage PostgreSQL fixture."""

    path = Path(__file__).with_name(
        "test_webhook_payment_linkage_postgres.py"
    )

    ensure(
        path.is_file(),
        "Approved linkage test fixture missing",
    )

    spec = importlib.util.spec_from_file_location(
        "payflow_combined_triage_fixture",
        path,
    )

    ensure(
        spec is not None and spec.loader is not None,
        "Unable to load approved linkage fixture",
    )

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    required = (
        "load_harness",
        "enable_sandbox",
        "make_financial_fixture",
        "insert_verified_events",
        "assert_runtime_select_privileges",
        "snapshot",
        "cleanup_financial_fixture",
    )

    for name in required:
        ensure(
            callable(getattr(module, name, None)),
            f"Missing verified fixture helper: {name}",
        )

    return module


def enable_services(monkeypatch, fixture):
    fixture.enable_sandbox(monkeypatch)

    settings = SimpleNamespace(
        app_env="development",
        sandbox_payment_attempts_enabled=True,
    )

    monkeypatch.setattr(
        combined,
        "get_settings",
        lambda: settings,
    )

    monkeypatch.setattr(
        base_triage,
        "get_settings",
        lambda: settings,
    )


def inspect(db, event):
    return combined.inspect_linked_sandbox_webhook(
        db,
        organization_id=event.organization_id,
        record_id=event.record_id,
    )


def assert_reconciliation_recommendation(
    result,
    event,
    attempt_id,
    order_id,
):
    ensure(
        result.organization_id == event.organization_id,
        "Incorrect tenant in reconciliation recommendation",
    )

    ensure(
        result.record_id == event.record_id,
        "Incorrect event in reconciliation recommendation",
    )

    ensure(
        result.action is TriageAction.RECONCILE,
        "Matched payment did not recommend reconciliation",
    )

    ensure(
        result.reason is TriageReason.READ_CONFIRMATION_REQUIRED,
        "Unexpected reconciliation reason",
    )

    ensure(
        result.linkage_kind is PaymentLinkKind.LOCAL_REFERENCE,
        "Matching local reference not recognized",
    )

    ensure(
        result.local_attempt_id == attempt_id,
        "Incorrect payment attempt association",
    )

    ensure(
        result.local_order_id == order_id,
        "Incorrect payment order association",
    )

    ensure(
        result.persisted is False,
        "Recommendation incorrectly claims persistence",
    )

    for forbidden in (
        "payment_state",
        "provider_confirmed",
        "settlement_confirmed",
        "retry_payment",
        "mutation_authorized",
    ):
        ensure(
            not hasattr(result, forbidden),
            f"Unsafe authority exposed: {forbidden}",
        )


def assert_quarantine_recommendation(
    result,
    event,
    expected_kind,
):
    ensure(
        result.organization_id == event.organization_id,
        "Incorrect tenant in quarantine recommendation",
    )

    ensure(
        result.record_id == event.record_id,
        "Incorrect inbox record in quarantine recommendation",
    )

    ensure(
        result.action is TriageAction.QUARANTINE,
        "Unlinked event was not recommended for quarantine",
    )

    ensure(
        result.reason is TriageReason.UNKNOWN_OBJECT,
        "Unexpected quarantine reason",
    )

    ensure(
        result.linkage_kind is expected_kind,
        "Unexpected linkage category",
    )

    ensure(
        result.local_attempt_id is None
        and result.local_order_id is None,
        "Unlinked event exposed financial references",
    )

    ensure(
        result.persisted is False,
        "Quarantine recommendation was incorrectly persisted",
    )


def verify_runtime_privileges(runtime, harness):
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
                allowed is False,
                f"Runtime unexpectedly has {privilege} on inbox",
            )


def test_real_postgres_combined_webhook_triage(monkeypatch):
    fixture = load_existing_fixture()
    harness = fixture.load_harness()

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
    financial_fixture = None

    enable_services(monkeypatch, fixture)

    try:
        with runtime.connect() as conn:
            harness.verify_identity(
                conn,
                "payflow_runtime",
            )

        # The existing fixture verifies the empty baseline and
        # rejects unexpected database clients or schema objects.
        organizations = harness.provision(migrator)

        org_a, org_b = organizations

        print("PASS: Approved disposable database provisioned")

        financial_fixture = fixture.make_financial_fixture(
            migrator,
            harness,
            org_a,
            org_b,
        )

        print("PASS: Synthetic financial references created")

        fixture.assert_runtime_select_privileges(
            runtime,
            harness,
        )

        verify_runtime_privileges(
            runtime,
            harness,
        )

        print("PASS: Runtime database privileges verified")

        # Existing helper verifies HMAC signatures and
        # deduplicates authenticated event replay.
        events = fixture.insert_verified_events(
            runtime,
            harness,
            org_a,
            org_b,
        )

        ensure(
            set(events) == {
                "tenant_a",
                "tenant_b",
                "unlinked",
                "legacy",
                "refund",
            },
            "Unexpected synthetic event inventory",
        )

        print("PASS: Five verified synthetic webhook events stored")
        print("PASS: Signed webhook replay deduplicated")

        before = fixture.snapshot(
            migrator,
            harness,
        )

        ensure(
            len(before["orders"]) == 3,
            "Unexpected payment-order count",
        )

        ensure(
            len(before["attempts"]) == 3,
            "Unexpected payment-attempt count",
        )

        ensure(
            len(before["inbox"]) == 5,
            "Unexpected webhook-inbox count",
        )

        attempt_a, attempt_b, _ = (
            financial_fixture["attempts"]
        )

        order_a, order_b, _ = (
            financial_fixture["orders"]
        )

        with Session(
            runtime,
            expire_on_commit=False,
        ) as db:
            with db.begin():
                # All inspections share one caller-owned
                # PostgreSQL transaction and restricted role.

                result_a = inspect(
                    db,
                    events["tenant_a"],
                )

                assert_reconciliation_recommendation(
                    result_a,
                    events["tenant_a"],
                    attempt_a,
                    order_a,
                )

                print(
                    "PASS: Tenant A linked payment recommends reconciliation"
                )

                result_b = inspect(
                    db,
                    events["tenant_b"],
                )

                assert_reconciliation_recommendation(
                    result_b,
                    events["tenant_b"],
                    attempt_b,
                    order_b,
                )

                ensure(
                    result_a.local_attempt_id
                    != result_b.local_attempt_id,
                    "Cross-tenant payment attempt collision",
                )

                print(
                    "PASS: Shared provider ID remains tenant-isolated"
                )

                unknown = inspect(
                    db,
                    events["unlinked"],
                )

                assert_quarantine_recommendation(
                    unknown,
                    events["unlinked"],
                    PaymentLinkKind.UNLINKED,
                )

                print(
                    "PASS: Unknown payment recommends manual quarantine"
                )

                legacy = inspect(
                    db,
                    events["legacy"],
                )

                assert_quarantine_recommendation(
                    legacy,
                    events["legacy"],
                    PaymentLinkKind.UNLINKED,
                )

                print(
                    "PASS: Legacy sandbox provider is not implicitly linked"
                )

                refund = inspect(
                    db,
                    events["refund"],
                )

                assert_quarantine_recommendation(
                    refund,
                    events["refund"],
                    PaymentLinkKind.REFUND_UNSUPPORTED,
                )

                print(
                    "PASS: Unsupported refund recommends manual quarantine"
                )

                # Inbox IDs must never be visible across tenants.

                with pytest.raises(WebhookTriageNotFound):
                    combined.inspect_linked_sandbox_webhook(
                        db,
                        organization_id=org_b,
                        record_id=events["tenant_a"].record_id,
                    )

                print(
                    "PASS: Cross-tenant inbox lookup fails closed"
                )

                with pytest.raises(WebhookTriageNotFound):
                    combined.inspect_linked_sandbox_webhook(
                        db,
                        organization_id=org_a,
                        record_id=uuid.uuid4(),
                    )

                print(
                    "PASS: Unknown inbox identity fails closed"
                )

                repeated = inspect(
                    db,
                    events["tenant_a"],
                )

                ensure(
                    repeated == result_a,
                    "Repeated inspection returned inconsistent result",
                )

                print(
                    "PASS: Repeated inspection is deterministic"
                )

        after = fixture.snapshot(
            migrator,
            harness,
        )

        ensure(
            before == after,
            "Integrated webhook triage mutated database records",
        )

        print(
            "PASS: Independent financial and inbox snapshots unchanged"
        )
        print(
            "PASS: No payment-state or settlement transitions"
        )
        print(
            "PASS: No inbox processing or quarantine persisted"
        )

    finally:
        try:
            # Cleanup is intentionally ordered:
            # financial fixtures first, inbox/events next.
            # Any unexpected data blocks cleanup and requires
            # manual review instead of broad deletion.

            if financial_fixture is not None:
                fixture.cleanup_financial_fixture(
                    migrator,
                    harness,
                    financial_fixture,
                )

            if organizations is not None:
                harness.cleanup(
                    migrator,
                    *organizations,
                )

        finally:
            runtime.dispose()
            migrator.dispose()

    # Verify the original empty disposable DB independently,
    # using a fresh connection and a read-only transaction.
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

                read_only = conn.execute(
                    text("""
                        SELECT current_setting(
                            'transaction_read_only'
                        )
                    """)
                ).scalar_one()

                ensure(
                    read_only == "on",
                    "Final verification is not read-only",
                )

                harness.verify_baseline(conn)

        print(
            "PASS: Original disposable PostgreSQL baseline restored"
        )
        print(
            "PASS: Independent read-only verification"
        )

    finally:
        verification.dispose()

    print(
        "PAYFLOW PHASE 3C.3D.1 POSTGRESQL TRIAGE VERIFIED"
    )
