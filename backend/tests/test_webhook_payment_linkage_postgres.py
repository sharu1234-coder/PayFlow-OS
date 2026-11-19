"""Real PostgreSQL sandbox payment-reference linkage tests.

Explicit opt-in only, using the previously approved local
disposable database. Never run against dev or production DB.

Creates temporary synthetic payment orders and attempts, then
verifies exact tenant/provider/object matching through the
restricted runtime database role.

Fixtures contain no customer payments and move no money.

The linkage service performs no SQL writes. This is verified
using independent database snapshots before and after inspection.

All fixture data and staged migrations are removed afterward.
An interrupted process may require manual database inspection.

A local payment-reference match is not settlement confirmation.
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

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

import app.services.webhook_inbox as webhook_inbox
import app.services.webhook_payment_linkage as linkage

from app.payments.contracts import PaymentState


TARGET = "payflow_payment_drill_20261117_020846_9fbac781"

PAYMENT_ID = "sim_pay_" + "a" * 32
UNLINKED_ID = "sim_pay_" + "b" * 32
LEGACY_ID = "sim_pay_" + "c" * 32
REFUND_ID = "sim_ref_" + "d" * 32


pytestmark = pytest.mark.skipif(
    os.environ.get("PAYFLOW_LINKAGE_TEST_DB") != TARGET,
    reason="Explicit disposable PostgreSQL linkage opt-in required",
)


def ensure(condition, message):
    if not condition:
        raise AssertionError(message)


def load_harness():
    path = Path(__file__).with_name(
        "test_webhook_inbox_concurrency_postgres.py"
    )

    ensure(
        path.is_file(),
        "Approved disposable database harness missing",
    )

    spec = importlib.util.spec_from_file_location(
        "payflow_payment_linkage_disposable_harness",
        path,
    )

    ensure(
        spec is not None and spec.loader is not None,
        "Unable to load disposable database harness",
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
            f"Missing disposable harness function: {name}",
        )

    return module


def enable_sandbox(monkeypatch):
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
        linkage,
        "get_settings",
        lambda: settings,
    )


def make_financial_fixture(migrator, harness, org_a, org_b):
    """Commit only controlled synthetic financial references.

    These records are local test fixtures, not real payments.
    Both tenants intentionally share a synthetic provider ID
    to prove that tenant-scoped lookup cannot leak records.
    """

    fixture = {
        "organizations": (org_a, org_b),
        "orders": tuple(uuid.uuid4() for _ in range(3)),
        "attempts": tuple(uuid.uuid4() for _ in range(3)),
    }

    order_a, order_b, order_legacy = fixture["orders"]
    attempt_a, attempt_b, attempt_legacy = fixture["attempts"]

    suffix = uuid.uuid4().hex[:12]

    with migrator.begin() as conn:
        harness.verify_identity(conn, "payflow_migrator")

        count = conn.execute(
            text("""
                SELECT COUNT(*)
                FROM payflow.organizations
                WHERE id IN (:a, :b)
            """),
            {"a": org_a, "b": org_b},
        ).scalar_one()

        ensure(
            count == 2,
            "Expected synthetic organizations are missing",
        )

        orders = (
            (order_a, org_a, "link-a-" + suffix),
            (order_b, org_b, "link-b-" + suffix),
            (order_legacy, org_a, "link-legacy-" + suffix),
        )

        for order_id, organization_id, reference in orders:
            conn.execute(
                text("""
                    INSERT INTO payflow.payment_orders (
                        id,
                        organization_id,
                        merchant_order_reference,
                        amount_minor_units,
                        currency,
                        status
                    )
                    VALUES (
                        :id, :org, :reference,
                        12500, 'INR', 'open'
                    )
                """),
                {
                    "id": order_id,
                    "org": organization_id,
                    "reference": reference,
                },
            )

        attempts = (
            (
                attempt_a,
                org_a,
                order_a,
                "sandbox_sim",
                PAYMENT_ID,
            ),
            (
                attempt_b,
                org_b,
                order_b,
                "sandbox_sim",
                PAYMENT_ID,
            ),
            (
                attempt_legacy,
                org_a,
                order_legacy,
                "sandbox",
                LEGACY_ID,
            ),
        )

        for (
            attempt_id,
            organization_id,
            order_id,
            provider_code,
            provider_payment_id,
        ) in attempts:
            conn.execute(
                text("""
                    INSERT INTO payflow.payment_attempts (
                        id,
                        organization_id,
                        order_id,
                        attempt_number,
                        amount_minor_units,
                        currency,
                        provider_code,
                        provider_payment_id,
                        status
                    )
                    VALUES (
                        :id, :org, :order_id,
                        1, 12500, 'INR',
                        :provider_code,
                        :provider_payment_id,
                        'processing'
                    )
                """),
                {
                    "id": attempt_id,
                    "org": organization_id,
                    "order_id": order_id,
                    "provider_code": provider_code,
                    "provider_payment_id": provider_payment_id,
                },
            )

        ensure(
            conn.execute(
                text("""
                    SELECT COUNT(*)
                    FROM payflow.payment_orders
                """)
            ).scalar_one() == 3,
            "Expected three synthetic payment orders",
        )

        ensure(
            conn.execute(
                text("""
                    SELECT COUNT(*)
                    FROM payflow.payment_attempts
                """)
            ).scalar_one() == 3,
            "Expected three synthetic payment attempts",
        )

    return fixture


def sign_custom(
    harness,
    organization_id,
    event_id,
    *,
    event_type="payment.succeeded",
    provider_object_id=PAYMENT_ID,
):
    event = harness.signed_event(
        organization_id,
        event_id,
    )

    payload = json.loads(
        event["raw_body"].decode("utf-8")
    )

    payload["event_type"] = event_type
    payload["provider_object_id"] = provider_object_id

    raw_body = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    signed_message = (
        b"v1."
        + event["timestamp"].encode("ascii")
        + b"."
        + raw_body
    )

    event["raw_body"] = raw_body
    event["signature"] = "v1=" + hmac.new(
        harness.SECRET,
        signed_message,
        hashlib.sha256,
    ).hexdigest()

    return event


def insert_verified_events(runtime, harness, org_a, org_b):
    """All events enter through the real signature-checking service."""

    inputs = {
        "tenant_a": sign_custom(
            harness,
            org_a,
            "evt_link_payment_001",
        ),
        "tenant_b": sign_custom(
            harness,
            org_b,
            "evt_link_payment_001",
        ),
        "unlinked": sign_custom(
            harness,
            org_a,
            "evt_link_unlinked_002",
            provider_object_id=UNLINKED_ID,
        ),
        "legacy": sign_custom(
            harness,
            org_a,
            "evt_link_legacy_003",
            provider_object_id=LEGACY_ID,
        ),
        "refund": sign_custom(
            harness,
            org_a,
            "evt_link_refund_004",
            event_type="refund.succeeded",
            provider_object_id=REFUND_ID,
        ),
    }

    results = {}

    with Session(runtime, expire_on_commit=False) as db:
        with db.begin():
            for name, signed in inputs.items():
                result = webhook_inbox.receive_sandbox_webhook(
                    db,
                    **signed,
                )

                ensure(
                    result.replayed is False,
                    "Unexpected duplicate initial event",
                )

                results[name] = result

            # An authenticated replay must resolve to the
            # original event record without creating a new one.
            replay = webhook_inbox.receive_sandbox_webhook(
                db,
                **inputs["tenant_a"],
            )

            ensure(
                replay.replayed is True,
                "Exact replay was not recognized",
            )

            ensure(
                replay.record_id
                == results["tenant_a"].record_id,
                "Replay changed the original event ID",
            )

    return results


def snapshot(migrator, harness):
    """Read independent complete snapshots of relevant tables."""

    with migrator.connect() as conn:
        harness.verify_identity(
            conn,
            "payflow_migrator",
        )

        statements = {
            "orders": """
                SELECT id, organization_id,
                       merchant_order_reference,
                       amount_minor_units, currency,
                       status, created_at
                FROM payflow.payment_orders
                ORDER BY id
            """,
            "attempts": """
                SELECT id, organization_id, order_id,
                       attempt_number, amount_minor_units,
                       currency, provider_code,
                       provider_payment_id, status, created_at
                FROM payflow.payment_attempts
                ORDER BY id
            """,
            "inbox": """
                SELECT id, organization_id, provider_code,
                       event_id, event_type,
                       provider_object_id, occurred_at,
                       signed_at, payload_sha256,
                       status, received_at, processed_at
                FROM payflow.provider_event_inbox
                ORDER BY id
            """,
        }

        result = {}

        for name, query in statements.items():
            rows = conn.execute(text(query)).all()

            result[name] = tuple(
                tuple(row) for row in rows
            )

        for table in (
            "payment_idempotency_records",
            "payment_attempt_idempotency_records",
        ):
            count = conn.exec_driver_sql(
                f"SELECT COUNT(*) FROM payflow.{table}"
            ).scalar_one()

            ensure(
                count == 0,
                f"Unexpected idempotency record in {table}",
            )

        return result


def assert_runtime_select_privileges(runtime, harness):
    with runtime.connect() as conn:
        harness.verify_identity(
            conn,
            "payflow_runtime",
        )

        for relation in (
            "payflow.provider_event_inbox",
            "payflow.payment_attempts",
            "payflow.payment_orders",
        ):
            permitted = conn.execute(
                text("""
                    SELECT has_table_privilege(
                        current_user,
                        :relation,
                        'SELECT'
                    )
                """),
                {"relation": relation},
            ).scalar_one()

            ensure(
                permitted,
                f"Runtime SELECT privilege missing: {relation}",
            )


def inspect_link(db, event):
    return linkage.inspect_local_payment_reference(
        db,
        organization_id=event.organization_id,
        record_id=event.record_id,
    )


def test_postgres_local_payment_reference_linkage(monkeypatch):
    harness = load_harness()

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

    organizations = None
    financial_fixture = None

    enable_sandbox(monkeypatch)

    try:
        with runtime.connect() as conn:
            harness.verify_identity(
                conn,
                "payflow_runtime",
            )

        organizations = harness.provision(migrator)

        org_a, org_b = organizations

        print("PASS: Disposable database preflight and migrations")

        financial_fixture = make_financial_fixture(
            migrator,
            harness,
            org_a,
            org_b,
        )

        print("PASS: Synthetic local payment references created")

        assert_runtime_select_privileges(
            runtime,
            harness,
        )

        print("PASS: Runtime SELECT privileges verified")

        events = insert_verified_events(
            runtime,
            harness,
            org_a,
            org_b,
        )

        print("PASS: Five signed webhook events stored")
        print("PASS: Exact signed replay deduplicated")

        before = snapshot(migrator, harness)

        ensure(
            len(before["orders"]) == 3,
            "Unexpected order count",
        )

        ensure(
            len(before["attempts"]) == 3,
            "Unexpected payment attempt count",
        )

        ensure(
            len(before["inbox"]) == 5,
            "Unexpected inbox event count",
        )

        attempt_a, attempt_b, _ = (
            financial_fixture["attempts"]
        )

        order_a, order_b, _ = (
            financial_fixture["orders"]
        )

        # All linkage inspections use the restricted
        # payflow_runtime connection role.
        with Session(runtime, expire_on_commit=False) as db:
            with db.begin():
                a = inspect_link(db, events["tenant_a"])

                ensure(
                    a.kind
                    is linkage.PaymentLinkKind.LOCAL_REFERENCE,
                    "Tenant A local payment reference not found",
                )

                ensure(
                    a.attempt_id == attempt_a,
                    "Tenant A linked to wrong payment attempt",
                )

                ensure(
                    a.order_id == order_a,
                    "Tenant A linked to wrong payment order",
                )

                ensure(
                    a.local_attempt_state
                    is PaymentState.PROCESSING,
                    "Unexpected local attempt state",
                )

                print("PASS: Tenant A exact local reference")

                b = inspect_link(db, events["tenant_b"])

                ensure(
                    b.kind
                    is linkage.PaymentLinkKind.LOCAL_REFERENCE,
                    "Tenant B local payment reference not found",
                )

                ensure(
                    b.attempt_id == attempt_b,
                    "Tenant B linked to wrong payment attempt",
                )

                ensure(
                    b.order_id == order_b,
                    "Tenant B linked to wrong payment order",
                )

                ensure(
                    a.attempt_id != b.attempt_id,
                    "Cross-tenant payment reference collision",
                )

                print("PASS: Shared provider ID remains tenant-scoped")

                unlinked = inspect_link(
                    db,
                    events["unlinked"],
                )

                ensure(
                    unlinked.kind
                    is linkage.PaymentLinkKind.UNLINKED,
                    "Unknown provider object was incorrectly linked",
                )

                ensure(
                    unlinked.attempt_id is None
                    and unlinked.order_id is None,
                    "Unlinked event exposed payment references",
                )

                print("PASS: Unknown provider reference remains unlinked")

                legacy = inspect_link(
                    db,
                    events["legacy"],
                )

                ensure(
                    legacy.kind
                    is linkage.PaymentLinkKind.UNLINKED,
                    "Legacy provider code incorrectly matched",
                )

                print("PASS: Legacy sandbox code is not aliased")

                refund = inspect_link(
                    db,
                    events["refund"],
                )

                ensure(
                    refund.kind
                    is linkage.PaymentLinkKind.REFUND_UNSUPPORTED,
                    "Unsupported refund event was linked",
                )

                print("PASS: Refund references remain unsupported")

                with pytest.raises(
                    linkage.PaymentLinkNotFound
                ):
                    linkage.inspect_local_payment_reference(
                        db,
                        organization_id=org_b,
                        record_id=events["tenant_a"].record_id,
                    )

                print("PASS: Cross-tenant inbox access denied")

                with pytest.raises(
                    linkage.PaymentLinkNotFound
                ):
                    linkage.inspect_local_payment_reference(
                        db,
                        organization_id=org_a,
                        record_id=uuid.uuid4(),
                    )

                print("PASS: Missing inbox record fails closed")

                repeated = inspect_link(
                    db,
                    events["tenant_a"],
                )

                ensure(
                    repeated == a,
                    "Repeated local reference inspection changed",
                )

                print("PASS: Repeated inspection is deterministic")

        after = snapshot(migrator, harness)

        ensure(
            before == after,
            "Linkage inspection modified persisted records",
        )

        print("PASS: Independent before/after DB snapshots match")
        print("PASS: No payment or inbox state changes")
        print("PASS: No settlement confirmation inferred")

    finally:
        try:
            if financial_fixture is not None:
                cleanup_financial_fixture(
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

                read_only = conn.execute(
                    text("""
                        SELECT current_setting(
                            'transaction_read_only'
                        )
                    """)
                ).scalar_one()

                ensure(
                    read_only == "on",
                    "Final inspection is not read-only",
                )

                harness.verify_baseline(conn)

        print("PASS: Original disposable database baseline restored")

    finally:
        inspection.dispose()

    print("PAYFLOW PHASE 3C.3C.2 POSTGRESQL LINKAGE VERIFIED")


def cleanup_financial_fixture(migrator, harness, fixture):
    """Remove ONLY generated financial fixture IDs.

    Refuse cleanup if the synthetic table inventory differs
    from what this test created. No broad table deletion.
    """

    org_a, org_b = fixture["organizations"]
    order_ids = fixture["orders"]
    attempt_ids = fixture["attempts"]

    parameters = {
        "org_a": org_a,
        "org_b": org_b,
        "order_a": order_ids[0],
        "order_b": order_ids[1],
        "order_legacy": order_ids[2],
        "attempt_a": attempt_ids[0],
        "attempt_b": attempt_ids[1],
        "attempt_legacy": attempt_ids[2],
    }

    with migrator.begin() as conn:
        harness.verify_identity(
            conn,
            "payflow_migrator",
        )

        actual_orders = set(
            conn.execute(
                text("""
                    SELECT id
                    FROM payflow.payment_orders
                """)
            ).scalars()
        )

        actual_attempts = set(
            conn.execute(
                text("""
                    SELECT id
                    FROM payflow.payment_attempts
                """)
            ).scalars()
        )

        ensure(
            actual_orders == set(order_ids),
            "Unexpected payment orders: manual inspection required",
        )

        ensure(
            actual_attempts == set(attempt_ids),
            "Unexpected payment attempts: manual inspection required",
        )

        for table in (
            "payment_idempotency_records",
            "payment_attempt_idempotency_records",
        ):
            ensure(
                conn.exec_driver_sql(
                    f"SELECT COUNT(*) FROM payflow.{table}"
                ).scalar_one() == 0,
                "Unexpected idempotency records",
            )

        removed_attempts = conn.execute(
            text("""
                DELETE FROM payflow.payment_attempts
                WHERE organization_id IN (:org_a, :org_b)
                  AND id IN (
                      :attempt_a,
                      :attempt_b,
                      :attempt_legacy
                  )
            """),
            parameters,
        )

        ensure(
            removed_attempts.rowcount == 3,
            "Synthetic attempt cleanup mismatch",
        )

        removed_orders = conn.execute(
            text("""
                DELETE FROM payflow.payment_orders
                WHERE organization_id IN (:org_a, :org_b)
                  AND id IN (
                      :order_a,
                      :order_b,
                      :order_legacy
                  )
            """),
            parameters,
        )

        ensure(
            removed_orders.rowcount == 3,
            "Synthetic order cleanup mismatch",
        )

    print("PASS: Synthetic financial references removed")
