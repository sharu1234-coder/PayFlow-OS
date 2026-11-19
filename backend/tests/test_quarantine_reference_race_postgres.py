"""Demonstrate the payment-reference race in an isolated PostgreSQL lab.

This is a vulnerability reproduction, NOT a successful safety proof.

The test shows that an inbox FOR UPDATE lock does not serialize
a concurrent payment-attempt INSERT or provider-reference UPDATE.

No quarantine function is installed or executed.
No worker credentials or grants are required.
No inbox status transition is performed.

Synthetic financial records are created only in the isolated
disposable test database and removed during cleanup.

Run only after an independent administrator attestation of
the exact PostgreSQL 18 cluster and its data directory.

If interrupted or cleanup fails, inspect the database manually
before any retry.
"""

import importlib.util
import os
import uuid
from pathlib import Path

import pytest

from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool


TARGET = "payflow_payment_drill_20261117_020846_9fbac781"
OPT_IN = "PAYFLOW_REFERENCE_RACE_TEST_DB"

pytestmark = pytest.mark.skipif(
    os.environ.get(OPT_IN) != TARGET
    or os.environ.get("PAYFLOW_ISOLATED_TEST_DB") != TARGET,
    reason="Explicit isolated PostgreSQL reference-race opt-in required",
)


def ensure(condition, message):
    if not condition:
        raise AssertionError(message)


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(
        name,
        path,
    )

    ensure(
        spec is not None and spec.loader is not None,
        "Required local test dependency unavailable",
    )

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


def dependencies():
    tests = Path(__file__).resolve().parent

    harness = load_module(
        tests / "test_webhook_inbox_concurrency_postgres.py",
        "reference_race_isolated_harness",
    )

    helpers = load_module(
        tests / "test_webhook_quarantine_audit_postgres.py",
        "reference_race_synthetic_helpers",
    )

    return harness, helpers


def verified_reference(conn, event):
    row = conn.execute(
        text("""
            SELECT provider_code, provider_object_id,
                   status, processed_at
            FROM payflow.provider_event_inbox
            WHERE organization_id = :organization_id
              AND id = :record_id
            FOR UPDATE
        """),
        {
            "organization_id": event["organization_id"],
            "record_id": event["record_id"],
        },
    ).one()

    ensure(
        row.provider_code == "sandbox_sim",
        "Unexpected synthetic provider",
    )

    ensure(
        row.status == "received"
        and row.processed_at is None,
        "Inbox event was already resolved",
    )

    return row.provider_object_id


def matching_attempt_exists(conn, organization_id, reference):
    return conn.execute(
        text("""
            SELECT EXISTS (
                SELECT 1
                FROM payflow.payment_attempts
                WHERE organization_id = :organization_id
                  AND provider_code = 'sandbox_sim'
                  AND provider_payment_id = :reference
            )
        """),
        {
            "organization_id": organization_id,
            "reference": reference,
        },
    ).scalar_one()


def seed_orders(migrator, harness, organizations, ids):
    organization_a, organization_b = organizations

    with migrator.begin() as conn:
        harness.verify_identity(
            conn,
            "payflow_migrator",
        )

        for organization, order_id, reference in (
            (
                organization_a,
                ids["order_a"],
                "race-order-a-" + ids["order_a"].hex[:12],
            ),
            (
                organization_b,
                ids["order_b"],
                "race-order-b-" + ids["order_b"].hex[:12],
            ),
        ):
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
                        :id,
                        :organization_id,
                        :reference,
                        100,
                        'INR',
                        'open'
                    )
                """),
                {
                    "id": order_id,
                    "organization_id": organization,
                    "reference": reference,
                },
            )

        # Tenant A already has an attempt without a provider
        # reference. Another transaction will link it later.
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
                    :id,
                    :organization_id,
                    :order_id,
                    1,
                    100,
                    'INR',
                    'sandbox_sim',
                    NULL,
                    'created'
                )
            """),
            {
                "id": ids["attempt_a"],
                "organization_id": organization_a,
                "order_id": ids["order_a"],
            },
        )


def demonstrate_gap(
    migrator,
    runtime,
    harness,
    *,
    event,
    order_id,
    attempt_id,
    mode,
):
    ensure(
        mode in ("update", "insert"),
        "Unsupported reproduction mode",
    )

    organization_id = event["organization_id"]

    with migrator.connect() as inspecting:
        with inspecting.begin():
            harness.verify_identity(
                inspecting,
                "payflow_migrator",
            )

            inspecting.exec_driver_sql(
                "SET LOCAL lock_timeout = '3s'"
            )

            # Keep the inbox row locked throughout the
            # other transaction's INSERT or UPDATE.
            reference = verified_reference(
                inspecting,
                event,
            )

            ensure(
                matching_attempt_exists(
                    inspecting,
                    organization_id,
                    reference,
                ) is False,
                "Expected initially unlinked event",
            )

            # Separate PostgreSQL transaction, while the
            # original inbox FOR UPDATE lock is held.
            with runtime.begin() as competing:
                harness.verify_identity(
                    competing,
                    "payflow_runtime",
                )

                competing.exec_driver_sql(
                    "SET LOCAL lock_timeout = '2s'"
                )

                if mode == "update":
                    result = competing.execute(
                        text("""
                            UPDATE payflow.payment_attempts
                            SET provider_payment_id = :reference
                            WHERE organization_id = :organization_id
                              AND id = :attempt_id
                              AND provider_payment_id IS NULL
                            RETURNING id
                        """),
                        {
                            "reference": reference,
                            "organization_id": organization_id,
                            "attempt_id": attempt_id,
                        },
                    ).scalar_one()

                else:
                    result = competing.execute(
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
                                :id,
                                :organization_id,
                                :order_id,
                                1,
                                100,
                                'INR',
                                'sandbox_sim',
                                :reference,
                                'created'
                            )
                            RETURNING id
                        """),
                        {
                            "id": attempt_id,
                            "organization_id": organization_id,
                            "order_id": order_id,
                            "reference": reference,
                        },
                    ).scalar_one()

                ensure(
                    result == attempt_id,
                    "Competing transaction did not write expected attempt",
                )

            # Under READ COMMITTED, the next statement can
            # observe the concurrently committed reference,
            # even though our inbox row lock never released.
            ensure(
                matching_attempt_exists(
                    inspecting,
                    organization_id,
                    reference,
                ) is True,
                "Expected concurrent reference linkage was not visible",
            )

            state = inspecting.execute(
                text("""
                    SELECT status, processed_at
                    FROM payflow.provider_event_inbox
                    WHERE organization_id = :organization_id
                      AND id = :record_id
                """),
                {
                    "organization_id": organization_id,
                    "record_id": event["record_id"],
                },
            ).one()

            ensure(
                state.status == "received"
                and state.processed_at is None,
                "Reproduction unexpectedly mutated inbox state",
            )

    print(
        "PASS: Concurrent reference "
        + mode
        + " committed despite inbox row lock"
    )
    print(
        "PASS: Earlier unlinked observation became stale"
    )
    print(
        "PASS: Inbox lifecycle remained unchanged"
    )


def remove_synthetic_financial_records(
    migrator,
    harness,
    organizations,
    ids,
):
    organization_a, organization_b = organizations

    expected_orders = {
        ids["order_a"],
        ids["order_b"],
    }

    expected_attempts = {
        ids["attempt_a"],
        ids["attempt_b"],
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
                    WHERE organization_id IN (:a, :b)
                """),
                {
                    "a": organization_a,
                    "b": organization_b,
                },
            ).scalars()
        )

        actual_attempts = set(
            conn.execute(
                text("""
                    SELECT id
                    FROM payflow.payment_attempts
                    WHERE organization_id IN (:a, :b)
                """),
                {
                    "a": organization_a,
                    "b": organization_b,
                },
            ).scalars()
        )

        # Never delete unexpected records.
        ensure(
            actual_orders.issubset(expected_orders)
            and actual_attempts.issubset(expected_attempts),
            "Unexpected financial records: manual inspection required",
        )

        conn.execute(
            text("""
                DELETE FROM payflow.payment_attempts
                WHERE organization_id IN (:a, :b)
                  AND id IN (:attempt_a, :attempt_b)
            """),
            {
                "a": organization_a,
                "b": organization_b,
                "attempt_a": ids["attempt_a"],
                "attempt_b": ids["attempt_b"],
            },
        )

        conn.execute(
            text("""
                DELETE FROM payflow.payment_orders
                WHERE organization_id IN (:a, :b)
                  AND id IN (:order_a, :order_b)
            """),
            {
                "a": organization_a,
                "b": organization_b,
                "order_a": ids["order_a"],
                "order_b": ids["order_b"],
            },
        )


def test_inbox_lock_does_not_serialize_payment_reference_writes(
    monkeypatch,
):
    harness, helpers = dependencies()

    ensure(
        harness._isolated_lab_mode(),
        "Dedicated isolated PostgreSQL lab required",
    )

    ensure(
        bool(os.environ.get(
            "PAYFLOW_LAB_ATTESTED_START_EPOCH"
        )),
        "Administrator server attestation required",
    )

    runtime_url, migrator_url = harness.approved_urls()

    ensure(
        runtime_url.database == TARGET
        and migrator_url.database == TARGET
        and runtime_url.port == 55432
        and migrator_url.port == 55432
        and runtime_url.host == "127.0.0.1"
        and migrator_url.host == "127.0.0.1",
        "Unexpected PostgreSQL target",
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

    ids = {
        "order_a": uuid.uuid4(),
        "order_b": uuid.uuid4(),
        "attempt_a": uuid.uuid4(),
        "attempt_b": uuid.uuid4(),
    }

    try:
        with migrator.connect() as conn:
            with conn.begin():
                conn.exec_driver_sql(
                    "SET TRANSACTION READ ONLY"
                )

                harness.verify_baseline(conn)
                harness.verify_no_other_clients(conn)

                function_exists = conn.execute(
                    text("""
                        SELECT pg_catalog.to_regprocedure(
                            'payflow.quarantine_sandbox_webhook(uuid,uuid)'
                        )
                    """)
                ).scalar_one()

                ensure(
                    function_exists is None,
                    "Privileged quarantine function must be absent",
                )

        organizations = harness.provision(migrator)

        helpers.enable_synthetic_inbox(monkeypatch)

        events = helpers.insert_verified_events(
            runtime,
            harness,
            *organizations,
        )

        seed_orders(
            migrator,
            harness,
            organizations,
            ids,
        )

        # Scenario A:
        # Another transaction updates a NULL provider reference
        # while the first transaction locks the inbox event.
        demonstrate_gap(
            migrator,
            runtime,
            harness,
            event=events["a"],
            order_id=ids["order_a"],
            attempt_id=ids["attempt_a"],
            mode="update",
        )

        # Scenario B:
        # Another transaction inserts a new, already linked
        # payment attempt while the inbox event is locked.
        demonstrate_gap(
            migrator,
            runtime,
            harness,
            event=events["b"],
            order_id=ids["order_b"],
            attempt_id=ids["attempt_b"],
            mode="insert",
        )

        print("PASS: Both adversarial interleavings reproduced")
        print("PASS: No quarantine function executed")
        print("PASS: No inbox status changes performed")

    finally:
        try:
            if organizations is not None:
                remove_synthetic_financial_records(
                    migrator,
                    harness,
                    organizations,
                    ids,
                )

                harness.cleanup(
                    migrator,
                    *organizations,
                )

        finally:
            runtime.dispose()
            migrator.dispose()

    # Independent inspection using a fresh connection.
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

                harness.verify_baseline(conn)

                quarantine_function = conn.execute(
                    text("""
                        SELECT pg_catalog.to_regprocedure(
                            'payflow.quarantine_sandbox_webhook(uuid,uuid)'
                        )
                    """)
                ).scalar_one()

                ensure(
                    quarantine_function is None,
                    "Unexpected quarantine function after test",
                )

        print("PASS: Independent empty-baseline verification")
        print("PASS: All synthetic financial records removed")

    finally:
        inspection.dispose()

    print("REFERENCE RACE REPRODUCED — ACTIVATION STILL BLOCKED")
