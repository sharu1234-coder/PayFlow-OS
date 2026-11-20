"""Real PostgreSQL residual-risk demonstrations in an isolated lab.

Demonstrates that direct database writers can bypass cooperative
advisory locks, and that valid linkage can arrive after a prior
read-only inspection transaction finishes.

These tests are NOT a concurrency fix or activation approval.

Synthetic organizations, orders, attempts and inbox records
are temporarily created only in the approved disposable lab.

No privileged quarantine function is installed or executed.
No inbox status, payment outcome, refund or settlement transition.

If interrupted or cleanup fails, inspect the disposable
database manually before any retry.
"""

import importlib.util
import os
import uuid
from pathlib import Path

import pytest

from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool


TARGET = "payflow_payment_drill_20261117_020846_9fbac781"
OPT_IN = "PAYFLOW_REFERENCE_RESIDUAL_TEST_DB"

pytestmark = pytest.mark.skipif(
    os.environ.get(OPT_IN) != TARGET
    or os.environ.get("PAYFLOW_ISOLATED_TEST_DB") != TARGET,
    reason="Explicit isolated residual-risk test opt-in required",
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
        "Required local test module missing",
    )

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


def dependencies():
    tests = Path(__file__).resolve().parent

    race = load_module(
        tests / "test_quarantine_reference_race_postgres.py",
        "residual_risk_existing_race_helpers",
    )

    contract = load_module(
        tests / "fixtures"
        / "reference_serialization_contract.py",
        "residual_risk_reference_contract",
    )

    harness, helpers = race.dependencies()

    return race, contract, harness, helpers


def advisory_lock(conn, lock_key):
    conn.execute(
        text("""
            SELECT pg_catalog.pg_advisory_xact_lock(
                CAST(:lock_key AS BIGINT)
            )
        """),
        {"lock_key": lock_key},
    )


def reference_key(contract, event, reference):
    return contract.payment_reference_lock_key(
        event["organization_id"],
        "sandbox_sim",
        reference,
    )


def assert_inbox_unmodified(conn, event):
    row = conn.execute(
        text("""
            SELECT status, processed_at
            FROM payflow.provider_event_inbox
            WHERE organization_id = :org
              AND id = :record
        """),
        {
            "org": event["organization_id"],
            "record": event["record_id"],
        },
    ).one()

    ensure(
        row.status == "received"
        and row.processed_at is None,
        "Inbox status unexpectedly changed",
    )


def demonstrate_bypass(
    race,
    contract,
    harness,
    migrator,
    runtime,
    *,
    event,
    attempt_id,
    order_id,
    mode,
):
    ensure(
        mode in ("update", "insert"),
        "Unexpected raw writer mode",
    )

    organization_id = event["organization_id"]

    with migrator.connect() as inspector:
        with inspector.begin():
            harness.verify_identity(
                inspector,
                "payflow_migrator",
            )

            inspector.exec_driver_sql(
                "SET LOCAL statement_timeout = '5s'"
            )

            reference = race.verified_reference(
                inspector,
                event,
            )

            key = reference_key(
                contract,
                event,
                reference,
            )

            advisory_lock(inspector, key)

            ensure(
                race.matching_attempt_exists(
                    inspector,
                    organization_id,
                    reference,
                ) is False,
                "Expected initially unlinked payment reference",
            )

            # Deliberate bypass: the competing writer DOES NOT
            # acquire the advisory lock. This illustrates the
            # current cooperative-lock limitation.
            with runtime.begin() as writer:
                harness.verify_identity(
                    writer,
                    "payflow_runtime",
                )

                writer.exec_driver_sql(
                    "SET LOCAL lock_timeout = '2s'"
                )

                writer.exec_driver_sql(
                    "SET LOCAL statement_timeout = '5s'"
                )

                if mode == "update":
                    result = writer.execute(
                        text("""
                            UPDATE payflow.payment_attempts
                            SET provider_payment_id = :reference
                            WHERE organization_id = :org
                              AND id = :attempt
                              AND provider_payment_id IS NULL
                            RETURNING id
                        """),
                        {
                            "org": organization_id,
                            "attempt": attempt_id,
                            "reference": reference,
                        },
                    ).scalar_one()

                else:
                    result = writer.execute(
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
                                :attempt,
                                :org,
                                :order,
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
                            "attempt": attempt_id,
                            "org": organization_id,
                            "order": order_id,
                            "reference": reference,
                        },
                    ).scalar_one()

                ensure(
                    result == attempt_id,
                    "Unexpected competing writer result",
                )

            # The inspector STILL holds its advisory lock.
            # Yet the non-cooperating transaction committed.
            ensure(
                race.matching_attempt_exists(
                    inspector,
                    organization_id,
                    reference,
                ) is True,
                "Non-cooperating reference write not visible",
            )

            assert_inbox_unmodified(
                inspector,
                event,
            )

    print(
        "PASS: Non-cooperating "
        + mode.upper()
        + " committed despite reference advisory lock"
    )

    print("PASS: Inbox lifecycle remained unchanged")


def demonstrate_late_linkage(
    race,
    contract,
    harness,
    migrator,
    runtime,
    *,
    event,
    attempt_id,
):
    organization_id = event["organization_id"]

    # Reset ONLY the synthetic attempt created by this test.
    # This prepares a fresh, unlinked starting condition.
    with runtime.begin() as writer:
        harness.verify_identity(
            writer,
            "payflow_runtime",
        )

        cleared = writer.execute(
            text("""
                UPDATE payflow.payment_attempts
                SET provider_payment_id = NULL
                WHERE organization_id = :org
                  AND id = :attempt
                RETURNING id
            """),
            {
                "org": organization_id,
                "attempt": attempt_id,
            },
        ).scalar_one()

        ensure(
            cleared == attempt_id,
            "Synthetic attempt reset failed",
        )

    with migrator.connect() as inspector:
        with inspector.begin():
            harness.verify_identity(
                inspector,
                "payflow_migrator",
            )

            reference = race.verified_reference(
                inspector,
                event,
            )

            key = reference_key(
                contract,
                event,
                reference,
            )

            advisory_lock(inspector, key)

            ensure(
                race.matching_attempt_exists(
                    inspector,
                    organization_id,
                    reference,
                ) is False,
                "Expected unlinked reference before decision",
            )

            # Conceptual observation only.
            # No actual quarantine decision is committed.
            review_disposition = "review_pending"

            assert_inbox_unmodified(inspector, event)

        # The read-only inspection transaction is now over.

    ensure(
        review_disposition == "review_pending",
        "Unexpected simulated review disposition",
    )

    with runtime.begin() as writer:
        harness.verify_identity(
            writer,
            "payflow_runtime",
        )

        writer.exec_driver_sql(
            "SET LOCAL statement_timeout = '5s'"
        )

        # This writer now COOPERATES with the protocol,
        # but the earlier inspection lock has ended.
        advisory_lock(writer, key)

        linked = writer.execute(
            text("""
                UPDATE payflow.payment_attempts
                SET provider_payment_id = :reference
                WHERE organization_id = :org
                  AND id = :attempt
                  AND provider_payment_id IS NULL
                RETURNING id
            """),
            {
                "org": organization_id,
                "attempt": attempt_id,
                "reference": reference,
            },
        ).scalar_one()

        ensure(
            linked == attempt_id,
            "Late synthetic linkage failed",
        )

    with migrator.connect() as inspector:
        with inspector.begin():
            inspector.exec_driver_sql(
                "SET TRANSACTION READ ONLY"
            )

            harness.verify_identity(
                inspector,
                "payflow_migrator",
            )

            ensure(
                race.matching_attempt_exists(
                    inspector,
                    organization_id,
                    reference,
                ) is True,
                "Late-arriving reference not visible",
            )

            assert_inbox_unmodified(inspector, event)

    print(
        "PASS: Reference linked after earlier "
        "inspection transaction completed"
    )

    print(
        "PASS: Earlier review observation "
        "did not establish permanent absence"
    )

    print("PASS: No actual quarantine decision committed")


def test_real_postgres_noncooperating_and_late_references(
    monkeypatch,
):
    race, contract, harness, helpers = dependencies()

    ensure(
        harness._isolated_lab_mode(),
        "Dedicated isolated PostgreSQL lab required",
    )

    ensure(
        bool(os.environ.get(
            "PAYFLOW_LAB_ATTESTED_START_EPOCH"
        )),
        "Administrator startup attestation required",
    )

    runtime_url, migrator_url = harness.approved_urls()

    for url, role in (
        (runtime_url, "payflow_runtime"),
        (migrator_url, "payflow_migrator"),
    ):
        ensure(
            url.host == "127.0.0.1"
            and url.port == 55432
            and url.database == TARGET
            and url.username == role,
            "Unexpected database target or role",
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

    ids = {
        "order_a": uuid.uuid4(),
        "order_b": uuid.uuid4(),
        "attempt_a": uuid.uuid4(),
        "attempt_b": uuid.uuid4(),
    }

    organizations = None

    try:
        with migrator.connect() as conn:
            with conn.begin():
                conn.exec_driver_sql(
                    "SET TRANSACTION READ ONLY"
                )

                harness.verify_baseline(conn)
                harness.verify_no_other_clients(conn)

                function = conn.execute(
                    text("""
                        SELECT pg_catalog.to_regprocedure(
                            'payflow.quarantine_sandbox_webhook(uuid,uuid)'
                        )
                    """)
                ).scalar_one()

                ensure(
                    function is None,
                    "Quarantine function must not exist",
                )

        organizations = harness.provision(migrator)

        helpers.enable_synthetic_inbox(monkeypatch)

        events = helpers.insert_verified_events(
            runtime,
            harness,
            *organizations,
        )

        race.seed_orders(
            migrator,
            harness,
            organizations,
            ids,
        )

        demonstrate_bypass(
            race,
            contract,
            harness,
            migrator,
            runtime,
            event=events["a"],
            attempt_id=ids["attempt_a"],
            order_id=ids["order_a"],
            mode="update",
        )

        demonstrate_bypass(
            race,
            contract,
            harness,
            migrator,
            runtime,
            event=events["b"],
            attempt_id=ids["attempt_b"],
            order_id=ids["order_b"],
            mode="insert",
        )

        demonstrate_late_linkage(
            race,
            contract,
            harness,
            migrator,
            runtime,
            event=events["b"],
            attempt_id=ids["attempt_b"],
        )

        print("PASS: All three residual risks demonstrated")
        print("PASS: No privileged quarantine function executed")

    finally:
        try:
            if organizations is not None:
                race.remove_synthetic_financial_records(
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

                function = conn.execute(
                    text("""
                        SELECT pg_catalog.to_regprocedure(
                            'payflow.quarantine_sandbox_webhook(uuid,uuid)'
                        )
                    """)
                ).scalar_one()

                ensure(
                    function is None,
                    "Quarantine function remains unexpectedly",
                )

        print("PASS: Independent disposable baseline verification")
        print("PASS: All synthetic financial records removed")
        print("PASS: No temporary webhook schema remains")

    finally:
        inspection.dispose()

    print(
        "RESIDUAL RISKS REPRODUCED - "
        "QUARANTINE WORKER ACTIVATION STILL BLOCKED"
    )
