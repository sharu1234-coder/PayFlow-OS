"""Isolated PostgreSQL advisory-lock contention security drill.

Tests cooperating transaction-scoped locks, NOT a production
payment-reference serialization implementation.

The test is skipped unless two explicit isolated-lab opt-ins
and a server-startup attestation are supplied.

No inbox, payment, audit, or refund records are created,
updated, or deleted. No quarantine worker is activated.

No PostgreSQL connections occur during test collection.
"""

import importlib.util
import os
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool


TARGET = "payflow_payment_drill_20261117_020846_9fbac781"

OPT_IN = "PAYFLOW_REFERENCE_LOCK_TEST_DB"

pytestmark = pytest.mark.skipif(
    os.environ.get(OPT_IN) != TARGET
    or os.environ.get("PAYFLOW_ISOLATED_TEST_DB") != TARGET,
    reason="Explicit isolated reference-lock test opt-in required",
)

ORG_A = UUID("11111111-1111-4111-8111-111111111111")
ORG_B = UUID("22222222-2222-4222-8222-222222222222")

REF_A = "sim_pay_" + ("a" * 32)
REF_C = "sim_pay_" + ("c" * 32)

TRY_LOCK = text("""
    SELECT pg_catalog.pg_try_advisory_xact_lock(
        CAST(:lock_key AS BIGINT)
    )
""")


def ensure(condition, message):
    if not condition:
        raise AssertionError(message)


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)

    ensure(
        spec is not None and spec.loader is not None,
        "Required test module missing",
    )

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def dependencies():
    tests = Path(__file__).resolve().parent

    harness = load_module(
        tests / "test_webhook_inbox_concurrency_postgres.py",
        "reference_lock_isolated_harness",
    )

    contract = load_module(
        tests / "fixtures" / "reference_serialization_contract.py",
        "reference_lock_test_contract",
    )

    return harness, contract


def try_lock(conn, lock_key):
    return conn.execute(
        TRY_LOCK,
        {"lock_key": lock_key},
    ).scalar_one()


def check_baseline(migrator, harness):
    with migrator.connect() as conn:
        with conn.begin():
            conn.exec_driver_sql(
                "SET TRANSACTION READ ONLY"
            )

            harness.verify_identity(
                conn,
                "payflow_migrator",
            )

            harness.verify_baseline(conn)
            harness.verify_no_other_clients(conn)


def test_cooperating_reference_lock_contention():
    harness, contract = dependencies()

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

    for url, role in (
        (runtime_url, "payflow_runtime"),
        (migrator_url, "payflow_migrator"),
    ):
        ensure(
            url.host == "127.0.0.1"
            and url.port == 55432
            and url.database == TARGET
            and url.username == role,
            "Unexpected PostgreSQL target or login",
        )

    key_a = contract.payment_reference_lock_key(
        ORG_A,
        "sandbox_sim",
        REF_A,
    )

    key_other_tenant = contract.payment_reference_lock_key(
        ORG_B,
        "sandbox_sim",
        REF_A,
    )

    ensure(
        key_a != key_other_tenant,
        "Test sample keys unexpectedly collide",
    )

    replacement_keys = contract.reference_change_lock_keys(
        ORG_A,
        "sandbox_sim",
        REF_A,
        REF_C,
    )

    ensure(
        len(replacement_keys) == 2,
        "Expected two distinct reference locks",
    )

    ensure(
        replacement_keys == tuple(sorted(replacement_keys)),
        "Reference locks are not ordered",
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

    try:
        print("Checking untouched isolated database baseline")

        check_baseline(migrator, harness)

        print("PASS: Baseline verified before lock test")

        with migrator.connect() as first:
            with runtime.connect() as second:
                try:
                    harness.verify_identity(
                        first, "payflow_migrator"
                    )

                    harness.verify_identity(
                        second, "payflow_runtime"
                    )

                    first.exec_driver_sql(
                        "SET LOCAL statement_timeout = '3s'"
                    )

                    second.exec_driver_sql(
                        "SET LOCAL statement_timeout = '3s'"
                    )

                    # Same identity: second session cannot
                    # acquire the key while first holds it.

                    ensure(
                        try_lock(first, key_a) is True,
                        "First session failed to acquire lock",
                    )

                    ensure(
                        try_lock(second, key_a) is False,
                        "Second session bypassed held lock",
                    )

                    print(
                        "PASS: Same reference blocked across sessions"
                    )

                    # Different tenant, identical provider ID:
                    # a separate key remains available.

                    ensure(
                        try_lock(second, key_other_tenant)
                        is True,
                        "Different-tenant lock was blocked",
                    )

                    print(
                        "PASS: Different tenant reference independent"
                    )

                    # Ending first transaction releases
                    # its transaction-scoped advisory lock.

                    first.rollback()

                    ensure(
                        try_lock(second, key_a) is True,
                        "Reference lock not released on rollback",
                    )

                    print(
                        "PASS: First transaction rollback released lock"
                    )

                    second.rollback()

                    ensure(
                        try_lock(first, key_a) is True,
                        "Second transaction did not release lock",
                    )

                    first.rollback()

                    print(
                        "PASS: Second transaction rollback released lock"
                    )

                    # A reference replacement must reserve
                    # both the old and new reference identities.

                    for lock_key in replacement_keys:
                        ensure(
                            try_lock(first, lock_key) is True,
                            "Replacement lock acquisition failed",
                        )

                    for lock_key in replacement_keys:
                        ensure(
                            try_lock(second, lock_key) is False,
                            "Replacement lock was bypassed",
                        )

                    print(
                        "PASS: Old and new references both protected"
                    )

                    first.rollback()

                    for lock_key in replacement_keys:
                        ensure(
                            try_lock(second, lock_key) is True,
                            "Replacement lock not released",
                        )

                    second.rollback()

                    print(
                        "PASS: Ordered replacement locks released"
                    )

                finally:
                    if first.in_transaction():
                        first.rollback()

                    if second.in_transaction():
                        second.rollback()

        check_baseline(migrator, harness)

        print("PASS: Independent post-test baseline verification")
        print("PASS: No synthetic financial rows created")
        print("PASS: No inbox or payment mutations")
        print("PASS: Quarantine worker remains inactive")
        print(
            "REFERENCE LOCK CONTENTION VERIFIED; "
            "PRODUCTION SERIALIZATION STILL BLOCKED"
        )

    finally:
        runtime.dispose()
        migrator.dispose()
