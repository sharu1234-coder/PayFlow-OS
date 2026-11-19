"""Disposable PostgreSQL installation and execution-denial test.

This is NOT a worker-execution or quarantine-transition test.

Explicit opt-in and approved local disposable DB only.
No cluster-level role creation or privilege grants.

Uses existing synthetic signed webhook fixtures and restores
the original disposable database baseline after verification.

If cleanup fails or execution is interrupted, inspect the
disposable database before another run.
"""

import importlib.util
import os
import uuid
from pathlib import Path

import pytest

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.pool import NullPool


TARGET = "payflow_payment_drill_20261117_020846_9fbac781"
SIGNATURE = "payflow.quarantine_sandbox_webhook(uuid,uuid)"

pytestmark = pytest.mark.skipif(
    os.environ.get("PAYFLOW_DORMANT_FUNCTION_TEST_DB") != TARGET,
    reason="Explicit disposable PostgreSQL function opt-in required",
)

CALL_SQL = text("""
    SELECT payflow.quarantine_sandbox_webhook(
        CAST(:organization_id AS uuid),
        CAST(:record_id AS uuid)
    )
""")


def ensure(condition, message):
    if not condition:
        raise AssertionError(message)


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)

    ensure(
        spec is not None and spec.loader is not None,
        "Required test module not found",
    )

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


def dependencies():
    backend = Path(__file__).resolve().parents[1]
    tests = Path(__file__).parent

    harness = load_module(
        tests / "test_webhook_inbox_concurrency_postgres.py",
        "dormant_function_disposable_harness",
    )

    helpers = load_module(
        tests / "test_webhook_quarantine_audit_postgres.py",
        "dormant_function_disposable_helpers",
    )

    audit = load_module(
        backend / "alembic" / "versions"
        / "a7c4e91d2b30_webhook_quarantine_audit.py",
        "dormant_function_audit_prerequisite",
    )

    function = load_module(
        tests / "fixtures"
        / "b6e2d40c9a51_dormant_quarantine_function.py",
        "dormant_function_disposable_sql",
    )

    return harness, helpers, audit, function


def bind(module, conn):
    context = MigrationContext.configure(
        conn,
        opts={"version_table_schema": "payflow"},
    )

    module.op = Operations(context)


def check_not_authorized(conn, harness, role, event):
    harness.verify_identity(conn, role)

    nested = conn.begin_nested()

    try:
        conn.execute(
            CALL_SQL,
            {
                "organization_id": event["organization_id"],
                "record_id": event["record_id"],
            },
        )

    except DBAPIError as error:
        state = (
            getattr(error.orig, "sqlstate", None)
            or getattr(error.orig, "pgcode", None)
        )

        nested.rollback()

        ensure(
            state == "42501",
            "Unexpected database error during denial check",
        )

    else:
        nested.rollback()
        raise AssertionError(
            "Unauthorized account executed quarantine function"
        )


def verify_function_definition(migrator, harness):
    with migrator.connect() as conn:
        with conn.begin():
            conn.exec_driver_sql("SET TRANSACTION READ ONLY")
            harness.verify_identity(conn, "payflow_migrator")

            row = conn.execute(
                text("""
                    SELECT
                        p.prosecdef,
                        p.proconfig
                    FROM pg_catalog.pg_proc AS p
                    WHERE p.oid = pg_catalog.to_regprocedure(
                        'payflow.quarantine_sandbox_webhook(uuid,uuid)'
                    )
                """)
            ).one_or_none()

            ensure(row is not None, "Function was not installed")
            ensure(row.prosecdef is True, "Function is not SECURITY DEFINER")

            config = row.proconfig or []

            ensure(
                any(
                    item.replace(" ", "")
                    == "search_path=pg_catalog,pg_temp"
                    for item in config
                ),
                "Function search_path is unsafe",
            )

            public_execute = conn.execute(
                text("""
                    SELECT EXISTS (
                        SELECT 1
                        FROM pg_catalog.pg_proc AS p
                        JOIN pg_catalog.pg_namespace AS n
                          ON n.oid = p.pronamespace
                        CROSS JOIN LATERAL pg_catalog.aclexplode(
                            COALESCE(
                                p.proacl,
                                pg_catalog.acldefault(
                                    'f',
                                    p.proowner
                                )
                            )
                        ) AS acl
                        WHERE n.nspname = 'payflow'
                          AND p.proname = 'quarantine_sandbox_webhook'
                          AND p.pronargs = 2
                          AND acl.grantee = 0
                          AND acl.privilege_type = 'EXECUTE'
                    )
                """)
            ).scalar_one()

            ensure(
                public_execute is False,
                "PUBLIC has function execution permission",
            )

    print("PASS: Function installed as SECURITY DEFINER")
    print("PASS: Trusted function search_path")
    print("PASS: PUBLIC execution privilege revoked")


def verify_runtime_denial(runtime, harness, event):
    with runtime.connect() as conn:
        with conn.begin():
            harness.verify_identity(conn, "payflow_runtime")

            can_execute = conn.execute(
                text("""
                    SELECT pg_catalog.has_function_privilege(
                        current_user,
                        'payflow.quarantine_sandbox_webhook(uuid,uuid)',
                        'EXECUTE'
                    )
                """)
            ).scalar_one()

            ensure(
                can_execute is False,
                "Runtime has unauthorized function EXECUTE",
            )

            for relation, privilege in (
                ("payflow.provider_event_inbox", "UPDATE"),
                ("payflow.webhook_quarantine_audit", "INSERT"),
            ):
                allowed = conn.execute(
                    text("""
                        SELECT pg_catalog.has_table_privilege(
                            current_user,
                            :relation,
                            :privilege
                        )
                    """),
                    {
                        "relation": relation,
                        "privilege": privilege,
                    },
                ).scalar_one()

                ensure(
                    allowed is False,
                    "Runtime gained direct protected-table permission",
                )

            check_not_authorized(
                conn,
                harness,
                "payflow_runtime",
                event,
            )

    print("PASS: API runtime cannot execute quarantine")
    print("PASS: No direct inbox or audit write permissions")


def verify_owner_denial(migrator, harness, event):
    with migrator.connect() as conn:
        with conn.begin():
            check_not_authorized(
                conn,
                harness,
                "payflow_migrator",
                event,
            )

    print("PASS: Migration owner denied by function identity check")


def test_dormant_function_install_and_denial(monkeypatch):
    harness, helpers, audit, function = dependencies()

    ensure(
        function.revision == "b6e2d40c9a51"
        and function.down_revision == "a7c4e91d2b30",
        "Unexpected fixture compatibility revision",
    )

    runtime_url, migrator_url = harness.approved_urls()

    ensure(
        runtime_url.database == TARGET
        and migrator_url.database == TARGET,
        "Database target not approved",
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
    installed = False

    helpers.enable_synthetic_inbox(monkeypatch)

    try:
        # No cluster-wide role or login may be created here.
        with migrator.connect() as conn:
            with conn.begin():
                conn.exec_driver_sql("SET TRANSACTION READ ONLY")
                harness.verify_baseline(conn)

                worker_exists = conn.execute(
                    text("""
                        SELECT EXISTS (
                            SELECT 1
                            FROM pg_catalog.pg_roles
                            WHERE rolname = 'payflow_quarantine_worker'
                        )
                    """)
                ).scalar_one()

                ensure(
                    worker_exists is False,
                    "Worker role already exists: manual review needed",
                )

        print("PASS: Disposable baseline and role preflight")

        organizations = harness.provision(migrator)

        # Both database objects installed in one transaction.
        # No worker role is created and no EXECUTE grant issued.
        with migrator.begin() as conn:
            harness.verify_identity(conn, "payflow_migrator")

            bind(audit, conn)
            audit.upgrade()

            bind(function, conn)
            function.upgrade()

        installed = True
        print("PASS: Audit and dormant function temporarily installed")

        verify_function_definition(migrator, harness)

        events = helpers.insert_verified_events(
            runtime,
            harness,
            *organizations,
        )

        print("PASS: Synthetic signed events staged")

        before = helpers.snapshot(migrator, harness)

        ensure(
            len(before[0]) == 2,
            "Unexpected number of verified inbox events",
        )

        ensure(
            all(
                row[9] == "received" and row[11] is None
                for row in before[0]
            ),
            "Unexpected inbox lifecycle",
        )

        ensure(
            all(value == 0 for value in before[1].values()),
            "Financial or audit data unexpectedly exists",
        )

        verify_runtime_denial(
            runtime,
            harness,
            events["a"],
        )

        verify_owner_denial(
            migrator,
            harness,
            events["b"],
        )

        after = helpers.snapshot(migrator, harness)

        ensure(
            before == after,
            "Denied execution modified persisted database state",
        )

        print("PASS: Independent before/after snapshots identical")
        print("PASS: No inbox, audit, or financial mutations")

    finally:
        try:
            if installed:
                with migrator.begin() as conn:
                    harness.verify_identity(
                        conn,
                        "payflow_migrator",
                    )

                    audit_count = conn.execute(
                        text("""
                            SELECT COUNT(*)
                            FROM payflow.webhook_quarantine_audit
                        """)
                    ).scalar_one()

                    ensure(
                        audit_count == 0,
                        "Unexpected audit history: inspect database",
                    )

                    bind(function, conn)
                    function.downgrade()

                    bind(audit, conn)
                    audit.downgrade()

                print("PASS: Dormant function and audit removed")

            if organizations is not None:
                harness.cleanup(migrator, *organizations)

        finally:
            runtime.dispose()
            migrator.dispose()

    # Independently confirm the original baseline in a new
    # read-only connection after all cleanup has completed.
    verification = create_engine(
        migrator_url,
        poolclass=NullPool,
        connect_args={"connect_timeout": 5},
    )

    try:
        with verification.connect() as conn:
            with conn.begin():
                conn.exec_driver_sql("SET TRANSACTION READ ONLY")

                harness.verify_baseline(conn)

                function_exists = conn.execute(
                    text("""
                        SELECT pg_catalog.to_regprocedure(
                            'payflow.quarantine_sandbox_webhook(uuid,uuid)'
                        )
                    """)
                ).scalar_one()

                audit_exists = conn.execute(
                    text("""
                        SELECT pg_catalog.to_regclass(
                            'payflow.webhook_quarantine_audit'
                        )
                    """)
                ).scalar_one()

                ensure(
                    function_exists is None
                    and audit_exists is None,
                    "Function or audit table remained after cleanup",
                )

        print("PASS: Original disposable baseline restored")

    finally:
        verification.dispose()

    print("PHASE 3C.3E.3B.2 FUNCTION SECURITY VERIFIED")
