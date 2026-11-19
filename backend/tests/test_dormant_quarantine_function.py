"""Offline tests for dormant atomic quarantine SQL.

These tests never connect to a real PostgreSQL server.
They do not activate or execute the SQL function.
"""

import importlib.util
from io import StringIO
from pathlib import Path

from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.script import ScriptDirectory


MIGRATION_PATH = (
    Path(__file__).resolve().parents[1]
    / "tests"
    / "fixtures"
    / "b6e2d40c9a51_dormant_quarantine_function.py"
)


def migration_module():
    spec = importlib.util.spec_from_file_location(
        "payflow_dormant_quarantine_function_test",
        MIGRATION_PATH,
    )
    assert spec is not None
    assert spec.loader is not None

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rendered_sql():
    module = migration_module()

    output = StringIO()
    context = MigrationContext.configure(
        dialect_name="postgresql",
        opts={
            "as_sql": True,
            "output_buffer": output,
        },
    )

    module.op = Operations(context)
    module.upgrade()
    return output.getvalue()


def test_revision_chain():
    module = migration_module()

    assert module.revision == "b6e2d40c9a51"
    assert module.down_revision == "a7c4e91d2b30"

    scripts = ScriptDirectory.from_config(
        Config("alembic.ini")
    )
    assert scripts.get_heads() == ["a7c4e91d2b30"]


def test_only_one_restricted_function_is_created():
    sql = rendered_sql()

    assert "CREATE FUNCTION payflow.quarantine_sandbox_webhook" in sql
    assert sql.count("CREATE FUNCTION") == 1
    assert "RETURNS text" in sql
    assert "LANGUAGE plpgsql" in sql


def test_function_is_privileged_but_search_path_hardened():
    sql = rendered_sql()

    assert "SECURITY DEFINER" in sql
    assert "SET search_path = pg_catalog, pg_temp" in sql


def test_disposable_database_only():
    sql = rendered_sql()

    assert (
        "current_database()" in sql
    )
    assert (
        "'payflow_payment_drill_20261117_020846_9fbac781'"
        in sql
    )


def test_dedicated_session_identity_is_required():
    sql = rendered_sql()

    assert (
        "session_user <> 'payflow_quarantine_worker'"
        in sql
    )
    assert (
        "RAISE EXCEPTION 'Dedicated quarantine login required'"
        in sql
    )


def test_read_committed_and_writable_transaction_required():
    sql = rendered_sql()

    assert "transaction_read_only" in sql
    assert "transaction_isolation" in sql
    assert "'read committed'" in sql


def test_row_lock_and_exact_tenant_identity():
    sql = rendered_sql()

    assert "FROM payflow.provider_event_inbox AS e" in sql
    assert "e.organization_id = p_organization_id" in sql
    assert "e.id = p_record_id" in sql
    assert "FOR UPDATE" in sql


def test_payment_linkage_is_rechecked_inside_database():
    sql = rendered_sql()

    assert "FROM payflow.payment_attempts AS a" in sql
    assert "a.organization_id = v_event.organization_id" in sql
    assert "a.provider_code = v_event.provider_code" in sql
    assert "a.provider_payment_id = v_event.provider_object_id" in sql
    assert "RETURN 'hold_for_reconciliation'" in sql


def test_refunds_are_not_processed_financially():
    sql = rendered_sql()

    assert "v_reason := 'refund_linkage_unavailable'" in sql
    assert "v_reason := 'unlinked_payment'" in sql
    assert "UPDATE payflow.payment_attempts" not in sql
    assert "UPDATE payflow.payment_orders" not in sql
    assert "UPDATE payflow.refunds" not in sql


def test_one_conditional_inbox_status_update():
    sql = rendered_sql()

    assert sql.count(
        "UPDATE payflow.provider_event_inbox"
    ) == 1
    assert "status = 'quarantined'" in sql
    assert "e.status = 'received'" in sql
    assert "e.processed_at IS NULL" in sql
    assert "transaction_timestamp()" in sql


def test_one_audit_insert():
    sql = rendered_sql()

    assert sql.count(
        "INSERT INTO payflow.webhook_quarantine_audit"
    ) == 1
    assert "v_reason" in sql
    assert "session_user" in sql


def test_duplicate_transition_has_integrity_check():
    sql = rendered_sql()

    assert "IF v_event.status = 'quarantined'" in sql
    assert "v_audit_count <> 1" in sql
    assert "RETURN 'already_quarantined'" in sql


def test_already_resolved_event_not_reprocessed():
    sql = rendered_sql()

    assert "IF v_event.status = 'processed'" in sql
    assert "RETURN 'already_resolved'" in sql


def test_public_execute_revoked_and_no_execution_grants():
    sql = rendered_sql()

    assert (
        "REVOKE ALL PRIVILEGES ON FUNCTION "
        "payflow.quarantine_sandbox_webhook(uuid, uuid) "
        "FROM PUBLIC, payflow_runtime"
    ) in sql

    assert "GRANT EXECUTE" not in sql
    assert "GRANT UPDATE" not in sql
    assert "CREATE ROLE" not in sql


def test_no_direct_financial_table_mutations():
    sql = rendered_sql()

    for forbidden in (
        "INSERT INTO payflow.payment_orders",
        "INSERT INTO payflow.payment_attempts",
        "DELETE FROM payflow.payment_orders",
        "DELETE FROM payflow.payment_attempts",
        "UPDATE payflow.payment_orders",
        "UPDATE payflow.payment_attempts",
        "CREATE EXTENSION",
        "ALTER ROLE",
    ):
        assert forbidden not in sql


def test_downgrade_refuses_existing_audit_history():
    source = MIGRATION_PATH.read_text(
        encoding="utf-8"
    )
    assert (
        "Refusing to drop quarantine function with audit history"
        in source
    )
    assert callable(migration_module().downgrade)
