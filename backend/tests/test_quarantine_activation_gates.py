"""Security regression checks for dormant quarantine activation.

These tests document and enforce the existing NO-GO boundary.

They do not establish that authorization or reference
serialization has been implemented.

No database connections, worker login, SQL execution,
gateway access, or payment processing.
"""

import importlib.util
from io import StringIO
from pathlib import Path

from alembic.migration import MigrationContext
from alembic.operations import Operations


BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parent

FIXTURE = (
    BACKEND
    / "tests"
    / "fixtures"
    / "b6e2d40c9a51_dormant_quarantine_function.py"
)

DOCUMENT = (
    ROOT
    / "docs"
    / "QUARANTINE_WORKER_ACTIVATION_GATES.md"
)

NORMAL_MIGRATIONS = BACKEND / "alembic" / "versions"


def fixture_module():
    spec = importlib.util.spec_from_file_location(
        "quarantine_activation_gate_fixture",
        FIXTURE,
    )

    assert spec is not None
    assert spec.loader is not None

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


def sql_definition():
    return fixture_module().FUNCTION_SQL


def rendered_install_sql():
    module = fixture_module()

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


def document():
    return DOCUMENT.read_text(encoding="utf-8")


def test_document_declares_no_go():
    content = document()

    assert "NO-GO" in content
    assert "WORKER MUST REMAIN DORMANT" in content
    assert "No production approval" in content


def test_trusted_job_authorization_is_a_blocker():
    content = document()

    assert "BLOCKED — trusted job authorization" in content
    assert "durable identity" in content
    assert "organization and inbox ID" in content
    assert "validated atomically" in content


def test_payment_reference_race_is_a_blocker():
    content = document()

    assert "BLOCKED — payment-reference race" in content
    assert "READ COMMITTED" in content
    assert "Concurrent payment-reference INSERT" in content
    assert "Concurrent payment-reference UPDATE" in content
    assert "commit" in content.lower()
    assert "rollback" in content.lower()


def test_successful_worker_execution_remains_blocked():
    content = document()

    assert "BLOCKED — successful worker execution" in content
    assert "Granting EXECUTE" in content
    assert "worker password" in content.lower()


def test_privileged_function_remains_test_only():
    assert FIXTURE.is_file()

    assert not (
        NORMAL_MIGRATIONS
        / FIXTURE.name
    ).exists()

    module = fixture_module()

    assert module.revision == "b6e2d40c9a51"
    assert module.down_revision == "a7c4e91d2b30"


def test_database_login_is_not_mistaken_for_job_claim():
    sql = sql_definition()

    assert (
        "session_user <> 'payflow_quarantine_worker'"
        in sql
    )

    assert "p_organization_id uuid" in sql
    assert "p_record_id uuid" in sql

    # Known architectural blocker. This assertion does not
    # certify an authorization implementation.
    assert "trusted_job_claim" not in sql
    assert "authorized_work_item" not in sql


def test_reference_existence_check_is_not_claimed_as_safe_locking():
    sql = sql_definition()

    assert "FROM payflow.payment_attempts AS a" in sql
    assert "a.provider_payment_id = v_event.provider_object_id" in sql

    assert "FOR UPDATE" in sql

    # Current inbox locking does not serialize attempt creation.
    # This explicit blocker must be revisited before activation.
    assert "pg_advisory_xact_lock" not in sql


def test_worker_execute_is_not_granted():
    sql = rendered_install_sql().upper()

    assert "CREATE FUNCTION" in sql
    assert "SECURITY DEFINER" in sql

    assert "GRANT EXECUTE" not in sql
    assert "CREATE ROLE" not in sql
    assert "ALTER ROLE" not in sql
    assert "ALTER DEFAULT PRIVILEGES" not in sql


def test_public_execution_is_revoked():
    sql = rendered_install_sql().upper()

    assert "REVOKE ALL PRIVILEGES ON FUNCTION" in sql
    assert "FROM PUBLIC, PAYFLOW_RUNTIME" in sql


def test_function_uses_hardened_search_path():
    sql = sql_definition()

    assert "SECURITY DEFINER" in sql
    assert "SET search_path = pg_catalog, pg_temp" in sql


def test_no_direct_payment_state_modification():
    sql = sql_definition().upper()

    forbidden = (
        "UPDATE PAYFLOW.PAYMENT_ORDERS",
        "UPDATE PAYFLOW.PAYMENT_ATTEMPTS",
        "INSERT INTO PAYFLOW.PAYMENT_ORDERS",
        "INSERT INTO PAYFLOW.PAYMENT_ATTEMPTS",
        "DELETE FROM PAYFLOW.PAYMENT_ORDERS",
        "DELETE FROM PAYFLOW.PAYMENT_ATTEMPTS",
        "UPDATE PAYFLOW.REFUNDS",
        "INSERT INTO PAYFLOW.REFUNDS",
    )

    for statement in forbidden:
        assert statement not in sql


def test_quarantine_writes_are_narrow():
    sql = sql_definition()

    assert sql.count(
        "UPDATE payflow.provider_event_inbox"
    ) == 1

    assert sql.count(
        "INSERT INTO payflow.webhook_quarantine_audit"
    ) == 1


def test_required_adversarial_cases_are_documented():
    content = document()

    required = (
        "Missing claim",
        "Expired or revoked claim",
        "Wrong organization or record ID",
        "Claim replay",
        "Concurrent workers",
        "Concurrent payment-reference INSERT",
        "Concurrent payment-reference UPDATE",
        "Audit failure",
        "baseline restoration",
    )

    for item in required:
        assert item in content


def test_document_does_not_claim_approval():
    content = document()

    assert "Current decision: **NO-GO" in content
    assert "green offline test suite alone" in content
    assert "No production approval" in content
