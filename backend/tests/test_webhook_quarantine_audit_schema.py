"""Offline security tests for webhook quarantine audit migration.

Never connects to PostgreSQL or applies migrations.
"""

import importlib.util
from io import StringIO
from pathlib import Path

import pytest

from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.script import ScriptDirectory
from sqlalchemy import CheckConstraint, ForeignKeyConstraint
from sqlalchemy import UniqueConstraint

import app.models
from app.core.model_base import Base


MIGRATION_PATH = (
    Path(__file__).resolve().parents[1]
    / "alembic"
    / "versions"
    / "a7c4e91d2b30_webhook_quarantine_audit.py"
)


def load_migration():
    spec = importlib.util.spec_from_file_location(
        "payflow_quarantine_audit_migration_test",
        MIGRATION_PATH,
    )

    assert spec is not None
    assert spec.loader is not None

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


def render_upgrade():
    migration = load_migration()
    stream = StringIO()

    context = MigrationContext.configure(
        dialect_name="postgresql",
        opts={
            "as_sql": True,
            "output_buffer": stream,
        },
    )

    migration.op = Operations(context)
    migration.upgrade()

    return stream.getvalue()


def audit_table():
    return Base.metadata.tables[
        "payflow.webhook_quarantine_audit"
    ]


def test_model_registered():
    assert "payflow.webhook_quarantine_audit" in Base.metadata.tables


def test_migration_revision_and_head():
    migration = load_migration()

    assert migration.revision == "a7c4e91d2b30"
    assert migration.down_revision == "f3c2a119b607"

    scripts = ScriptDirectory.from_config(Config("alembic.ini"))
    assert scripts.get_heads() == ["a7c4e91d2b30"]


def test_audit_columns_are_minimal():
    assert set(audit_table().columns.keys()) == {
        "id",
        "organization_id",
        "provider_code",
        "event_id",
        "reason_code",
        "processor_identity",
        "from_status",
        "to_status",
        "transitioned_at",
    }


def test_sensitive_data_not_collected():
    forbidden = {
        "raw_body",
        "payload_json",
        "authorization_header",
        "card_number",
        "signing_secret",
        "gateway_response",
        "api_key",
    }

    assert forbidden.isdisjoint(audit_table().columns.keys())


def test_audit_uses_existing_tenant_scoped_inbox_identity():
    foreign_keys = [
        item
        for item in audit_table().constraints
        if isinstance(item, ForeignKeyConstraint)
    ]

    assert len(foreign_keys) == 1

    fk = foreign_keys[0]

    assert tuple(fk.column_keys) == (
        "organization_id",
        "provider_code",
        "event_id",
    )

    targets = tuple(
        element.target_fullname
        for element in fk.elements
    )

    assert targets == (
        "payflow.provider_event_inbox.organization_id",
        "payflow.provider_event_inbox.provider_code",
        "payflow.provider_event_inbox.event_id",
    )

    assert fk.ondelete == "RESTRICT"


def test_only_one_quarantine_audit_per_event():
    uniques = {
        tuple(item.columns.keys())
        for item in audit_table().constraints
        if isinstance(item, UniqueConstraint)
    }

    assert (
        "organization_id",
        "provider_code",
        "event_id",
    ) in uniques


def test_reason_codes_are_explicitly_constrained():
    checks = [
        str(item.sqltext)
        for item in audit_table().constraints
        if isinstance(item, CheckConstraint)
    ]

    assert any(
        "unlinked_payment" in value
        and "refund_linkage_unavailable" in value
        for value in checks
    )


def test_only_received_to_quarantined_is_described():
    checks = [
        str(item.sqltext)
        for item in audit_table().constraints
        if isinstance(item, CheckConstraint)
    ]

    assert any(
        "from_status = 'received'" in value
        and "to_status = 'quarantined'" in value
        for value in checks
    )


def test_processor_identity_has_format_constraint():
    checks = [
        str(item.sqltext)
        for item in audit_table().constraints
        if isinstance(item, CheckConstraint)
    ]

    assert any(
        "processor_identity ~" in value
        for value in checks
    )


def test_database_timestamp_is_mandatory():
    column = audit_table().columns["transitioned_at"]

    assert column.nullable is False
    assert column.server_default is not None
    assert column.type.timezone is True


def test_offline_migration_creates_audit_table():
    sql = render_upgrade()

    assert "CREATE TABLE payflow.webhook_quarantine_audit" in sql
    assert "fk_webhook_quarantine_audit_event_identity" in sql
    assert "uq_webhook_quarantine_audit_event" in sql
    assert "ix_webhook_quarantine_audit_org_time" in sql


def test_database_constraints_rendered():
    sql = render_upgrade()

    for name in (
        "ck_webhook_quarantine_audit_sandbox_only",
        "ck_webhook_quarantine_audit_reason_valid",
        "ck_webhook_quarantine_audit_processor_identity_valid",
        "ck_webhook_quarantine_audit_transition_valid",
    ):
        assert name in sql


def test_no_runtime_or_public_audit_privileges_granted():
    sql = render_upgrade()

    assert (
        "REVOKE ALL PRIVILEGES ON TABLE "
        "payflow.webhook_quarantine_audit "
        "FROM PUBLIC, payflow_runtime"
    ) in sql

    assert "GRANT " not in sql


def test_migration_does_not_modify_inbox_or_money_tables():
    sql = render_upgrade()

    for forbidden in (
        "UPDATE payflow.provider_event_inbox",
        "UPDATE payflow.payment_orders",
        "UPDATE payflow.payment_attempts",
        "DELETE FROM",
        "INSERT INTO",
        "CREATE ROLE",
        "CREATE FUNCTION",
        "SECURITY DEFINER",
    ):
        assert forbidden not in sql


def test_migration_does_not_change_inbox_privileges():
    sql = render_upgrade()

    assert "GRANT UPDATE" not in sql
    assert "GRANT INSERT" not in sql
    assert "GRANT EXECUTE" not in sql
    assert "REVOKE ALL PRIVILEGES ON TABLE payflow.provider_event_inbox" not in sql


def test_downgrade_refuses_nonempty_audit():
    source = MIGRATION_PATH.read_text(encoding="utf-8")

    assert (
        "Refusing to drop non-empty webhook quarantine audit"
    ) in source

    assert callable(load_migration().downgrade)


def test_audit_is_not_a_public_processing_service():
    import app.models.webhook_quarantine as model

    assert not hasattr(model, "process_webhook")
    assert not hasattr(model, "quarantine_event")
    assert not hasattr(model, "retry_payment")
    assert not hasattr(model, "confirm_settlement")
