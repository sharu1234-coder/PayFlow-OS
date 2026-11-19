"""Offline tests for the verified webhook inbox migration.

These tests never connect to or modify PostgreSQL.
The migration is exercised through Alembic offline SQL.
"""

import importlib.util
from io import StringIO
from pathlib import Path

from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.script import ScriptDirectory

from app.core.model_base import Base
import app.models


MIGRATION_PATH = (
    Path(__file__).resolve().parents[1]
    / "alembic"
    / "versions"
    / "f3c2a119b607_verified_webhook_inbox.py"
)


def load_migration():
    spec = importlib.util.spec_from_file_location(
        "payflow_verified_webhook_inbox_migration",
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


def test_webhook_model_is_discovered():
    assert "payflow.provider_event_inbox" in Base.metadata.tables


def test_webhook_inbox_contains_expected_columns():
    table = Base.metadata.tables[
        "payflow.provider_event_inbox"
    ]

    assert set(table.columns.keys()) == {
        "id",
        "organization_id",
        "provider_code",
        "event_id",
        "event_type",
        "provider_object_id",
        "occurred_at",
        "signed_at",
        "payload_sha256",
        "status",
        "received_at",
        "processed_at",
    }


def test_webhook_inbox_does_not_store_raw_payload_or_secrets():
    table = Base.metadata.tables[
        "payflow.provider_event_inbox"
    ]

    forbidden = {
        "raw_body",
        "payload_json",
        "raw_headers",
        "signing_secret",
        "api_key",
        "card_number",
        "gateway_response",
    }

    assert forbidden.isdisjoint(
        table.columns.keys()
    )


def test_migration_extends_existing_revision_chain():
    migration = load_migration()

    assert migration.revision == "f3c2a119b607"
    assert migration.down_revision == "e4b3c1a8d205"

    scripts = ScriptDirectory.from_config(
        Config("alembic.ini")
    )

    assert scripts.get_heads() == ["a7c4e91d2b30"]


def test_offline_migration_creates_inbox():
    sql = render_upgrade()

    assert (
        "CREATE TABLE payflow.provider_event_inbox"
        in sql
    )

    assert (
        "uq_provider_event_inbox_identity"
        in sql
    )


def test_event_identity_is_tenant_and_provider_scoped():
    table = Base.metadata.tables[
        "payflow.provider_event_inbox"
    ]

    unique_groups = {
        tuple(constraint.columns.keys())
        for constraint in table.constraints
        if constraint.__class__.__name__ == "UniqueConstraint"
    }

    assert (
        "organization_id",
        "provider_code",
        "event_id",
    ) in unique_groups


def test_offline_migration_contains_validity_checks():
    sql = render_upgrade()

    for required in (
        "ck_provider_event_inbox_sandbox_only",
        "ck_provider_event_inbox_event_type_valid",
        "ck_provider_event_inbox_object_kind_match",
        "ck_provider_event_inbox_payload_hash_format",
        "ck_provider_event_inbox_timestamps_valid",
        "ck_provider_event_inbox_status_valid",
        "ck_provider_event_inbox_status_timestamp_match",
    ):
        assert required in sql


def test_inbox_has_processing_and_object_indexes():
    sql = render_upgrade()

    assert (
        "ix_provider_event_inbox_org_status_received"
        in sql
    )
    assert (
        "ix_provider_event_inbox_org_object"
        in sql
    )


def test_runtime_only_receives_read_and_insert():
    sql = render_upgrade()

    assert (
        "REVOKE ALL PRIVILEGES ON TABLE "
        "payflow.provider_event_inbox "
        "FROM PUBLIC, payflow_runtime"
    ) in sql

    assert (
        "GRANT SELECT, INSERT ON TABLE "
        "payflow.provider_event_inbox "
        "TO payflow_runtime"
    ) in sql

    assert "GRANT UPDATE" not in sql
    assert "GRANT DELETE" not in sql
    assert "GRANT TRUNCATE" not in sql


def test_migration_does_not_modify_payment_state_tables():
    sql = render_upgrade()

    assert "UPDATE payflow.payment_orders" not in sql
    assert "UPDATE payflow.payment_attempts" not in sql
    assert "DELETE FROM" not in sql


def test_nonempty_event_inbox_downgrade_is_blocked():
    source = MIGRATION_PATH.read_text(encoding="utf-8")

    assert (
        "Refusing to drop non-empty provider event inbox"
        in source
    )

    assert callable(load_migration().downgrade)
