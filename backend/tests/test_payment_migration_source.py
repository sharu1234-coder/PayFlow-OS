"""Offline migration rendering and metadata discovery tests."""

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
    / "alembic/versions/"
    "b2c1f20a7d31_payment_persistence_foundation.py"
)


def load_migration():
    spec = importlib.util.spec_from_file_location(
        "payflow_payment_migration_under_test",
        MIGRATION_PATH,
    )
    assert spec is not None
    assert spec.loader is not None

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def offline_upgrade_sql():
    module = load_migration()
    stream = StringIO()

    context = MigrationContext.configure(
        dialect_name="postgresql",
        opts={
            "as_sql": True,
            "output_buffer": stream,
        },
    )

    module.op = Operations(context)
    module.upgrade()

    return stream.getvalue()


def test_payment_models_autoload_with_app_models():
    expected = {
        "payflow.payment_orders",
        "payflow.payment_attempts",
        "payflow.payment_idempotency_records",
    }
    assert expected.issubset(Base.metadata.tables)


def test_migration_revision_chain():
    scripts = ScriptDirectory.from_config(
        Config("alembic.ini")
    )
    assert scripts.get_heads() == ["e4b3c1a8d205"]

    migration = load_migration()
    assert migration.down_revision == "abaee6e0c017"


def test_offline_upgrade_creates_all_payment_tables():
    sql = offline_upgrade_sql()

    for table in (
        "payment_orders",
        "payment_attempts",
        "payment_idempotency_records",
    ):
        assert f"CREATE TABLE payflow.{table}" in sql


def test_offline_upgrade_has_tenant_integrity():
    sql = offline_upgrade_sql()

    assert (
        "fk_payment_attempts_tenant_order_amount"
        in sql
    )
    assert (
        "uq_payment_orders_tenant_amount_identity"
        in sql
    )
    assert (
        "uq_payment_idempotency_tenant_operation_key"
        in sql
    )


def test_runtime_grants_exclude_delete_and_truncate():
    sql = offline_upgrade_sql()

    for table in (
        "payment_orders",
        "payment_attempts",
        "payment_idempotency_records",
    ):
        assert (
            f"REVOKE ALL PRIVILEGES ON TABLE "
            f"payflow.{table} FROM PUBLIC, payflow_runtime"
            in sql
        )

        assert (
            f"GRANT SELECT, INSERT ON TABLE "
            f"payflow.{table} TO payflow_runtime"
            in sql
        )

    assert "GRANT DELETE" not in sql
    assert "GRANT TRUNCATE" not in sql


def test_runtime_only_updates_approved_columns():
    sql = offline_upgrade_sql()

    assert (
        "GRANT UPDATE (status) "
        "ON TABLE payflow.payment_orders"
    ) in sql

    assert (
        "GRANT UPDATE (status, provider_payment_id) "
        "ON TABLE payflow.payment_attempts"
    ) in sql

    assert (
        "GRANT UPDATE (status) "
        "ON TABLE payflow.payment_idempotency_records"
    ) in sql

    assert "GRANT UPDATE (amount_minor_units)" not in sql


def test_downgrade_refuses_nonempty_financial_records():
    migration = load_migration()
    source = MIGRATION_PATH.read_text(encoding="utf-8")

    assert callable(migration.downgrade)
    assert "SELECT EXISTS" in source
    assert "Refusing to drop non-empty payment table" in source
