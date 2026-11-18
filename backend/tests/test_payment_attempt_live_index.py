"""Source-only contract tests for the attempt uniqueness index."""

import importlib.util
import re
from pathlib import Path

import pytest
from unittest.mock import patch

from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateIndex

from app.models.payments import PaymentAttempt


INDEX_NAME = "ux_payment_attempts_one_live_or_successful"
REVISION = "d7a2f6c8b310"

PROTECTED_STATES = {
    "created",
    "requires_action",
    "processing",
    "authorized",
    "succeeded",
}


def get_index():
    matches = [
        index
        for index in PaymentAttempt.__table__.indexes
        if index.name == INDEX_NAME
    ]

    assert len(matches) == 1
    return matches[0]


def predicate_text():
    index = get_index()
    predicate = index.dialect_options["postgresql"]["where"]

    assert predicate is not None
    return str(predicate)


def load_migration():
    path = (
        Path(__file__).resolve().parents[1]
        / "alembic"
        / "versions"
        / f"{REVISION}_one_live_payment_attempt.py"
    )

    assert path.is_file()

    spec = importlib.util.spec_from_file_location(
        "payflow_attempt_index_migration",
        path,
    )

    assert spec is not None
    assert spec.loader is not None

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


def test_index_is_unique_and_tenant_order_scoped():
    index = get_index()

    assert index.unique is True

    assert [column.name for column in index.columns] == [
        "organization_id",
        "order_id",
    ]


def test_partial_predicate_matches_all_protected_states():
    predicate = predicate_text()

    assert predicate.startswith("status IN (")

    states = set(
        re.findall(r"'([^']+)'", predicate)
    )

    assert states == PROTECTED_STATES

    # Failed and cancelled historical attempts remain
    # outside the unique-index predicate.
    assert "failed" not in states
    assert "cancelled" not in states


def test_postgresql_compilation_is_unique_and_partial():
    index = get_index()

    compiled = str(
        CreateIndex(index).compile(
            dialect=postgresql.dialect()
        )
    )

    assert "CREATE UNIQUE INDEX" in compiled
    assert INDEX_NAME in compiled
    assert "organization_id" in compiled
    assert "order_id" in compiled
    assert "WHERE status IN (" in compiled


def test_migration_revision_and_upgrade_contract():
    migration = load_migration()

    assert migration.revision == REVISION
    assert migration.down_revision == "b2c1f20a7d31"

    with patch.object(migration.op, "create_index") as create:
        migration.upgrade()

    create.assert_called_once()

    args, kwargs = create.call_args

    assert args == (
        INDEX_NAME,
        "payment_attempts",
        ["organization_id", "order_id"],
    )

    assert kwargs["unique"] is True
    assert kwargs["schema"] == "payflow"

    assert str(kwargs["postgresql_where"]) == predicate_text()


def test_downgrade_only_drops_introduced_index():
    migration = load_migration()

    with patch.object(migration.op, "get_bind") as get_bind:
        get_bind.return_value.execute.return_value.scalar_one.return_value = (
            False
        )

        with patch.object(migration.op, "drop_index") as drop:
            migration.downgrade()

        drop.assert_called_once_with(
            INDEX_NAME,
            table_name="payment_attempts",
            schema="payflow",
        )

        statement = get_bind.return_value.execute.call_args.args[0]

        assert "payflow.payment_attempts" in str(statement)


def test_downgrade_refuses_when_payment_history_exists():
    migration = load_migration()

    with patch.object(migration.op, "get_bind") as get_bind:
        get_bind.return_value.execute.return_value.scalar_one.return_value = (
            True
        )

        with patch.object(migration.op, "drop_index") as drop:
            with pytest.raises(
                RuntimeError,
                match="payment attempt history exists",
            ):
                migration.downgrade()

        drop.assert_not_called()


def test_downgrade_fails_closed_if_history_query_fails():
    migration = load_migration()

    with patch.object(migration.op, "get_bind") as get_bind:
        get_bind.return_value.execute.side_effect = RuntimeError(
            "synthetic storage error"
        )

        with patch.object(migration.op, "drop_index") as drop:
            with pytest.raises(
                RuntimeError,
                match="synthetic storage error",
            ):
                migration.downgrade()

        drop.assert_not_called()
