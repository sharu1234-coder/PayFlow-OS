"""Source-only checks for durable attempt idempotency schema."""

import importlib.util
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy import (
    CheckConstraint,
    ForeignKeyConstraint,
    UniqueConstraint,
)

from app.models.payments import (
    PaymentAttemptIdempotencyRecord,
    PaymentOrder,
)


REVISION = "e4b3c1a8d205"
TABLE = "payment_attempt_idempotency_records"


def load_migration():
    path = (
        Path(__file__).resolve().parents[1]
        / "alembic"
        / "versions"
        / f"{REVISION}_attempt_idempotency_records.py"
    )

    assert path.is_file()

    spec = importlib.util.spec_from_file_location(
        "payflow_attempt_idempotency_migration",
        path,
    )

    assert spec is not None
    assert spec.loader is not None

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


def named_constraints(table, cls):
    return {
        item.name: item
        for item in table.constraints
        if isinstance(item, cls)
    }


def test_dedicated_table_and_required_columns():
    table = PaymentAttemptIdempotencyRecord.__table__

    assert table.name == TABLE

    assert {
        "id",
        "organization_id",
        "order_id",
        "idempotency_key",
        "request_fingerprint",
        "attempt_number",
        "status",
        "created_at",
    } == set(table.c.keys())

    assert table.c.attempt_number.nullable is True
    assert table.c.organization_id.nullable is False
    assert table.c.order_id.nullable is False


def test_tenant_key_and_order_uniqueness():
    record_constraints = named_constraints(
        PaymentAttemptIdempotencyRecord.__table__,
        UniqueConstraint,
    )

    record_unique = record_constraints[
        "uq_attempt_idem_tenant_key"
    ]

    assert [
        column.name for column in record_unique.columns
    ] == [
        "organization_id",
        "idempotency_key",
    ]

    order_constraints = named_constraints(
        PaymentOrder.__table__,
        UniqueConstraint,
    )

    order_unique = order_constraints[
        "uq_payment_orders_tenant_id"
    ]

    assert [
        column.name for column in order_unique.columns
    ] == [
        "organization_id",
        "id",
    ]


def test_reserved_record_references_correct_tenant_order():
    fks = named_constraints(
        PaymentAttemptIdempotencyRecord.__table__,
        ForeignKeyConstraint,
    )

    fk = fks["fk_attempt_idem_tenant_order"]

    assert [
        col.name for col in fk.columns
    ] == [
        "organization_id",
        "order_id",
    ]

    assert [
        element.target_fullname
        for element in fk.elements
    ] == [
        "payflow.payment_orders.organization_id",
        "payflow.payment_orders.id",
    ]

    assert fk.ondelete == "RESTRICT"


def test_completed_record_references_exact_attempt():
    fks = named_constraints(
        PaymentAttemptIdempotencyRecord.__table__,
        ForeignKeyConstraint,
    )

    fk = fks["fk_attempt_idem_tenant_attempt"]

    assert [
        col.name for col in fk.columns
    ] == [
        "organization_id",
        "order_id",
        "attempt_number",
    ]

    assert [
        element.target_fullname
        for element in fk.elements
    ] == [
        "payflow.payment_attempts.organization_id",
        "payflow.payment_attempts.order_id",
        "payflow.payment_attempts.attempt_number",
    ]


def test_status_mapping_and_fingerprint_constraints():
    checks = named_constraints(
        PaymentAttemptIdempotencyRecord.__table__,
        CheckConstraint,
    )

    mapping = str(
        checks["ck_attempt_idem_status_mapping"].sqltext
    )

    assert "attempt_number IS NULL" in mapping
    assert "attempt_number IS NOT NULL" in mapping
    assert "'reserved'" in mapping
    assert "'completed'" in mapping

    fingerprint = str(
        checks["ck_attempt_idem_fingerprint_format"].sqltext
    )

    key_format = str(
        checks["ck_attempt_idem_key_format"].sqltext
    )

    assert "[0-9a-f]{64}" in fingerprint
    assert "[A-Za-z0-9_-]{10,128}" in key_format


def test_migration_revision_upgrade_and_runtime_grants():
    module = load_migration()

    assert module.revision == REVISION
    assert module.down_revision == "d7a2f6c8b310"

    with (
        patch.object(
            module.op,
            "create_unique_constraint",
        ) as create_unique,
        patch.object(
            module.op,
            "create_table",
        ) as create_table,
        patch.object(
            module.op,
            "execute",
        ) as execute,
    ):
        module.upgrade()

    create_unique.assert_called_once_with(
        "uq_payment_orders_tenant_id",
        "payment_orders",
        ["organization_id", "id"],
        schema="payflow",
    )

    assert create_table.call_count == 1
    assert create_table.call_args.args[0] == TABLE
    assert create_table.call_args.kwargs["schema"] == "payflow"

    statements = [
        call.args[0]
        for call in execute.call_args_list
    ]

    assert len(statements) == 3

    assert "REVOKE ALL PRIVILEGES" in statements[0]
    assert "GRANT SELECT, INSERT" in statements[1]
    assert "GRANT UPDATE (status, attempt_number)" in statements[2]

    assert all(
        "payment_attempt_idempotency_records" in statement
        for statement in statements
    )


def test_downgrade_refuses_to_delete_idempotency_history():
    module = load_migration()

    with (
        patch.object(module.op, "get_bind") as get_bind,
        patch.object(module.op, "drop_table") as drop_table,
        patch.object(module.op, "drop_constraint") as drop_constraint,
    ):
        get_bind.return_value.execute.return_value.scalar_one.return_value = (
            True
        )

        with pytest.raises(
            RuntimeError,
            match="attempt idempotency history",
        ):
            module.downgrade()

    drop_table.assert_not_called()
    drop_constraint.assert_not_called()


def test_empty_history_downgrade_drops_only_new_schema():
    module = load_migration()

    with (
        patch.object(module.op, "get_bind") as get_bind,
        patch.object(module.op, "drop_table") as drop_table,
        patch.object(module.op, "drop_constraint") as drop_constraint,
    ):
        get_bind.return_value.execute.return_value.scalar_one.return_value = (
            False
        )

        module.downgrade()

    drop_table.assert_called_once_with(
        TABLE,
        schema="payflow",
    )

    drop_constraint.assert_called_once_with(
        "uq_payment_orders_tenant_id",
        "payment_orders",
        type_="unique",
        schema="payflow",
    )
