"""Offline metadata tests: no database schema is changed."""

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    ForeignKeyConstraint,
    UniqueConstraint,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable

from app.core.model_base import Base
from app.models.identity import Organization  # noqa: F401
from app.models.payments import (
    PaymentAttempt,
    PaymentIdempotencyRecord,
    PaymentOrder,
)


TABLES = (
    PaymentOrder.__table__,
    PaymentAttempt.__table__,
    PaymentIdempotencyRecord.__table__,
)


def uniques(table):
    return {
        frozenset(c.columns.keys())
        for c in table.constraints
        if isinstance(c, UniqueConstraint)
    }


def check_expressions(table):
    return [
        str(c.sqltext)
        for c in table.constraints
        if isinstance(c, CheckConstraint)
    ]


def test_three_payment_tables_use_payflow_schema():
    assert {table.name for table in TABLES} == {
        "payment_orders",
        "payment_attempts",
        "payment_idempotency_records",
    }

    assert all(
        table.schema == "payflow"
        for table in TABLES
    )


def test_tables_registered_with_existing_base():
    for table in TABLES:
        assert Base.metadata.tables[table.fullname] is table


def test_every_payment_table_has_uuid_primary_key():
    for table in TABLES:
        assert list(table.primary_key.columns.keys()) == ["id"]
        assert isinstance(
            table.c.id.type,
            postgresql.UUID,
        )


def test_payment_orders_have_tenant_scoped_reference():
    table = PaymentOrder.__table__

    assert frozenset({
        "organization_id",
        "merchant_order_reference",
    }) in uniques(table)


def test_order_has_composite_identity_for_attempt_validation():
    table = PaymentOrder.__table__

    assert frozenset({
        "organization_id",
        "id",
        "amount_minor_units",
        "currency",
    }) in uniques(table)


def test_attempt_foreign_key_enforces_tenant_and_money():
    table = PaymentAttempt.__table__

    constraints = [
        constraint
        for constraint in table.constraints
        if isinstance(constraint, ForeignKeyConstraint)
    ]

    composite = [
        constraint
        for constraint in constraints
        if set(constraint.column_keys) == {
            "organization_id",
            "order_id",
            "amount_minor_units",
            "currency",
        }
    ]

    assert len(composite) == 1

    actual_targets = [
        element.target_fullname
        for element in composite[0].elements
    ]

    assert actual_targets == [
        "payflow.payment_orders.organization_id",
        "payflow.payment_orders.id",
        "payflow.payment_orders.amount_minor_units",
        "payflow.payment_orders.currency",
    ]

    assert composite[0].ondelete == "RESTRICT"


def test_attempt_number_unique_per_order_and_tenant():
    assert frozenset({
        "organization_id",
        "order_id",
        "attempt_number",
    }) in uniques(PaymentAttempt.__table__)


def test_provider_payment_id_unique_within_tenant_and_provider():
    assert frozenset({
        "organization_id",
        "provider_code",
        "provider_payment_id",
    }) in uniques(PaymentAttempt.__table__)


def test_idempotency_key_unique_per_tenant_and_operation():
    assert frozenset({
        "organization_id",
        "operation",
        "idempotency_key",
    }) in uniques(PaymentIdempotencyRecord.__table__)


def test_idempotency_fingerprint_has_fixed_length():
    table = PaymentIdempotencyRecord.__table__

    assert table.c.request_fingerprint.type.length == 64

    assert any(
        "^[0-9a-f]{64}$" in expression
        for expression in check_expressions(table)
    )


def test_amount_columns_are_bigint_and_positive():
    for model in (PaymentOrder, PaymentAttempt):
        table = model.__table__

        assert isinstance(
            table.c.amount_minor_units.type,
            BigInteger,
        )

        assert any(
            "amount_minor_units > 0" in expression
            for expression in check_expressions(table)
        )


def test_critical_tenant_fields_are_not_nullable():
    for table in TABLES:
        assert table.c.organization_id.nullable is False

    attempt = PaymentAttempt.__table__

    for name in (
        "order_id",
        "amount_minor_units",
        "currency",
        "provider_code",
        "attempt_number",
    ):
        assert attempt.c[name].nullable is False


def test_provider_id_may_be_unavailable_at_creation():
    table = PaymentAttempt.__table__

    assert table.c.provider_payment_id.nullable is True


def test_currency_format_checks_exist():
    for model in (PaymentOrder, PaymentAttempt):
        assert any(
            "^[A-Z]{3}$" in expression
            for expression in check_expressions(model.__table__)
        )


def test_unsafe_raw_payment_fields_are_absent():
    forbidden = {
        "card_number",
        "card_cvv",
        "card_pin",
        "raw_gateway_response",
        "provider_secret",
        "api_key",
    }

    for table in TABLES:
        assert forbidden.isdisjoint(table.c.keys())


def test_postgresql_create_table_sql_compiles():
    for table in TABLES:
        statement = str(
            CreateTable(table).compile(
                dialect=postgresql.dialect()
            )
        )

        assert "CREATE TABLE payflow." in statement
        assert table.name in statement


def test_idempotency_records_have_unique_scoped_index():
    table = PaymentIdempotencyRecord.__table__

    assert any(
        "organization_id" in index.columns.keys()
        for index in table.indexes
    )


def test_order_and_attempt_status_checks_exist():
    for model in (PaymentOrder, PaymentAttempt):
        assert any(
            "status IN" in expression
            for expression in check_expressions(model.__table__)
        )
