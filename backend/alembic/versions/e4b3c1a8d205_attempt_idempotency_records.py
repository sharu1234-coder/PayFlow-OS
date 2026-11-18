"""Durable, tenant-bound payment-attempt idempotency records.

Revision ID: e4b3c1a8d205
Revises: d7a2f6c8b310

Schema and least-privilege grants only.
No provider calls or payment-state changes.

A completed record references its original attempt through the
(organization_id, order_id, attempt_number) unique key.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "e4b3c1a8d205"
down_revision = "d7a2f6c8b310"
branch_labels = None
depends_on = None


TABLE = "payment_attempt_idempotency_records"


def upgrade() -> None:
    # PostgreSQL requires a unique referenced key for the
    # (organization_id, order_id) composite foreign key.
    op.create_unique_constraint(
        "uq_payment_orders_tenant_id",
        "payment_orders",
        ["organization_id", "id"],
        schema="payflow",
    )

    op.create_table(
        TABLE,
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "order_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "idempotency_key",
            sa.String(length=128),
            nullable=False,
        ),
        sa.Column(
            "request_fingerprint",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "attempt_number",
            sa.Integer(),
            nullable=True,
        ),
        sa.Column(
            "status",
            sa.String(length=24),
            server_default=sa.text("'reserved'"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "order_id"],
            [
                "payflow.payment_orders.organization_id",
                "payflow.payment_orders.id",
            ],
            name="fk_attempt_idem_tenant_order",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            [
                "organization_id",
                "order_id",
                "attempt_number",
            ],
            [
                "payflow.payment_attempts.organization_id",
                "payflow.payment_attempts.order_id",
                "payflow.payment_attempts.attempt_number",
            ],
            name="fk_attempt_idem_tenant_attempt",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "id",
            name="pk_payment_attempt_idempotency_records",
        ),
        sa.UniqueConstraint(
            "organization_id",
            "idempotency_key",
            name="uq_attempt_idem_tenant_key",
        ),
        sa.CheckConstraint(
            "idempotency_key ~ '^[A-Za-z0-9_-]{10,128}$'",
            name=sa.schema.conv("ck_attempt_idem_key_format"),
        ),
        sa.CheckConstraint(
            "request_fingerprint ~ '^[0-9a-f]{64}$'",
            name=sa.schema.conv("ck_attempt_idem_fingerprint_format"),
        ),
        sa.CheckConstraint(
            "status IN ('reserved', 'completed')",
            name=sa.schema.conv("ck_attempt_idem_status_valid"),
        ),
        sa.CheckConstraint(
            "("
            "status = 'reserved' AND attempt_number IS NULL"
            ") OR ("
            "status = 'completed' AND attempt_number IS NOT NULL"
            ")",
            name=sa.schema.conv("ck_attempt_idem_status_mapping"),
        ),
        schema="payflow",
    )

    # The runtime can reserve a key and complete its mapping,
    # but cannot delete records or modify identity fields.
    op.execute(
        "REVOKE ALL PRIVILEGES ON TABLE "
        "payflow.payment_attempt_idempotency_records "
        "FROM PUBLIC, payflow_runtime"
    )

    op.execute(
        "GRANT SELECT, INSERT ON TABLE "
        "payflow.payment_attempt_idempotency_records "
        "TO payflow_runtime"
    )

    op.execute(
        "GRANT UPDATE (status, attempt_number) ON TABLE "
        "payflow.payment_attempt_idempotency_records "
        "TO payflow_runtime"
    )


def downgrade() -> None:
    bind = op.get_bind()

    has_history = bind.execute(
        sa.text(
            "SELECT EXISTS "
            "(SELECT 1 FROM "
            "payflow.payment_attempt_idempotency_records)"
        )
    ).scalar_one()

    if has_history:
        raise RuntimeError(
            "Refusing to drop attempt idempotency history"
        )

    op.drop_table(
        TABLE,
        schema="payflow",
    )

    op.drop_constraint(
        "uq_payment_orders_tenant_id",
        "payment_orders",
        type_="unique",
        schema="payflow",
    )
