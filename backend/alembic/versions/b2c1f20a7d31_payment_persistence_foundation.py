"""Payment persistence foundation.

Revision ID: b2c1f20a7d31
Revises: abaee6e0c017

Schema and grants only: no live payment processing.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "b2c1f20a7d31"
down_revision = "abaee6e0c017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "payment_orders",
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
            "merchant_order_reference",
            sa.String(length=128),
            nullable=False,
        ),
        sa.Column(
            "amount_minor_units",
            sa.BigInteger(),
            nullable=False,
        ),
        sa.Column(
            "currency",
            sa.String(length=3),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.String(length=24),
            server_default=sa.text("'open'"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "amount_minor_units > 0",
            name=op.f("ck_payment_orders_amount_positive"),
        ),
        sa.CheckConstraint(
            "currency ~ '^[A-Z]{3}$'",
            name=op.f("ck_payment_orders_currency_format"),
        ),
        sa.CheckConstraint(
            "merchant_order_reference ~ "
            "'^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'",
            name=op.f("ck_payment_orders_reference_format"),
        ),
        sa.CheckConstraint(
            "status IN ('open', 'paid', 'cancelled')",
            name=op.f("ck_payment_orders_status_valid"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["payflow.organizations.id"],
            name=op.f(
                "fk_payment_orders_organization_id_organizations"
            ),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "id",
            name=op.f("pk_payment_orders"),
        ),
        sa.UniqueConstraint(
            "organization_id",
            "merchant_order_reference",
            name=op.f(
                "uq_payment_orders_tenant_reference"
            ),
        ),
        sa.UniqueConstraint(
            "organization_id",
            "id",
            "amount_minor_units",
            "currency",
            name=op.f(
                "uq_payment_orders_tenant_amount_identity"
            ),
        ),
        schema="payflow",
    )

    op.create_index(
        "ix_payment_orders_org_created_at",
        "payment_orders",
        ["organization_id", "created_at"],
        unique=False,
        schema="payflow",
    )

    op.create_table(
        "payment_attempts",
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
            "attempt_number",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "amount_minor_units",
            sa.BigInteger(),
            nullable=False,
        ),
        sa.Column(
            "currency",
            sa.String(length=3),
            nullable=False,
        ),
        sa.Column(
            "provider_code",
            sa.String(length=32),
            nullable=False,
        ),
        sa.Column(
            "provider_payment_id",
            sa.String(length=128),
            nullable=True,
        ),
        sa.Column(
            "status",
            sa.String(length=24),
            server_default=sa.text("'created'"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "attempt_number > 0",
            name=op.f(
                "ck_payment_attempts_attempt_number_positive"
            ),
        ),
        sa.CheckConstraint(
            "amount_minor_units > 0",
            name=op.f("ck_payment_attempts_amount_positive"),
        ),
        sa.CheckConstraint(
            "currency ~ '^[A-Z]{3}$'",
            name=op.f("ck_payment_attempts_currency_format"),
        ),
        sa.CheckConstraint(
            "provider_code ~ '^[a-z][a-z0-9_]{1,31}$'",
            name=op.f(
                "ck_payment_attempts_provider_code_format"
            ),
        ),
        sa.CheckConstraint(
            "provider_payment_id IS NULL OR "
            "length(provider_payment_id) > 0",
            name=op.f(
                "ck_payment_attempts_provider_payment_id_nonempty"
            ),
        ),
        sa.CheckConstraint(
            "status IN ("
            "'created', 'requires_action', 'processing', "
            "'authorized', 'succeeded', 'failed', 'cancelled'"
            ")",
            name=op.f("ck_payment_attempts_status_valid"),
        ),
        sa.ForeignKeyConstraint(
            [
                "organization_id",
                "order_id",
                "amount_minor_units",
                "currency",
            ],
            [
                "payflow.payment_orders.organization_id",
                "payflow.payment_orders.id",
                "payflow.payment_orders.amount_minor_units",
                "payflow.payment_orders.currency",
            ],
            name=op.f(
                "fk_payment_attempts_tenant_order_amount"
            ),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "id",
            name=op.f("pk_payment_attempts"),
        ),
        sa.UniqueConstraint(
            "organization_id",
            "order_id",
            "attempt_number",
            name=op.f(
                "uq_payment_attempts_order_number"
            ),
        ),
        sa.UniqueConstraint(
            "organization_id",
            "provider_code",
            "provider_payment_id",
            name=op.f(
                "uq_payment_attempts_provider_payment"
            ),
        ),
        schema="payflow",
    )

    op.create_index(
        "ix_payment_attempts_org_order_status",
        "payment_attempts",
        ["organization_id", "order_id", "status"],
        unique=False,
        schema="payflow",
    )

    op.create_table(
        "payment_idempotency_records",
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
            "operation",
            sa.String(length=32),
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
            "status",
            sa.String(length=32),
            server_default=sa.text("'reserved'"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "operation IN ('create_payment', 'create_refund')",
            name=op.f(
                "ck_payment_idempotency_records_operation_valid"
            ),
        ),
        sa.CheckConstraint(
            "idempotency_key ~ '^[A-Za-z0-9_-]{10,128}$'",
            name=op.f(
                "ck_payment_idempotency_records_key_format"
            ),
        ),
        sa.CheckConstraint(
            "request_fingerprint ~ '^[0-9a-f]{64}$'",
            name=op.f(
                "ck_payment_idempotency_records_fingerprint_format"
            ),
        ),
        sa.CheckConstraint(
            "status IN ("
            "'reserved', 'completed', "
            "'requires_reconciliation', 'failed'"
            ")",
            name=op.f(
                "ck_payment_idempotency_records_status_valid"
            ),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["payflow.organizations.id"],
            name=op.f(
                "fk_payment_idempotency_records_"
                "organization_id_organizations"
            ),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "id",
            name=op.f("pk_payment_idempotency_records"),
        ),
        sa.UniqueConstraint(
            "organization_id",
            "operation",
            "idempotency_key",
            name=op.f(
                "uq_payment_idempotency_tenant_operation_key"
            ),
        ),
        schema="payflow",
    )

    op.create_index(
        "ix_payment_idempotency_org_created_at",
        "payment_idempotency_records",
        ["organization_id", "created_at"],
        unique=False,
        schema="payflow",
    )

    # Reset any default grants on newly created tables.
    # Runtime is intentionally not permitted DELETE/TRUNCATE.
    for table in (
        "payment_orders",
        "payment_attempts",
        "payment_idempotency_records",
    ):
        op.execute(
            f"REVOKE ALL PRIVILEGES ON TABLE "
            f"payflow.{table} FROM PUBLIC, payflow_runtime"
        )

        op.execute(
            f"GRANT SELECT, INSERT ON TABLE "
            f"payflow.{table} TO payflow_runtime"
        )

    # Protect tenant ownership, amount and currency columns.
    op.execute(
        "GRANT UPDATE (status) "
        "ON TABLE payflow.payment_orders "
        "TO payflow_runtime"
    )

    op.execute(
        "GRANT UPDATE (status, provider_payment_id) "
        "ON TABLE payflow.payment_attempts "
        "TO payflow_runtime"
    )

    # Idempotency keys and fingerprints are not editable.
    op.execute(
        "GRANT UPDATE (status) "
        "ON TABLE payflow.payment_idempotency_records "
        "TO payflow_runtime"
    )


def downgrade() -> None:
    # Financial records must never be discarded by an
    # accidental routine downgrade.
    bind = op.get_bind()

    for table in (
        "payment_idempotency_records",
        "payment_attempts",
        "payment_orders",
    ):
        result = bind.execute(
            sa.text(
                f"SELECT EXISTS "
                f"(SELECT 1 FROM payflow.{table})"
            )
        ).scalar_one()

        if result:
            raise RuntimeError(
                "Refusing to drop non-empty payment table: "
                + table
            )

    op.drop_index(
        "ix_payment_idempotency_org_created_at",
        table_name="payment_idempotency_records",
        schema="payflow",
    )

    op.drop_table(
        "payment_idempotency_records",
        schema="payflow",
    )

    op.drop_index(
        "ix_payment_attempts_org_order_status",
        table_name="payment_attempts",
        schema="payflow",
    )

    op.drop_table(
        "payment_attempts",
        schema="payflow",
    )

    op.drop_index(
        "ix_payment_orders_org_created_at",
        table_name="payment_orders",
        schema="payflow",
    )

    op.drop_table(
        "payment_orders",
        schema="payflow",
    )
