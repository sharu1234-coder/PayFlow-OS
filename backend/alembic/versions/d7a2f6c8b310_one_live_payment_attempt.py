"""Prevent multiple live or successful attempts per payment order.

Revision ID: d7a2f6c8b310
Revises: b2c1f20a7d31

This migration adds a database uniqueness invariant only.
It does not process payments or modify payment statuses.

Existing conflicting rows will cause index creation to fail.
No existing financial records are automatically changed.
"""

from alembic import op
import sqlalchemy as sa


revision = "d7a2f6c8b310"
down_revision = "b2c1f20a7d31"
branch_labels = None
depends_on = None


INDEX_NAME = "ux_payment_attempts_one_live_or_successful"

LIVE_OR_SUCCESSFUL = sa.text(
    "status IN ("
    "'created', 'requires_action', 'processing', "
    "'authorized', 'succeeded'"
    ")"
)


def upgrade() -> None:
    op.create_index(
        INDEX_NAME,
        "payment_attempts",
        ["organization_id", "order_id"],
        unique=True,
        schema="payflow",
        postgresql_where=LIVE_OR_SUCCESSFUL,
    )


def downgrade() -> None:
    """Refuse to remove financial uniqueness with attempt history."""
    bind = op.get_bind()

    has_history = bind.execute(
        sa.text(
            "SELECT EXISTS "
            "(SELECT 1 FROM payflow.payment_attempts)"
        )
    ).scalar_one()

    if has_history:
        raise RuntimeError(
            "Refusing to drop attempt uniqueness "
            "while payment attempt history exists"
        )

    op.drop_index(
        INDEX_NAME,
        table_name="payment_attempts",
        schema="payflow",
    )
