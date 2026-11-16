"""Enforce append-only runtime access to audit events.

Revision ID: c7e1054a9b20
Revises: ab0f91dda403
"""

from alembic import op

revision = "c7e1054a9b20"
down_revision = "ab0f91dda403"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "REVOKE UPDATE, DELETE, TRUNCATE "
        "ON TABLE payflow.audit_events "
        "FROM payflow_runtime"
    )


def downgrade() -> None:
    raise RuntimeError(
        "Audit privileges are intentionally not restored "
        "by an automatic downgrade. Manual security review required."
    )