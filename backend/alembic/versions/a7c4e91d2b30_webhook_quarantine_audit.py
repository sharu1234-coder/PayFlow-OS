"""Create restricted webhook quarantine audit schema.

Revision ID: a7c4e91d2b30
Revises: f3c2a119b607

Schema only. No processor role, privileged function, webhook
status mutation, public endpoint, or financial operation.

The API runtime role receives no audit table privileges.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "a7c4e91d2b30"
down_revision = "f3c2a119b607"
branch_labels = None
depends_on = None

TABLE = "webhook_quarantine_audit"


def upgrade() -> None:
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
            "provider_code",
            sa.String(length=32),
            nullable=False,
        ),
        sa.Column(
            "event_id",
            sa.String(length=128),
            nullable=False,
        ),
        sa.Column(
            "reason_code",
            sa.String(length=48),
            nullable=False,
        ),
        sa.Column(
            "processor_identity",
            sa.String(length=128),
            nullable=False,
        ),
        sa.Column(
            "from_status",
            sa.String(length=24),
            nullable=False,
            server_default=sa.text("'received'"),
        ),
        sa.Column(
            "to_status",
            sa.String(length=24),
            nullable=False,
            server_default=sa.text("'quarantined'"),
        ),
        sa.Column(
            "transitioned_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.ForeignKeyConstraint(
            [
                "organization_id",
                "provider_code",
                "event_id",
            ],
            [
                "payflow.provider_event_inbox.organization_id",
                "payflow.provider_event_inbox.provider_code",
                "payflow.provider_event_inbox.event_id",
            ],
            name="fk_webhook_quarantine_audit_event_identity",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "id",
            name=op.f("pk_webhook_quarantine_audit"),
        ),
        sa.UniqueConstraint(
            "organization_id",
            "provider_code",
            "event_id",
            name="uq_webhook_quarantine_audit_event",
        ),
        sa.CheckConstraint(
            "provider_code = 'sandbox_sim'",
            name=op.f(
                "ck_webhook_quarantine_audit_sandbox_only"
            ),
        ),
        sa.CheckConstraint(
            "reason_code IN ("
            "'unlinked_payment', "
            "'refund_linkage_unavailable'"
            ")",
            name=op.f(
                "ck_webhook_quarantine_audit_reason_valid"
            ),
        ),
        sa.CheckConstraint(
            "processor_identity ~ "
            "'^[a-z][a-z0-9_.:-]{2,127}$'",
            name=op.f(
                "ck_webhook_quarantine_audit_processor_identity_valid"
            ),
        ),
        sa.CheckConstraint(
            "from_status = 'received' "
            "AND to_status = 'quarantined'",
            name=op.f(
                "ck_webhook_quarantine_audit_transition_valid"
            ),
        ),
        schema="payflow",
    )

    op.create_index(
        "ix_webhook_quarantine_audit_org_time",
        TABLE,
        ["organization_id", "transitioned_at"],
        unique=False,
        schema="payflow",
    )

    # Explicitly prevent the API runtime and PUBLIC from
    # interacting with audit records. Do not add a GRANT
    # until a separate processor authorization design
    # and real PostgreSQL permission tests are complete.
    op.execute(
        "REVOKE ALL PRIVILEGES ON TABLE "
        "payflow.webhook_quarantine_audit "
        "FROM PUBLIC, payflow_runtime"
    )

    # The existing inbox SELECT/INSERT-only grants remain
    # untouched. This migration does not allow inbox UPDATE.


def downgrade() -> None:
    # Audit records must never be silently discarded.

    bind = op.get_bind()

    has_records = bind.execute(
        sa.text(
            "SELECT EXISTS ("
            "SELECT 1 FROM payflow.webhook_quarantine_audit"
            ")"
        )
    ).scalar_one()

    if has_records:
        raise RuntimeError(
            "Refusing to drop non-empty webhook quarantine audit"
        )

    op.drop_index(
        "ix_webhook_quarantine_audit_org_time",
        table_name=TABLE,
        schema="payflow",
    )

    op.drop_table(
        TABLE,
        schema="payflow",
    )
