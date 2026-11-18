"""Create verified sandbox provider event inbox.

Revision ID: f3c2a119b607
Revises: e4b3c1a8d205

Schema and restrictive grants only.
No gateway integration or payment-state changes.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "f3c2a119b607"
down_revision = "e4b3c1a8d205"
branch_labels = None
depends_on = None

TABLE = "provider_event_inbox"


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
            "event_type",
            sa.String(length=48),
            nullable=False,
        ),
        sa.Column(
            "provider_object_id",
            sa.String(length=128),
            nullable=False,
        ),
        sa.Column(
            "occurred_at",
            sa.BigInteger(),
            nullable=False,
        ),
        sa.Column(
            "signed_at",
            sa.BigInteger(),
            nullable=False,
        ),
        sa.Column(
            "payload_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.String(length=24),
            server_default=sa.text("'received'"),
            nullable=False,
        ),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "processed_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["payflow.organizations.id"],
            name=op.f(
                "fk_provider_event_inbox_organization_id_organizations"
            ),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "id",
            name=op.f("pk_provider_event_inbox"),
        ),
        sa.UniqueConstraint(
            "organization_id",
            "provider_code",
            "event_id",
            name="uq_provider_event_inbox_identity",
        ),
        sa.CheckConstraint(
            "provider_code = 'sandbox_sim'",
            name=op.f("ck_provider_event_inbox_sandbox_only"),
        ),
        sa.CheckConstraint(
            "event_id ~ "
            "'^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'",
            name=op.f("ck_provider_event_inbox_event_id_format"),
        ),
        sa.CheckConstraint(
            "event_type IN ("
            "'payment.processing', "
            "'payment.succeeded', "
            "'payment.failed', "
            "'refund.pending', "
            "'refund.succeeded', "
            "'refund.failed'"
            ")",
            name=op.f("ck_provider_event_inbox_event_type_valid"),
        ),
        sa.CheckConstraint(
            "provider_object_id ~ "
            "'^sim_(pay|ref)_[0-9a-f]{32}$'",
            name=op.f("ck_provider_event_inbox_object_id_format"),
        ),
        sa.CheckConstraint(
            "("
            "event_type LIKE 'payment.%' "
            "AND provider_object_id LIKE 'sim_pay_%'"
            ") OR ("
            "event_type LIKE 'refund.%' "
            "AND provider_object_id LIKE 'sim_ref_%'"
            ")",
            name=op.f("ck_provider_event_inbox_object_kind_match"),
        ),
        sa.CheckConstraint(
            "occurred_at > 0 "
            "AND signed_at > 0 "
            "AND signed_at < 1000000000000 "
            "AND occurred_at <= signed_at + 30",
            name=op.f("ck_provider_event_inbox_timestamps_valid"),
        ),
        sa.CheckConstraint(
            "payload_sha256 ~ '^[0-9a-f]{64}$'",
            name=op.f("ck_provider_event_inbox_payload_hash_format"),
        ),
        sa.CheckConstraint(
            "status IN ('received', 'processed', 'quarantined')",
            name=op.f("ck_provider_event_inbox_status_valid"),
        ),
        sa.CheckConstraint(
            "("
            "status = 'received' AND processed_at IS NULL"
            ") OR ("
            "status IN ('processed', 'quarantined') "
            "AND processed_at IS NOT NULL"
            ")",
            name=op.f(
                "ck_provider_event_inbox_status_timestamp_match"
            ),
        ),
        schema="payflow",
    )

    op.create_index(
        "ix_provider_event_inbox_org_status_received",
        TABLE,
        ["organization_id", "status", "received_at"],
        unique=False,
        schema="payflow",
    )

    op.create_index(
        "ix_provider_event_inbox_org_object",
        TABLE,
        ["organization_id", "provider_code", "provider_object_id"],
        unique=False,
        schema="payflow",
    )

    # Explicit least-privilege grants.
    # No UPDATE privilege until the processing service exists.
    # Never permit runtime DELETE or TRUNCATE.

    op.execute(
        "REVOKE ALL PRIVILEGES ON TABLE "
        "payflow.provider_event_inbox "
        "FROM PUBLIC, payflow_runtime"
    )

    op.execute(
        "GRANT SELECT, INSERT ON TABLE "
        "payflow.provider_event_inbox "
        "TO payflow_runtime"
    )


def downgrade() -> None:
    # Event history is audit-sensitive. Never silently discard it.

    bind = op.get_bind()

    has_events = bind.execute(
        sa.text(
            "SELECT EXISTS ("
            "SELECT 1 FROM payflow.provider_event_inbox"
            ")"
        )
    ).scalar_one()

    if has_events:
        raise RuntimeError(
            "Refusing to drop non-empty provider event inbox"
        )

    op.drop_index(
        "ix_provider_event_inbox_org_object",
        table_name=TABLE,
        schema="payflow",
    )

    op.drop_index(
        "ix_provider_event_inbox_org_status_received",
        table_name=TABLE,
        schema="payflow",
    )

    op.drop_table(TABLE, schema="payflow")
