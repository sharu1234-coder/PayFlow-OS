"""Schema for restricted sandbox webhook quarantine audit records.

Persistence model only. There is no quarantine writer or
application-runtime privilege to access this audit table.

Records identify one verified inbox event using the existing
unique tenant/provider/event identity.

An audit row must eventually be inserted atomically with a
restricted inbox transition. This model does not authorize one.
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.model_base import Base


class WebhookQuarantineAudit(Base):
    __tablename__ = "webhook_quarantine_audit"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
    )

    provider_code: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    event_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )

    reason_code: Mapped[str] = mapped_column(
        String(48),
        nullable=False,
    )

    processor_identity: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )

    from_status: Mapped[str] = mapped_column(
        String(24),
        nullable=False,
        server_default=text("'received'"),
    )

    to_status: Mapped[str] = mapped_column(
        String(24),
        nullable=False,
        server_default=text("'quarantined'"),
    )

    transitioned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    __table_args__ = (
        ForeignKeyConstraint(
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
        UniqueConstraint(
            "organization_id",
            "provider_code",
            "event_id",
            name="uq_webhook_quarantine_audit_event",
        ),
        CheckConstraint(
            "provider_code = 'sandbox_sim'",
            name="sandbox_only",
        ),
        CheckConstraint(
            "reason_code IN ("
            "'unlinked_payment', "
            "'refund_linkage_unavailable'"
            ")",
            name="reason_valid",
        ),
        CheckConstraint(
            "processor_identity ~ "
            "'^[a-z][a-z0-9_.:-]{2,127}$'",
            name="processor_identity_valid",
        ),
        CheckConstraint(
            "from_status = 'received' "
            "AND to_status = 'quarantined'",
            name="transition_valid",
        ),
        Index(
            "ix_webhook_quarantine_audit_org_time",
            "organization_id",
            "transitioned_at",
        ),
    )
