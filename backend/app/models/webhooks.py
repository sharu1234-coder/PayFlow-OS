"""Tenant-scoped verified provider event inbox schema.

This is a persistence model only.

Verification happens before storage. This table intentionally
does not contain a raw webhook body, signing credentials,
customer card details, or gateway response secrets.

No event handler, financial state mutation, or live integration.
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.model_base import Base


class VerifiedProviderEvent(Base):
    __tablename__ = "provider_event_inbox"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "payflow.organizations.id",
            ondelete="RESTRICT",
        ),
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

    event_type: Mapped[str] = mapped_column(
        String(48),
        nullable=False,
    )

    provider_object_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )

    occurred_at: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
    )

    signed_at: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
    )

    payload_sha256: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(24),
        nullable=False,
        server_default=text("'received'"),
    )

    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    processed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "provider_code",
            "event_id",
            name="uq_provider_event_inbox_identity",
        ),
        CheckConstraint(
            "provider_code = 'sandbox_sim'",
            name="sandbox_only",
        ),
        CheckConstraint(
            "event_id ~ "
            "'^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'",
            name="event_id_format",
        ),
        CheckConstraint(
            "event_type IN ("
            "'payment.processing', "
            "'payment.succeeded', "
            "'payment.failed', "
            "'refund.pending', "
            "'refund.succeeded', "
            "'refund.failed'"
            ")",
            name="event_type_valid",
        ),
        CheckConstraint(
            "provider_object_id ~ "
            "'^sim_(pay|ref)_[0-9a-f]{32}$'",
            name="object_id_format",
        ),
        CheckConstraint(
            "("
            "event_type LIKE 'payment.%' "
            "AND provider_object_id LIKE 'sim_pay_%'"
            ") OR ("
            "event_type LIKE 'refund.%' "
            "AND provider_object_id LIKE 'sim_ref_%'"
            ")",
            name="object_kind_match",
        ),
        CheckConstraint(
            "occurred_at > 0 "
            "AND signed_at > 0 "
            "AND signed_at < 1000000000000 "
            "AND occurred_at <= signed_at + 30",
            name="timestamps_valid",
        ),
        CheckConstraint(
            "payload_sha256 ~ '^[0-9a-f]{64}$'",
            name="payload_hash_format",
        ),
        CheckConstraint(
            "status IN ('received', 'processed', 'quarantined')",
            name="status_valid",
        ),
        CheckConstraint(
            "("
            "status = 'received' AND processed_at IS NULL"
            ") OR ("
            "status IN ('processed', 'quarantined') "
            "AND processed_at IS NOT NULL"
            ")",
            name="status_timestamp_match",
        ),
        Index(
            "ix_provider_event_inbox_org_status_received",
            "organization_id",
            "status",
            "received_at",
        ),
        Index(
            "ix_provider_event_inbox_org_object",
            "organization_id",
            "provider_code",
            "provider_object_id",
        ),
    )
