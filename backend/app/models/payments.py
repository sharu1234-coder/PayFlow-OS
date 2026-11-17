"""PayFlow payment persistence models.

Schema definitions only. No payment processing, network
operations, transaction orchestration or database migration.
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.model_base import Base


class PaymentOrder(Base):
    __tablename__ = "payment_orders"

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

    merchant_order_reference: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )

    amount_minor_units: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
    )

    currency: Mapped[str] = mapped_column(
        String(3),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(24),
        nullable=False,
        server_default=text("'open'"),
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "merchant_order_reference",
            name="uq_payment_orders_tenant_reference",
        ),
        UniqueConstraint(
            "organization_id",
            "id",
            "amount_minor_units",
            "currency",
            name="uq_payment_orders_tenant_amount_identity",
        ),
        CheckConstraint(
            "amount_minor_units > 0",
            name="amount_positive",
        ),
        CheckConstraint(
            "currency ~ '^[A-Z]{3}$'",
            name="currency_format",
        ),
        CheckConstraint(
            "merchant_order_reference ~ "
            "'^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'",
            name="reference_format",
        ),
        CheckConstraint(
            "status IN ('open', 'paid', 'cancelled')",
            name="status_valid",
        ),
        Index(
            "ix_payment_orders_org_created_at",
            "organization_id",
            "created_at",
        ),
    )


class PaymentAttempt(Base):
    __tablename__ = "payment_attempts"

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

    order_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
    )

    attempt_number: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    amount_minor_units: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
    )

    currency: Mapped[str] = mapped_column(
        String(3),
        nullable=False,
    )

    provider_code: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    provider_payment_id: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
    )

    status: Mapped[str] = mapped_column(
        String(24),
        nullable=False,
        server_default=text("'created'"),
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    __table_args__ = (
        ForeignKeyConstraint(
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
            name="fk_payment_attempts_tenant_order_amount",
            ondelete="RESTRICT",
        ),
        UniqueConstraint(
            "organization_id",
            "order_id",
            "attempt_number",
            name="uq_payment_attempts_order_number",
        ),
        UniqueConstraint(
            "organization_id",
            "provider_code",
            "provider_payment_id",
            name="uq_payment_attempts_provider_payment",
        ),
        CheckConstraint(
            "attempt_number > 0",
            name="attempt_number_positive",
        ),
        CheckConstraint(
            "amount_minor_units > 0",
            name="amount_positive",
        ),
        CheckConstraint(
            "currency ~ '^[A-Z]{3}$'",
            name="currency_format",
        ),
        CheckConstraint(
            "provider_code ~ '^[a-z][a-z0-9_]{1,31}$'",
            name="provider_code_format",
        ),
        CheckConstraint(
            "provider_payment_id IS NULL OR "
            "length(provider_payment_id) > 0",
            name="provider_payment_id_nonempty",
        ),
        CheckConstraint(
            "status IN ("
            "'created', 'requires_action', 'processing', "
            "'authorized', 'succeeded', 'failed', 'cancelled'"
            ")",
            name="status_valid",
        ),
        Index(
            "ix_payment_attempts_org_order_status",
            "organization_id",
            "order_id",
            "status",
        ),
    )


class PaymentIdempotencyRecord(Base):
    __tablename__ = "payment_idempotency_records"

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

    operation: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    idempotency_key: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )

    request_fingerprint: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        server_default=text("'reserved'"),
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "operation",
            "idempotency_key",
            name="uq_payment_idempotency_tenant_operation_key",
        ),
        CheckConstraint(
            "operation IN ('create_payment', 'create_refund')",
            name="operation_valid",
        ),
        CheckConstraint(
            "idempotency_key ~ '^[A-Za-z0-9_-]{10,128}$'",
            name="key_format",
        ),
        CheckConstraint(
            "request_fingerprint ~ '^[0-9a-f]{64}$'",
            name="fingerprint_format",
        ),
        CheckConstraint(
            "status IN ("
            "'reserved', 'completed', "
            "'requires_reconciliation', 'failed'"
            ")",
            name="status_valid",
        ),
        Index(
            "ix_payment_idempotency_org_created_at",
            "organization_id",
            "created_at",
        ),
    )
