import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.model_base import Base


def uuid_column():
    return mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )


def created_column():
    return mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = uuid_column()
    email: Mapped[str] = mapped_column(
        String(320), nullable=False, unique=True
    )
    password_hash: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    display_name: Mapped[str | None] = mapped_column(
        String(160)
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("true")
    )
    email_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = created_column()

    __table_args__ = (
        CheckConstraint(
            "email = lower(email)",
            name="email_lowercase",
        ),
    )


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = uuid_column()
    name: Mapped[str] = mapped_column(
        String(200), nullable=False
    )
    slug: Mapped[str] = mapped_column(
        String(80), nullable=False, unique=True
    )
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        server_default=text("'active'"),
    )
    created_at: Mapped[datetime] = created_column()

    __table_args__ = (
        CheckConstraint(
            "slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'",
            name="slug_format",
        ),
        CheckConstraint(
            "status IN ('active', 'suspended', 'closed')",
            name="status_valid",
        ),
    )


class OrganizationMembership(Base):
    __tablename__ = "organization_memberships"

    id: Mapped[uuid.UUID] = uuid_column()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("payflow.organizations.id", ondelete="RESTRICT"),
        nullable=False,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("payflow.users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    role: Mapped[str] = mapped_column(
        String(20), nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        server_default=text("'active'"),
    )
    created_at: Mapped[datetime] = created_column()

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "user_id",
            name="uq_membership_organization_user",
        ),
        CheckConstraint(
            "role IN ('owner', 'admin', 'developer', 'finance', 'viewer')",
            name="role_valid",
        ),
        CheckConstraint(
            "status IN ('invited', 'active', 'revoked')",
            name="status_valid",
        ),
    )


class MerchantProfile(Base):
    __tablename__ = "merchant_profiles"

    id: Mapped[uuid.UUID] = uuid_column()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("payflow.organizations.id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    )
    business_name: Mapped[str | None] = mapped_column(
        String(200)
    )
    onboarding_status: Mapped[str] = mapped_column(
        String(24),
        nullable=False,
        server_default=text("'draft'"),
    )
    created_at: Mapped[datetime] = created_column()

    __table_args__ = (
        CheckConstraint(
            "onboarding_status IN "
            "('draft', 'pending_review', 'approved', 'rejected', 'suspended')",
            name="onboarding_status_valid",
        ),
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = uuid_column()
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("payflow.organizations.id", ondelete="RESTRICT"),
        index=True,
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("payflow.users.id", ondelete="RESTRICT"),
    )
    action: Mapped[str] = mapped_column(
        String(120), nullable=False
    )
    subject_type: Mapped[str] = mapped_column(
        String(80), nullable=False
    )
    subject_id: Mapped[str | None] = mapped_column(
        String(100)
    )
    payload: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        server_default=text("'{}'::jsonb"),
    )
    created_at: Mapped[datetime] = created_column()
