import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.model_base import Base
from app.models.identity import created_column, uuid_column


class OrganizationInvitation(Base):
    __tablename__ = "organization_invitations"

    id: Mapped[uuid.UUID] = uuid_column()

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "payflow.organizations.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
        index=True,
    )

    invited_by_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "payflow.users.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
        index=True,
    )

    email: Mapped[str] = mapped_column(
        String(320),
        nullable=False,
    )

    role: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    # Never store or return the raw invitation secret.
    token_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
    )

    created_at: Mapped[datetime] = created_column()

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    accepted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    accepted_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "payflow.users.id",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )

    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    __table_args__ = (
        CheckConstraint(
            "email = lower(email)",
            name="email_lowercase",
        ),
        CheckConstraint(
            "role IN ('admin', 'developer', 'finance', 'viewer')",
            name="role_valid",
        ),
        CheckConstraint(
            "length(token_hash) = 64",
            name="token_hash_length",
        ),
        CheckConstraint(
            "expires_at > created_at",
            name="expiry_after_creation",
        ),
        CheckConstraint(
            "(accepted_at IS NULL) = (accepted_user_id IS NULL)",
            name="acceptance_fields_match",
        ),
        CheckConstraint(
            "accepted_at IS NULL OR revoked_at IS NULL",
            name="terminal_states_exclusive",
        ),
        # At most one outstanding invitation per organization/email.
        # Expired invitations must be revoked before reissuing.
        Index(
            "uq_organization_invitations_pending",
            "organization_id",
            "email",
            unique=True,
            postgresql_where=text(
                "accepted_at IS NULL AND revoked_at IS NULL"
            ),
        ),
    )
