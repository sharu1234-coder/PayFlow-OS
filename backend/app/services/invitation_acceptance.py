import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import hash_secure_token
from app.models import (
    AuditEvent,
    Organization,
    OrganizationInvitation,
    OrganizationMembership,
    User,
)
from app.services.invitation_issuance import (
    ExistingOrganizationMember,
)
from app.services.organization_rbac import (
    permissions_for_role,
)


class InvalidInvitation(Exception):
    """Generic failure that does not reveal invitation details."""


@dataclass(frozen=True)
class AcceptedInvitation:
    invitation_id: uuid.UUID
    organization_id: uuid.UUID
    user_id: uuid.UUID
    membership_id: uuid.UUID
    role: str


def invitation_digest(raw_token: str) -> str:
    if (
        not isinstance(raw_token, str)
        or len(raw_token) < 32
        or len(raw_token) > 256
    ):
        raise InvalidInvitation()

    return hash_secure_token(raw_token)


def accept_organization_invitation(
    db: Session,
    *,
    raw_token: str,
    accepting_user_id: uuid.UUID,
) -> AcceptedInvitation:
    """
    Accept a valid invitation within the caller's transaction.

    The caller MUST commit or roll back.

    Lock order:
      1. Organization
      2. Invitation
      3. Relevant organization memberships

    No email is sent. No API endpoint is exposed.
    """

    digest = invitation_digest(raw_token)

    # First locate the organization. This read does not
    # lock anything or consume the invitation.
    organization_id = db.scalar(
        select(OrganizationInvitation.organization_id)
        .where(
            OrganizationInvitation.token_hash == digest
        )
    )

    if organization_id is None:
        raise InvalidInvitation()

    # Invitation issuance uses the same organization lock.
    # This serializes conflicting operations on its invitations.
    organization = db.scalar(
        select(Organization)
        .where(
            Organization.id == organization_id,
            Organization.status == "active",
        )
        .with_for_update()
    )

    if organization is None:
        raise InvalidInvitation()

    # Re-read and lock the invitation AFTER the organization.
    # A concurrent operation may have revoked or accepted it.
    invitation = db.scalar(
        select(OrganizationInvitation)
        .where(
            OrganizationInvitation.token_hash == digest,
            OrganizationInvitation.organization_id
            == organization_id,
        )
        .with_for_update()
    )

    now = datetime.now(timezone.utc)

    if (
        invitation is None
        or invitation.accepted_at is not None
        or invitation.revoked_at is not None
        or invitation.expires_at <= now
    ):
        raise InvalidInvitation()

    # The accepting account must belong to the exact
    # verified email address on the invitation.
    user = db.scalar(
        select(User).where(
            User.id == accepting_user_id,
            User.is_active.is_(True),
            User.email_verified_at.is_not(None),
        )
    )

    if (
        user is None
        or user.email.lower() != invitation.email
    ):
        raise InvalidInvitation()

    # Fail closed if the issuer has lost the authority
    # needed to grant the invitation's role.
    inviter = db.scalar(
        select(OrganizationMembership)
        .where(
            OrganizationMembership.organization_id
            == organization_id,
            OrganizationMembership.user_id
            == invitation.invited_by_user_id,
            OrganizationMembership.status == "active",
        )
        .with_for_update()
    )

    if (
        inviter is None
        or "members.manage"
        not in permissions_for_role(inviter.role)
    ):
        raise InvalidInvitation()

    if (
        invitation.role == "admin"
        and inviter.role != "owner"
    ):
        raise InvalidInvitation()

    existing = db.scalar(
        select(OrganizationMembership)
        .where(
            OrganizationMembership.organization_id
            == organization_id,
            OrganizationMembership.user_id
            == accepting_user_id,
        )
        .with_for_update()
    )

    if existing is not None:
        # Previously revoked users can be explicitly
        # reinvited. Active or invited memberships cannot
        # be overwritten through token acceptance.
        if existing.status != "revoked":
            raise ExistingOrganizationMember()

        existing.role = invitation.role
        existing.status = "active"
        membership = existing

    else:
        membership = OrganizationMembership(
            organization_id=organization_id,
            user_id=accepting_user_id,
            role=invitation.role,
            status="active",
        )

        db.add(membership)

    db.flush()

    # Consume the invitation in the same transaction
    # as the membership change.
    invitation.accepted_at = now
    invitation.accepted_user_id = accepting_user_id

    db.add(
        AuditEvent(
            organization_id=organization_id,
            actor_user_id=accepting_user_id,
            action="organization.invitation_accepted",
            subject_type="organization_invitation",
            subject_id=str(invitation.id),
            payload={
                "role": invitation.role,
                "membership_id": str(membership.id),
            },
        )
    )

    db.flush()

    return AcceptedInvitation(
        invitation_id=invitation.id,
        organization_id=organization_id,
        user_id=accepting_user_id,
        membership_id=membership.id,
        role=invitation.role,
    )
