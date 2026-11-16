import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from pydantic import EmailStr, TypeAdapter, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import (
    generate_secure_token,
    hash_secure_token,
)
from app.models import (
    AuditEvent,
    Organization,
    OrganizationInvitation,
    OrganizationMembership,
    User,
)
from app.services.organization_rbac import (
    OrganizationUnavailable,
    PermissionDenied,
    permissions_for_role,
)


INVITATION_LIFETIME = timedelta(days=7)

INVITABLE_ROLES = frozenset({
    "admin",
    "developer",
    "finance",
    "viewer",
})

_email_adapter = TypeAdapter(EmailStr)


class InvalidInvitationEmail(Exception):
    pass


class InvalidInvitationRole(Exception):
    pass


class ExistingOrganizationMember(Exception):
    pass


class ExistingPendingInvitation(Exception):
    pass


@dataclass(frozen=True)
class IssuedInvitation:
    invitation_id: uuid.UUID
    organization_id: uuid.UUID
    email: str
    role: str
    expires_at: datetime

    # Keep the raw token out of object repr and log output.
    raw_token: str = field(repr=False)


def normalize_invitation_email(value: str) -> str:
    if not isinstance(value, str):
        raise InvalidInvitationEmail()

    try:
        normalized = str(
            _email_adapter.validate_python(value.strip())
        ).lower()

    except ValidationError:
        raise InvalidInvitationEmail() from None

    if len(normalized) > 320:
        raise InvalidInvitationEmail()

    return normalized


def issue_organization_invitation(
    db: Session,
    *,
    organization_id: uuid.UUID,
    invited_by_user_id: uuid.UUID,
    email: str,
    role: str,
) -> IssuedInvitation:
    """
    Issue an invitation within the caller's transaction.

    IMPORTANT:
    - The caller owns commit/rollback.
    - No email is delivered here.
    - Never expose raw_token through a public API.
    - Acceptance must also lock the organization first.
    """

    if role not in INVITABLE_ROLES:
        raise InvalidInvitationRole()

    normalized_email = normalize_invitation_email(email)

    now = datetime.now(timezone.utc)

    # Serialize invitation issuance within an organization.
    # Later invitation acceptance must use the same lock order.
    organization = db.scalar(
        select(Organization)
        .where(
            Organization.id == organization_id,
            Organization.status == "active",
        )
        .with_for_update()
    )

    if organization is None:
        raise OrganizationUnavailable()

    actor = db.scalar(
        select(OrganizationMembership)
        .where(
            OrganizationMembership.organization_id
            == organization_id,
            OrganizationMembership.user_id
            == invited_by_user_id,
            OrganizationMembership.status == "active",
        )
        .with_for_update()
    )

    if actor is None:
        raise OrganizationUnavailable()

    actor_user = db.scalar(
        select(User)
        .where(
            User.id == invited_by_user_id,
            User.is_active.is_(True),
            User.email_verified_at.is_not(None),
        )
    )

    if actor_user is None:
        raise PermissionDenied()

    if "members.manage" not in permissions_for_role(
        actor.role
    ):
        raise PermissionDenied()

    # Admins cannot issue admin invitations.
    # Only owners can invite another administrator.
    if actor.role == "admin" and role == "admin":
        raise PermissionDenied()

    # Do not invite someone who already has an active
    # or invited membership in this organization.
    existing_member = db.scalar(
        select(OrganizationMembership.id)
        .join(
            User,
            User.id == OrganizationMembership.user_id,
        )
        .where(
            OrganizationMembership.organization_id
            == organization_id,
            User.email == normalized_email,
            OrganizationMembership.status.in_(
                ("active", "invited")
            ),
        )
        .limit(1)
    )

    if existing_member is not None:
        raise ExistingOrganizationMember()

    # The partial unique database index permits only
    # one unaccepted and unrevoked invitation per
    # organization/email.
    pending = db.scalar(
        select(OrganizationInvitation)
        .where(
            OrganizationInvitation.organization_id
            == organization_id,
            OrganizationInvitation.email
            == normalized_email,
            OrganizationInvitation.accepted_at.is_(None),
            OrganizationInvitation.revoked_at.is_(None),
        )
        .with_for_update()
    )

    if pending is not None:
        if pending.expires_at > now:
            raise ExistingPendingInvitation()

        # Expired invitations must be explicitly revoked
        # before inserting a new invitation, because the
        # partial unique index does not check expiry.
        pending.revoked_at = now
        db.flush()

    raw_token = generate_secure_token()
    expires_at = now + INVITATION_LIFETIME

    invitation = OrganizationInvitation(
        organization_id=organization_id,
        invited_by_user_id=invited_by_user_id,
        email=normalized_email,
        role=role,
        token_hash=hash_secure_token(raw_token),
        expires_at=expires_at,
    )

    db.add(invitation)
    db.flush()

    # Never store invitation secrets in the audit trail.
    db.add(
        AuditEvent(
            organization_id=organization_id,
            actor_user_id=invited_by_user_id,
            action="organization.invitation_issued",
            subject_type="organization_invitation",
            subject_id=str(invitation.id),
            payload={
                "role": role,
                "expires_at": expires_at.isoformat(),
            },
        )
    )

    db.flush()

    return IssuedInvitation(
        invitation_id=invitation.id,
        organization_id=organization_id,
        email=normalized_email,
        role=role,
        expires_at=expires_at,
        raw_token=raw_token,
    )
