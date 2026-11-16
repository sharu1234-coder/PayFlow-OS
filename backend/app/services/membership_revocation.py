import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    AuditEvent,
    Organization,
    OrganizationMembership,
)
from app.services.membership_management import (
    TeamMemberUnavailable,
)
from app.services.organization_rbac import (
    OrganizationUnavailable,
    PermissionDenied,
    permissions_for_role,
)


def revoke_organization_member(
    db: Session,
    *,
    organization_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    target_user_id: uuid.UUID,
) -> None:
    # Lock the organization to serialize revocation operations.
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

    # The actor must be an active member of this organization.
    actor = db.scalar(
        select(OrganizationMembership)
        .where(
            OrganizationMembership.organization_id
            == organization_id,
            OrganizationMembership.user_id
            == actor_user_id,
            OrganizationMembership.status == "active",
        )
        .with_for_update()
    )

    if actor is None:
        raise OrganizationUnavailable()

    if "members.manage" not in permissions_for_role(actor.role):
        raise PermissionDenied()

    # Prevent accidental self-removal.
    if actor_user_id == target_user_id:
        raise PermissionDenied()

    target = db.scalar(
        select(OrganizationMembership)
        .where(
            OrganizationMembership.organization_id
            == organization_id,
            OrganizationMembership.user_id
            == target_user_id,
        )
        .with_for_update()
    )

    if target is None or target.status != "active":
        raise TeamMemberUnavailable()

    # No owner can be removed through this endpoint.
    # Ownership transfer requires a separate secure process.
    if target.role == "owner":
        raise PermissionDenied()

    # Admins cannot remove other admins.
    if actor.role == "admin" and target.role == "admin":
        raise PermissionDenied()

    previous_status = target.status
    previous_role = target.role

    target.status = "revoked"

    db.add(
        AuditEvent(
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="organization.member_revoked",
            subject_type="organization_membership",
            subject_id=str(target.id),
            payload={
                "target_user_id": str(target_user_id),
                "previous_role": previous_role,
                "previous_status": previous_status,
                "new_status": "revoked",
            },
        )
    )

    db.flush()
