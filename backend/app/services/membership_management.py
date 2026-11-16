import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    AuditEvent,
    Organization,
    OrganizationMembership,
)
from app.services.organization_rbac import (
    OrganizationUnavailable,
    PermissionDenied,
    permissions_for_role,
)


class TeamMemberUnavailable(Exception):
    pass


def change_member_role(
    db: Session,
    *,
    organization_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    target_user_id: uuid.UUID,
    new_role: str,
) -> str:
    if new_role not in {
        "admin", "developer", "finance", "viewer"
    }:
        raise ValueError("Unsupported membership role")

    # Lock the acting membership and verify organization status.
    # This prevents a role that has already been revoked from
    # authorizing a new change.
    actor = db.scalar(
        select(OrganizationMembership)
        .join(
            Organization,
            Organization.id
            == OrganizationMembership.organization_id,
        )
        .where(
            Organization.id == organization_id,
            Organization.status == "active",
            OrganizationMembership.user_id == actor_user_id,
            OrganizationMembership.status == "active",
        )
        .with_for_update(of=OrganizationMembership)
    )

    if actor is None:
        raise OrganizationUnavailable()

    if "members.manage" not in permissions_for_role(actor.role):
        raise PermissionDenied()

    target = db.scalar(
        select(OrganizationMembership)
        .where(
            OrganizationMembership.organization_id
            == organization_id,
            OrganizationMembership.user_id == target_user_id,
        )
        .with_for_update()
    )

    if target is None or target.status != "active":
        raise TeamMemberUnavailable()

    # Owner changes require a separate ownership-transfer flow.
    if target.role == "owner":
        raise PermissionDenied()

    # An admin cannot grant admin or modify another admin.
    if actor.role == "admin":
        if target.role == "admin" or new_role == "admin":
            raise PermissionDenied()

    previous_role = target.role

    if previous_role != new_role:
        target.role = new_role

        db.add(
            AuditEvent(
                organization_id=organization_id,
                actor_user_id=actor_user_id,
                action="organization.member_role_changed",
                subject_type="organization_membership",
                subject_id=str(target.id),
                payload={
                    "target_user_id": str(target_user_id),
                    "previous_role": previous_role,
                    "new_role": new_role,
                },
            )
        )

    db.flush()
    return target.role
