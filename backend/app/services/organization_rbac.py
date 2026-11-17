import uuid
from types import MappingProxyType

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    Organization,
    OrganizationMembership,
)


ALL_PERMISSIONS = frozenset({
    "organizations.read",
    "organizations.manage",
    "members.read",
    "members.manage",
    "credentials.manage",
    "payments.read",
    "payments.create",
    "refunds.request",
    "reports.read",
    "billing.manage",
})


ROLE_PERMISSIONS = MappingProxyType({
    "owner": ALL_PERMISSIONS,

    "admin": ALL_PERMISSIONS - {
        "billing.manage",
    },

    "developer": frozenset({
        "organizations.read",
        "credentials.manage",
        "payments.read",
        "reports.read",
    }),

    "finance": frozenset({
        "organizations.read",
        "payments.read",
        "refunds.request",
        "reports.read",
        "billing.manage",
    }),

    "viewer": frozenset({
        "organizations.read",
        "payments.read",
        "reports.read",
    }),
})


class OrganizationUnavailable(Exception):
    pass


class PermissionDenied(Exception):
    pass


def permissions_for_role(role: str) -> frozenset[str]:
    # Unrecognized roles never gain permissions.
    return ROLE_PERMISSIONS.get(role, frozenset())


def require_organization_permission(
    db: Session,
    user_id: uuid.UUID,
    organization_id: uuid.UUID,
    permission: str,
) -> str:
    if permission not in ALL_PERMISSIONS:
        raise ValueError(
            f"Unrecognized application permission: {permission}"
        )

    # The organization AND active membership must match
    # in the same database query.
    role = db.scalar(
        select(OrganizationMembership.role)
        .join(
            Organization,
            Organization.id
            == OrganizationMembership.organization_id,
        )
        .where(
            Organization.id == organization_id,
            Organization.status == "active",
            OrganizationMembership.user_id == user_id,
            OrganizationMembership.status == "active",
        )
    )

    if role is None:
        # Do not reveal whether the organization exists.
        raise OrganizationUnavailable()

    if permission not in permissions_for_role(role):
        raise PermissionDenied()

    return role
