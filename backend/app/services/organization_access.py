import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    MerchantProfile,
    Organization,
    OrganizationMembership,
)


def list_accessible_organizations(
    db: Session,
    user_id: uuid.UUID,
):
    statement = (
        select(
            Organization,
            OrganizationMembership.role,
        )
        .join(
            OrganizationMembership,
            OrganizationMembership.organization_id
            == Organization.id,
        )
        .where(
            OrganizationMembership.user_id == user_id,
            OrganizationMembership.status == "active",
            Organization.status == "active",
        )
        .order_by(Organization.name, Organization.id)
    )

    return db.execute(statement).all()


def get_accessible_organization(
    db: Session,
    user_id: uuid.UUID,
    organization_id: uuid.UUID,
):
    # Authorization is enforced inside the database query.
    # Never fetch an organization by ID alone and assume
    # that knowing its identifier grants access.
    statement = (
        select(
            Organization,
            OrganizationMembership.role,
            MerchantProfile,
        )
        .join(
            OrganizationMembership,
            OrganizationMembership.organization_id
            == Organization.id,
        )
        .join(
            MerchantProfile,
            MerchantProfile.organization_id
            == Organization.id,
        )
        .where(
            Organization.id == organization_id,
            OrganizationMembership.user_id == user_id,
            OrganizationMembership.status == "active",
            Organization.status == "active",
        )
    )

    return db.execute(statement).one_or_none()
