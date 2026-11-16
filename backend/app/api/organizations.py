import uuid

from fastapi import (
    APIRouter,
    Cookie,
    Depends,
    HTTPException,
    status,
)
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.dependencies import get_db
from app.core.config import get_settings
from app.models import User
from app.services.organization_access import (
    get_accessible_organization,
    list_accessible_organizations,
)
from app.services.session_identity import (
    get_authenticated_user,
)
from app.services.organization_rbac import (
    OrganizationUnavailable,
    PermissionDenied,
    permissions_for_role,
    require_organization_permission,
)


router = APIRouter(
    prefix="/api/v1/organizations",
    tags=["Organizations"],
)


class OrganizationSummary(BaseModel):
    id: uuid.UUID
    name: str
    slug: str
    status: str
    role: str


class OrganizationDetail(OrganizationSummary):
    business_name: str | None
    onboarding_status: str


def require_user(
    db: Session = Depends(get_db),
    session_token: str | None = Cookie(
        default=None,
        alias="payflow_session",
    ),
) -> User:
    if get_settings().app_env != "development":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Organization API is not enabled",
        )

    user = get_authenticated_user(db, session_token)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    return user


@router.get(
    "",
    response_model=list[OrganizationSummary],
)
def list_organizations(
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    records = list_accessible_organizations(
        db, user.id
    )

    return [
        OrganizationSummary(
            id=organization.id,
            name=organization.name,
            slug=organization.slug,
            status=organization.status,
            role=role,
        )
        for organization, role in records
    ]


@router.get(
    "/{organization_id}",
    response_model=OrganizationDetail,
)
def get_organization(
    organization_id: uuid.UUID,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    result = get_accessible_organization(
        db,
        user.id,
        organization_id,
    )

    # Return the same error for nonexistent and unauthorized IDs.
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )

    organization, role, merchant_profile = result

    return OrganizationDetail(
        id=organization.id,
        name=organization.name,
        slug=organization.slug,
        status=organization.status,
        role=role,
        business_name=merchant_profile.business_name,
        onboarding_status=merchant_profile.onboarding_status,
    )


class OrganizationPermissionsResponse(BaseModel):
    organization_id: uuid.UUID
    role: str
    permissions: list[str]


class TeamMemberResponse(BaseModel):
    user_id: uuid.UUID
    email: str
    display_name: str | None
    role: str
    status: str


def authorize_organization_action(
    db: Session,
    user_id: uuid.UUID,
    organization_id: uuid.UUID,
    permission: str,
) -> str:
    try:
        return require_organization_permission(
            db,
            user_id,
            organization_id,
            permission,
        )
    except OrganizationUnavailable:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        ) from None
    except PermissionDenied:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions",
        ) from None


@router.get(
    "/{organization_id}/permissions",
    response_model=OrganizationPermissionsResponse,
)
def get_organization_permissions(
    organization_id: uuid.UUID,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    role = authorize_organization_action(
        db,
        user.id,
        organization_id,
        "organizations.read",
    )

    return OrganizationPermissionsResponse(
        organization_id=organization_id,
        role=role,
        permissions=sorted(permissions_for_role(role)),
    )


@router.get(
    "/{organization_id}/members",
    response_model=list[TeamMemberResponse],
)
def list_organization_members(
    organization_id: uuid.UUID,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    # Team information is restricted to owners and admins.
    authorize_organization_action(
        db,
        user.id,
        organization_id,
        "members.read",
    )

    from sqlalchemy import select
    from app.models import OrganizationMembership

    rows = db.execute(
        select(
            User.id,
            User.email,
            User.display_name,
            OrganizationMembership.role,
            OrganizationMembership.status,
        )
        .join(
            OrganizationMembership,
            OrganizationMembership.user_id == User.id,
        )
        .where(
            OrganizationMembership.organization_id
            == organization_id,
            OrganizationMembership.status.in_(
                ("active", "invited")
            ),
        )
        .order_by(User.email)
    ).all()

    return [
        TeamMemberResponse(
            user_id=row.id,
            email=row.email,
            display_name=row.display_name,
            role=row.role,
            status=row.status,
        )
        for row in rows
    ]
