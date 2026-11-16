import uuid
from typing import Literal

from fastapi import (
    APIRouter,
    Cookie,
    Depends,
    Header,
    HTTPException,
    status,
)
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.dependencies import get_db
from app.api.organizations import require_user
from app.models import User
from app.services.membership_management import (
    TeamMemberUnavailable,
    change_member_role,
)
from app.services.organization_rbac import (
    OrganizationUnavailable,
    PermissionDenied,
)
from app.api.csrf_dependencies import require_authenticated_csrf


router = APIRouter(
    prefix="/api/v1/organizations",
    tags=["Team Management"],
)


class ChangeMemberRoleRequest(BaseModel):
    role: Literal["admin", "developer", "finance", "viewer"]


class MemberRoleResponse(BaseModel):
    organization_id: uuid.UUID
    user_id: uuid.UUID
    role: str


@router.patch(
    "/{organization_id}/members/{member_id}/role",
    response_model=MemberRoleResponse,
)
def update_member_role(
    organization_id: uuid.UUID,
    member_id: uuid.UUID,
    payload: ChangeMemberRoleRequest,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
    csrf_verified: None = Depends(
        require_authenticated_csrf
    ),
) -> MemberRoleResponse:
    try:
        new_role = change_member_role(
            db,
            organization_id=organization_id,
            actor_user_id=user.id,
            target_user_id=member_id,
            new_role=payload.role,
        )

        db.commit()

    except OrganizationUnavailable:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        ) from None

    except TeamMemberUnavailable:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Member not found",
        ) from None

    except PermissionDenied:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions",
        ) from None

    except Exception:
        db.rollback()
        raise

    return MemberRoleResponse(
        organization_id=organization_id,
        user_id=member_id,
        role=new_role,
    )
