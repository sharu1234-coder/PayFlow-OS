import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.database import engine
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
    ExistingPendingInvitation,
    InvalidInvitationEmail,
    InvalidInvitationRole,
    issue_organization_invitation,
)
from app.services.organization_rbac import (
    OrganizationUnavailable,
    PermissionDenied,
)


def new_session(connection):
    return Session(
        bind=connection,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    )


@pytest.fixture
def sandbox():
    with engine.connect() as connection:
        outer = connection.begin()

        try:
            with new_session(connection) as db:
                with db.begin():
                    owner = User(
                        email=(
                            f"invite-owner-{uuid.uuid4().hex}"
                            "@example.com"
                        ),
                        password_hash="unused-test-password-hash",
                        display_name="Invitation Owner",
                        email_verified_at=datetime.now(timezone.utc),
                    )

                    manager = User(
                        email=(
                            f"invite-manager-{uuid.uuid4().hex}"
                            "@example.com"
                        ),
                        password_hash="unused-test-password-hash",
                        display_name="Invitation Manager",
                        email_verified_at=datetime.now(timezone.utc),
                    )

                    existing = User(
                        email=(
                            f"existing-{uuid.uuid4().hex}"
                            "@example.com"
                        ),
                        password_hash="unused-test-password-hash",
                        display_name="Existing Member",
                        email_verified_at=datetime.now(timezone.utc),
                    )

                    outsider = User(
                        email=(
                            f"outsider-{uuid.uuid4().hex}"
                            "@example.com"
                        ),
                        password_hash="unused-test-password-hash",
                        display_name="Outside Owner",
                        email_verified_at=datetime.now(timezone.utc),
                    )

                    db.add_all([
                        owner,
                        manager,
                        existing,
                        outsider,
                    ])
                    db.flush()

                    own = Organization(
                        name="Invitation Merchant Alpha",
                        slug=(
                            "invitation-alpha-"
                            + uuid.uuid4().hex[:16]
                        ),
                    )

                    other = Organization(
                        name="Invitation Merchant Beta",
                        slug=(
                            "invitation-beta-"
                            + uuid.uuid4().hex[:16]
                        ),
                    )

                    db.add_all([own, other])
                    db.flush()

                    db.add_all([
                        OrganizationMembership(
                            organization_id=own.id,
                            user_id=owner.id,
                            role="owner",
                            status="active",
                        ),
                        OrganizationMembership(
                            organization_id=own.id,
                            user_id=manager.id,
                            role="viewer",
                            status="active",
                        ),
                        OrganizationMembership(
                            organization_id=own.id,
                            user_id=existing.id,
                            role="finance",
                            status="active",
                        ),
                        OrganizationMembership(
                            organization_id=other.id,
                            user_id=outsider.id,
                            role="owner",
                            status="active",
                        ),
                    ])

                    values = {
                        "connection": connection,
                        "owner_id": owner.id,
                        "manager_id": manager.id,
                        "existing_id": existing.id,
                        "existing_email": existing.email,
                        "own_id": own.id,
                        "other_id": other.id,
                    }

            yield values

        finally:
            if outer.is_active:
                outer.rollback()


def issue(
    s,
    *,
    email=None,
    role="viewer",
    actor_id=None,
    organization_id=None,
):
    with new_session(s["connection"]) as db:
        with db.begin():
            return issue_organization_invitation(
                db,
                organization_id=organization_id or s["own_id"],
                invited_by_user_id=actor_id or s["owner_id"],
                email=email or (
                    f"new-{uuid.uuid4().hex}@example.com"
                ),
                role=role,
            )


def change_membership(
    s,
    user_id,
    *,
    role=None,
    status=None,
):
    with new_session(s["connection"]) as db:
        with db.begin():
            membership = db.scalar(
                select(OrganizationMembership).where(
                    OrganizationMembership.organization_id
                    == s["own_id"],
                    OrganizationMembership.user_id
                    == user_id,
                )
            )

            assert membership is not None

            if role is not None:
                membership.role = role

            if status is not None:
                membership.status = status


def change_user(s, user_id, *, active=None, verified=None):
    with new_session(s["connection"]) as db:
        with db.begin():
            user = db.get(User, user_id)
            assert user is not None

            if active is not None:
                user.is_active = active

            if verified is False:
                user.email_verified_at = None


def audit_count(s):
    with new_session(s["connection"]) as db:
        return db.scalar(
            select(func.count(AuditEvent.id)).where(
                AuditEvent.organization_id == s["own_id"],
                AuditEvent.action
                == "organization.invitation_issued",
            )
        )


def test_owner_issues_hashed_email_bound_invitation(sandbox):
    email = f"NEW-{uuid.uuid4().hex}@EXAMPLE.COM"

    result = issue(
        sandbox,
        email="  " + email + "  ",
        role="finance",
    )

    assert result.email == email.lower()
    assert result.role == "finance"
    assert len(result.raw_token) >= 32
    assert result.raw_token not in repr(result)

    with new_session(sandbox["connection"]) as db:
        record = db.get(
            OrganizationInvitation,
            result.invitation_id,
        )

        assert record is not None
        assert record.email == email.lower()
        assert record.role == "finance"
        assert record.token_hash == hash_secure_token(
            result.raw_token
        )
        assert record.token_hash != result.raw_token
        assert record.accepted_at is None
        assert record.revoked_at is None

    assert audit_count(sandbox) == 1


def test_owner_can_invite_admin(sandbox):
    result = issue(sandbox, role="admin")

    assert result.role == "admin"


def test_admin_can_invite_viewer(sandbox):
    change_membership(
        sandbox,
        sandbox["manager_id"],
        role="admin",
    )

    result = issue(
        sandbox,
        actor_id=sandbox["manager_id"],
        role="viewer",
    )

    assert result.role == "viewer"


def test_admin_cannot_invite_admin(sandbox):
    change_membership(
        sandbox,
        sandbox["manager_id"],
        role="admin",
    )

    with pytest.raises(PermissionDenied):
        issue(
            sandbox,
            actor_id=sandbox["manager_id"],
            role="admin",
        )


def test_viewer_cannot_issue_invitations(sandbox):
    with pytest.raises(PermissionDenied):
        issue(
            sandbox,
            actor_id=sandbox["manager_id"],
        )


def test_revoked_actor_cannot_issue_invitations(sandbox):
    change_membership(
        sandbox,
        sandbox["owner_id"],
        status="revoked",
    )

    with pytest.raises(OrganizationUnavailable):
        issue(sandbox)


def test_unverified_actor_cannot_issue_invitations(sandbox):
    change_user(
        sandbox,
        sandbox["owner_id"],
        verified=False,
    )

    with pytest.raises(PermissionDenied):
        issue(sandbox)


def test_inactive_actor_cannot_issue_invitations(sandbox):
    change_user(
        sandbox,
        sandbox["owner_id"],
        active=False,
    )

    with pytest.raises(PermissionDenied):
        issue(sandbox)


def test_cross_merchant_invitation_is_denied(sandbox):
    with pytest.raises(OrganizationUnavailable):
        issue(
            sandbox,
            organization_id=sandbox["other_id"],
        )


def test_suspended_organization_is_denied(sandbox):
    with new_session(sandbox["connection"]) as db:
        with db.begin():
            db.get(
                Organization,
                sandbox["own_id"],
            ).status = "suspended"

    with pytest.raises(OrganizationUnavailable):
        issue(sandbox)


def test_existing_member_cannot_be_invited(sandbox):
    with pytest.raises(ExistingOrganizationMember):
        issue(
            sandbox,
            email=sandbox["existing_email"],
        )


def test_duplicate_pending_invitation_is_rejected(sandbox):
    email = f"duplicate-{uuid.uuid4().hex}@example.com"

    first = issue(sandbox, email=email)

    with pytest.raises(ExistingPendingInvitation):
        issue(sandbox, email=email)

    with new_session(sandbox["connection"]) as db:
        records = db.scalars(
            select(OrganizationInvitation)
            .where(
                OrganizationInvitation.organization_id
                == sandbox["own_id"],
                OrganizationInvitation.email == email,
            )
        ).all()

        assert len(records) == 1
        assert records[0].id == first.invitation_id

    assert audit_count(sandbox) == 1


def test_expired_pending_invitation_can_be_reissued(sandbox):
    email = f"expired-{uuid.uuid4().hex}@example.com"

    first = issue(sandbox, email=email)

    # Preserve the database check constraint:
    # expires_at must remain after created_at.
    with new_session(sandbox["connection"]) as db:
        with db.begin():
            old = db.get(
                OrganizationInvitation,
                first.invitation_id,
            )

            old.created_at = (
                datetime.now(timezone.utc) - timedelta(days=10)
            )
            old.expires_at = (
                datetime.now(timezone.utc) - timedelta(days=1)
            )

    second = issue(sandbox, email=email)

    assert second.invitation_id != first.invitation_id
    assert second.raw_token != first.raw_token

    with new_session(sandbox["connection"]) as db:
        old = db.get(
            OrganizationInvitation,
            first.invitation_id,
        )

        new = db.get(
            OrganizationInvitation,
            second.invitation_id,
        )

        assert old.revoked_at is not None
        assert new.revoked_at is None
        assert new.accepted_at is None

    assert audit_count(sandbox) == 2


def test_revoked_former_member_can_be_invited(sandbox):
    change_membership(
        sandbox,
        sandbox["existing_id"],
        status="revoked",
    )

    result = issue(
        sandbox,
        email=sandbox["existing_email"],
    )

    assert result.email == sandbox["existing_email"]


def test_owner_role_cannot_be_invited(sandbox):
    with pytest.raises(InvalidInvitationRole):
        issue(sandbox, role="owner")


@pytest.mark.parametrize(
    "email",
    [
        "not-an-email",
        "invalid@",
        " ",
    ],
)
def test_invalid_invitation_email_is_rejected(sandbox, email):
    with pytest.raises(InvalidInvitationEmail):
        issue(sandbox, email=email)

    assert audit_count(sandbox) == 0


def test_audit_event_never_contains_raw_secret(sandbox):
    result = issue(sandbox)

    with new_session(sandbox["connection"]) as db:
        event = db.scalar(
            select(AuditEvent)
            .where(
                AuditEvent.action
                == "organization.invitation_issued",
                AuditEvent.subject_id
                == str(result.invitation_id),
            )
        )

        assert event is not None
        assert event.payload["role"] == "viewer"
        assert result.raw_token not in str(event.payload)
        assert "raw_token" not in event.payload
        assert "token_hash" not in event.payload
