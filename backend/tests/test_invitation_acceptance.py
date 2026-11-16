import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.database import engine
from app.models import (
    AuditEvent,
    Organization,
    OrganizationInvitation,
    OrganizationMembership,
    User,
)
from app.services.invitation_acceptance import (
    InvalidInvitation,
    accept_organization_invitation,
)
from app.services.invitation_issuance import (
    ExistingOrganizationMember,
    issue_organization_invitation,
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
                    prefix = uuid.uuid4().hex

                    owner = User(
                        email=f"owner-{prefix}@example.com",
                        password_hash="test-only-hash",
                        display_name="Invitation Owner",
                        email_verified_at=datetime.now(
                            timezone.utc
                        ),
                    )

                    recipient = User(
                        email=f"recipient-{prefix}@example.com",
                        password_hash="test-only-hash",
                        display_name="Invitation Recipient",
                        email_verified_at=datetime.now(
                            timezone.utc
                        ),
                    )

                    wrong_user = User(
                        email=f"different-{prefix}@example.com",
                        password_hash="test-only-hash",
                        display_name="Different User",
                        email_verified_at=datetime.now(
                            timezone.utc
                        ),
                    )

                    unverified = User(
                        email=f"unverified-{prefix}@example.com",
                        password_hash="test-only-hash",
                        display_name="Unverified Recipient",
                    )

                    inactive = User(
                        email=f"inactive-{prefix}@example.com",
                        password_hash="test-only-hash",
                        display_name="Inactive Recipient",
                        is_active=False,
                        email_verified_at=datetime.now(
                            timezone.utc
                        ),
                    )

                    db.add_all([
                        owner,
                        recipient,
                        wrong_user,
                        unverified,
                        inactive,
                    ])
                    db.flush()

                    organization = Organization(
                        name="Invitation Acceptance Test",
                        slug=(
                            "acceptance-"
                            + uuid.uuid4().hex[:16]
                        ),
                    )

                    db.add(organization)
                    db.flush()

                    db.add(
                        OrganizationMembership(
                            organization_id=organization.id,
                            user_id=owner.id,
                            role="owner",
                            status="active",
                        )
                    )

                    values = {
                        "connection": connection,
                        "organization_id": organization.id,
                        "owner_id": owner.id,
                        "recipient_id": recipient.id,
                        "recipient_email": recipient.email,
                        "wrong_user_id": wrong_user.id,
                        "unverified_id": unverified.id,
                        "unverified_email": unverified.email,
                        "inactive_id": inactive.id,
                        "inactive_email": inactive.email,
                    }

            yield values

        finally:
            if outer.is_active:
                outer.rollback()


def issue(s, *, email=None, role="viewer"):
    with new_session(s["connection"]) as db:
        with db.begin():
            return issue_organization_invitation(
                db,
                organization_id=s["organization_id"],
                invited_by_user_id=s["owner_id"],
                email=(
                    email
                    if email is not None
                    else s["recipient_email"]
                ),
                role=role,
            )


def accept(s, token, *, user_id=None):
    with new_session(s["connection"]) as db:
        with db.begin():
            return accept_organization_invitation(
                db,
                raw_token=token,
                accepting_user_id=(
                    user_id
                    if user_id is not None
                    else s["recipient_id"]
                ),
            )


def get_invitation(s, invitation_id):
    with new_session(s["connection"]) as db:
        record = db.get(
            OrganizationInvitation,
            invitation_id,
        )

        return {
            "accepted_at": record.accepted_at,
            "accepted_user_id": record.accepted_user_id,
            "revoked_at": record.revoked_at,
        }


def membership(s):
    with new_session(s["connection"]) as db:
        record = db.scalar(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id
                == s["organization_id"],
                OrganizationMembership.user_id
                == s["recipient_id"],
            )
        )

        if record is None:
            return None

        return {
            "id": record.id,
            "role": record.role,
            "status": record.status,
        }


def audit_count(s):
    with new_session(s["connection"]) as db:
        return db.scalar(
            select(func.count(AuditEvent.id)).where(
                AuditEvent.organization_id
                == s["organization_id"],
                AuditEvent.action
                == "organization.invitation_accepted",
            )
        )


def test_valid_invitation_creates_active_membership(sandbox):
    issued = issue(sandbox, role="finance")
    result = accept(sandbox, issued.raw_token)

    assert result.invitation_id == issued.invitation_id
    assert result.organization_id == sandbox["organization_id"]
    assert result.user_id == sandbox["recipient_id"]
    assert result.role == "finance"

    member = membership(sandbox)

    assert member is not None
    assert member["id"] == result.membership_id
    assert member["role"] == "finance"
    assert member["status"] == "active"

    state = get_invitation(
        sandbox, issued.invitation_id
    )

    assert state["accepted_at"] is not None
    assert state["accepted_user_id"] == sandbox["recipient_id"]
    assert audit_count(sandbox) == 1


def test_accepted_invitation_cannot_be_replayed(sandbox):
    issued = issue(sandbox)

    accept(sandbox, issued.raw_token)

    with pytest.raises(InvalidInvitation):
        accept(sandbox, issued.raw_token)

    assert audit_count(sandbox) == 1


@pytest.mark.parametrize(
    "token",
    [
        None,
        "",
        "short",
        "x" * 257,
        12345,
    ],
)
def test_invalid_token_format_is_rejected(sandbox, token):
    with pytest.raises(InvalidInvitation):
        accept(sandbox, token)

    assert audit_count(sandbox) == 0


def test_unknown_token_is_rejected(sandbox):
    with pytest.raises(InvalidInvitation):
        accept(sandbox, "z" * 48)


def test_modified_token_does_not_work(sandbox):
    issued = issue(sandbox)

    altered = (
        "A" if issued.raw_token[0] != "A" else "B"
    ) + issued.raw_token[1:]

    with pytest.raises(InvalidInvitation):
        accept(sandbox, altered)

    assert get_invitation(
        sandbox, issued.invitation_id
    )["accepted_at"] is None


def test_verified_email_must_match_invitation(sandbox):
    issued = issue(sandbox)

    with pytest.raises(InvalidInvitation):
        accept(
            sandbox,
            issued.raw_token,
            user_id=sandbox["wrong_user_id"],
        )

    assert audit_count(sandbox) == 0

    # Rejection must not consume the valid invitation.
    result = accept(sandbox, issued.raw_token)
    assert result.user_id == sandbox["recipient_id"]


def test_unverified_user_cannot_accept(sandbox):
    issued = issue(
        sandbox,
        email=sandbox["unverified_email"],
    )

    with pytest.raises(InvalidInvitation):
        accept(
            sandbox,
            issued.raw_token,
            user_id=sandbox["unverified_id"],
        )

    assert audit_count(sandbox) == 0


def test_inactive_user_cannot_accept(sandbox):
    issued = issue(
        sandbox,
        email=sandbox["inactive_email"],
    )

    with pytest.raises(InvalidInvitation):
        accept(
            sandbox,
            issued.raw_token,
            user_id=sandbox["inactive_id"],
        )


def test_expired_invitation_is_rejected(sandbox):
    issued = issue(sandbox)

    with new_session(sandbox["connection"]) as db:
        with db.begin():
            record = db.get(
                OrganizationInvitation,
                issued.invitation_id,
            )

            record.created_at = (
                datetime.now(timezone.utc)
                - timedelta(days=10)
            )
            record.expires_at = (
                datetime.now(timezone.utc)
                - timedelta(days=1)
            )

    with pytest.raises(InvalidInvitation):
        accept(sandbox, issued.raw_token)

    assert membership(sandbox) is None


def test_revoked_invitation_is_rejected(sandbox):
    issued = issue(sandbox)

    with new_session(sandbox["connection"]) as db:
        with db.begin():
            record = db.get(
                OrganizationInvitation,
                issued.invitation_id,
            )
            record.revoked_at = datetime.now(timezone.utc)

    with pytest.raises(InvalidInvitation):
        accept(sandbox, issued.raw_token)


def test_previously_revoked_member_can_be_reinvited(sandbox):
    issued = issue(sandbox, role="developer")

    with new_session(sandbox["connection"]) as db:
        with db.begin():
            db.add(
                OrganizationMembership(
                    organization_id=sandbox["organization_id"],
                    user_id=sandbox["recipient_id"],
                    role="viewer",
                    status="revoked",
                )
            )

    result = accept(sandbox, issued.raw_token)

    assert result.role == "developer"
    assert membership(sandbox)["status"] == "active"
    assert membership(sandbox)["role"] == "developer"


@pytest.mark.parametrize("existing_status", [
    "active",
    "invited",
])
def test_existing_nonrevoked_membership_is_protected(
    sandbox,
    existing_status,
):
    issued = issue(sandbox)

    with new_session(sandbox["connection"]) as db:
        with db.begin():
            db.add(
                OrganizationMembership(
                    organization_id=sandbox["organization_id"],
                    user_id=sandbox["recipient_id"],
                    role="finance",
                    status=existing_status,
                )
            )

    with pytest.raises(ExistingOrganizationMember):
        accept(sandbox, issued.raw_token)

    assert membership(sandbox)["role"] == "finance"
    assert audit_count(sandbox) == 0
    assert get_invitation(
        sandbox, issued.invitation_id
    )["accepted_at"] is None


def test_suspended_organization_rejects_acceptance(sandbox):
    issued = issue(sandbox)

    with new_session(sandbox["connection"]) as db:
        with db.begin():
            db.get(
                Organization,
                sandbox["organization_id"],
            ).status = "suspended"

    with pytest.raises(InvalidInvitation):
        accept(sandbox, issued.raw_token)


def test_revoked_inviter_cannot_grant_access(sandbox):
    issued = issue(sandbox)

    with new_session(sandbox["connection"]) as db:
        with db.begin():
            inviter = db.scalar(
                select(OrganizationMembership).where(
                    OrganizationMembership.organization_id
                    == sandbox["organization_id"],
                    OrganizationMembership.user_id
                    == sandbox["owner_id"],
                )
            )
            inviter.status = "revoked"

    with pytest.raises(InvalidInvitation):
        accept(sandbox, issued.raw_token)


def test_downgraded_inviter_cannot_grant_admin(sandbox):
    issued = issue(sandbox, role="admin")

    with new_session(sandbox["connection"]) as db:
        with db.begin():
            inviter = db.scalar(
                select(OrganizationMembership).where(
                    OrganizationMembership.organization_id
                    == sandbox["organization_id"],
                    OrganizationMembership.user_id
                    == sandbox["owner_id"],
                )
            )
            inviter.role = "viewer"

    with pytest.raises(InvalidInvitation):
        accept(sandbox, issued.raw_token)


def test_owner_issued_admin_invitation_is_accepted(sandbox):
    issued = issue(sandbox, role="admin")
    result = accept(sandbox, issued.raw_token)

    assert result.role == "admin"
    assert membership(sandbox)["role"] == "admin"


def test_successful_acceptance_audit_excludes_secret(sandbox):
    issued = issue(sandbox)
    result = accept(sandbox, issued.raw_token)

    with new_session(sandbox["connection"]) as db:
        event = db.scalar(
            select(AuditEvent).where(
                AuditEvent.action
                == "organization.invitation_accepted",
                AuditEvent.subject_id
                == str(issued.invitation_id),
            )
        )

        assert event is not None
        assert event.payload["role"] == "viewer"
        assert issued.raw_token not in str(event.payload)
        assert "raw_token" not in event.payload
        assert "token_hash" not in event.payload

    assert issued.raw_token not in repr(result)


def test_acceptance_rolls_back_atomically(sandbox):
    issued = issue(sandbox)

    with pytest.raises(RuntimeError):
        with new_session(sandbox["connection"]) as db:
            with db.begin():
                accept_organization_invitation(
                    db,
                    raw_token=issued.raw_token,
                    accepting_user_id=sandbox["recipient_id"],
                )

                # Simulate an application failure before commit.
                raise RuntimeError("Simulated transaction failure")

    assert membership(sandbox) is None
    assert audit_count(sandbox) == 0

    assert get_invitation(
        sandbox, issued.invitation_id
    )["accepted_at"] is None


def test_expired_old_token_fails_after_reissue(sandbox):
    first = issue(sandbox)

    with new_session(sandbox["connection"]) as db:
        with db.begin():
            record = db.get(
                OrganizationInvitation,
                first.invitation_id,
            )

            record.created_at = (
                datetime.now(timezone.utc)
                - timedelta(days=10)
            )
            record.expires_at = (
                datetime.now(timezone.utc)
                - timedelta(days=1)
            )

    second = issue(sandbox)

    with pytest.raises(InvalidInvitation):
        accept(sandbox, first.raw_token)

    result = accept(sandbox, second.raw_token)

    assert result.invitation_id == second.invitation_id
    assert audit_count(sandbox) == 1
