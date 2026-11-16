import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.dependencies import get_db
from app.core.database import engine
from app.core.security import hash_password
from app.main import app
from app.models import (
    MerchantProfile,
    Organization,
    OrganizationMembership,
    User,
)
from app.services.organization_rbac import (
    ALL_PERMISSIONS,
    permissions_for_role,
    require_organization_permission,
)


PASSWORD = "PayFlow-RBAC-Local-Test-2026!"


def make_session(connection):
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
            with make_session(connection) as db:
                with db.begin():
                    owner = User(
                        email=f"rbac-{uuid.uuid4().hex}@example.com",
                        password_hash=hash_password(PASSWORD),
                        display_name="RBAC Owner",
                        email_verified_at=datetime.now(timezone.utc),
                    )
                    colleague = User(
                        email=f"colleague-{uuid.uuid4().hex}@example.com",
                        password_hash="unused-test-hash",
                        display_name="Team Colleague",
                        email_verified_at=datetime.now(timezone.utc),
                    )
                    outsider = User(
                        email=f"outsider-{uuid.uuid4().hex}@example.com",
                        password_hash="unused-test-hash",
                        display_name="Other Merchant User",
                        email_verified_at=datetime.now(timezone.utc),
                    )

                    db.add_all([owner, colleague, outsider])
                    db.flush()

                    own = Organization(
                        name="RBAC Merchant Alpha",
                        slug=f"rbac-alpha-{uuid.uuid4().hex[:12]}",
                    )
                    other = Organization(
                        name="RBAC Merchant Beta",
                        slug=f"rbac-beta-{uuid.uuid4().hex[:12]}",
                    )

                    db.add_all([own, other])
                    db.flush()

                    db.add_all([
                        MerchantProfile(
                            organization_id=own.id,
                            business_name="Private Alpha",
                            onboarding_status="draft",
                        ),
                        MerchantProfile(
                            organization_id=other.id,
                            business_name="Private Beta",
                            onboarding_status="draft",
                        ),
                        OrganizationMembership(
                            organization_id=own.id,
                            user_id=owner.id,
                            role="owner",
                            status="active",
                        ),
                        OrganizationMembership(
                            organization_id=own.id,
                            user_id=colleague.id,
                            role="viewer",
                            status="active",
                        ),
                        OrganizationMembership(
                            organization_id=other.id,
                            user_id=outsider.id,
                            role="owner",
                            status="active",
                        ),
                    ])

                    owner_id = owner.id
                    owner_email = owner.email
                    colleague_email = colleague.email
                    outsider_email = outsider.email
                    own_id = own.id
                    other_id = other.id

            def override_db():
                with make_session(connection) as db:
                    yield db

            app.dependency_overrides[get_db] = override_db

            try:
                with TestClient(app) as client:
                    response = client.post(
                        "/api/v1/auth/login",
                        json={
                            "email": owner_email,
                            "password": PASSWORD,
                        },
                    )

                    assert response.status_code == 200, response.text

                    yield {
                        "client": client,
                        "connection": connection,
                        "owner_id": owner_id,
                        "own_id": own_id,
                        "other_id": other_id,
                        "owner_email": owner_email,
                        "colleague_email": colleague_email,
                        "outsider_email": outsider_email,
                    }
            finally:
                app.dependency_overrides.pop(get_db, None)
        finally:
            if outer.is_active:
                outer.rollback()


def permissions_url(s):
    return (
        f"/api/v1/organizations/"
        f"{s['own_id']}/permissions"
    )


def members_url(s):
    return (
        f"/api/v1/organizations/"
        f"{s['own_id']}/members"
    )


def change_membership(s, *, role=None, status=None):
    with make_session(s["connection"]) as db:
        with db.begin():
            membership = db.scalar(
                select(OrganizationMembership)
                .where(
                    OrganizationMembership.organization_id
                    == s["own_id"],
                    OrganizationMembership.user_id
                    == s["owner_id"],
                )
            )

            assert membership is not None

            if role is not None:
                membership.role = role

            if status is not None:
                membership.status = status


def test_owner_receives_full_permission_manifest(sandbox):
    response = sandbox["client"].get(
        permissions_url(sandbox)
    )

    assert response.status_code == 200

    data = response.json()

    assert data["organization_id"] == str(sandbox["own_id"])
    assert data["role"] == "owner"
    assert set(data["permissions"]) == ALL_PERMISSIONS


def test_owner_can_view_own_team_but_not_other_team(sandbox):
    response = sandbox["client"].get(members_url(sandbox))

    assert response.status_code == 200

    members = response.json()
    emails = {member["email"] for member in members}

    assert sandbox["owner_email"] in emails
    assert sandbox["colleague_email"] in emails
    assert sandbox["outsider_email"] not in emails

    assert "password_hash" not in response.text


@pytest.mark.parametrize(
    "role,expected_status",
    [
        ("owner", 200),
        ("admin", 200),
        ("developer", 403),
        ("finance", 403),
        ("viewer", 403),
    ],
)
def test_team_access_enforces_each_role(
    sandbox,
    role,
    expected_status,
):
    change_membership(sandbox, role=role)

    response = sandbox["client"].get(
        members_url(sandbox)
    )

    assert response.status_code == expected_status

    permissions = sandbox["client"].get(
        permissions_url(sandbox)
    )

    assert permissions.status_code == 200
    assert permissions.json()["role"] == role

    can_read_members = (
        "members.read"
        in permissions.json()["permissions"]
    )

    assert can_read_members == (expected_status == 200)


def test_role_downgrade_takes_effect_immediately(sandbox):
    client = sandbox["client"]

    assert client.get(members_url(sandbox)).status_code == 200

    change_membership(sandbox, role="viewer")

    assert client.get(members_url(sandbox)).status_code == 403


def test_cross_merchant_permissions_are_hidden(sandbox):
    path = (
        f"/api/v1/organizations/"
        f"{sandbox['other_id']}/permissions"
    )

    response = sandbox["client"].get(path)

    assert response.status_code == 404
    assert "Private Beta" not in response.text


def test_cross_merchant_members_are_hidden(sandbox):
    path = (
        f"/api/v1/organizations/"
        f"{sandbox['other_id']}/members"
    )

    response = sandbox["client"].get(path)

    assert response.status_code == 404
    assert sandbox["outsider_email"] not in response.text


@pytest.mark.parametrize("status", ["invited", "revoked"])
def test_inactive_membership_cannot_access_rbac(
    sandbox,
    status,
):
    change_membership(sandbox, status=status)

    assert sandbox["client"].get(
        permissions_url(sandbox)
    ).status_code == 404

    assert sandbox["client"].get(
        members_url(sandbox)
    ).status_code == 404


def test_suspended_organization_cannot_be_accessed(sandbox):
    with make_session(sandbox["connection"]) as db:
        with db.begin():
            organization = db.get(
                Organization,
                sandbox["own_id"],
            )
            organization.status = "suspended"

    assert sandbox["client"].get(
        permissions_url(sandbox)
    ).status_code == 404

    assert sandbox["client"].get(
        members_url(sandbox)
    ).status_code == 404


def test_unauthenticated_team_request_is_rejected(sandbox):
    client = sandbox["client"]
    client.cookies.clear()

    assert client.get(members_url(sandbox)).status_code == 401
    assert client.get(
        permissions_url(sandbox)
    ).status_code == 401


def test_nonexistent_organization_is_hidden(sandbox):
    path = (
        f"/api/v1/organizations/"
        f"{uuid.uuid4()}/members"
    )

    assert sandbox["client"].get(path).status_code == 404


def test_unknown_role_is_fail_closed():
    assert permissions_for_role("superadmin") == frozenset()
    assert permissions_for_role("") == frozenset()


def test_unknown_permission_is_rejected_by_service(sandbox):
    with make_session(sandbox["connection"]) as db:
        with pytest.raises(ValueError):
            require_organization_permission(
                db,
                sandbox["owner_id"],
                sandbox["own_id"],
                "unknown.permission",
            )


def test_invalid_organization_identifier_is_rejected(sandbox):
    response = sandbox["client"].get(
        "/api/v1/organizations/not-a-uuid/members"
    )

    assert response.status_code == 422
