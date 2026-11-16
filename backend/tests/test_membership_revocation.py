import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.dependencies import get_db
from app.core.database import engine
from app.core.security import hash_password
from app.main import app
from app.models import (
    AuditEvent,
    Organization,
    OrganizationMembership,
    User,
)


PASSWORD = "PayFlow-Revocation-Test-2026!"


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
                        email=f"revoke-owner-{uuid.uuid4().hex}@example.com",
                        password_hash=hash_password(PASSWORD),
                        display_name="Revocation Owner",
                        email_verified_at=datetime.now(timezone.utc),
                    )

                    target = User(
                        email=f"revoke-target-{uuid.uuid4().hex}@example.com",
                        password_hash=hash_password(PASSWORD),
                        display_name="Revocation Target",
                        email_verified_at=datetime.now(timezone.utc),
                    )

                    outsider = User(
                        email=f"revoke-other-{uuid.uuid4().hex}@example.com",
                        password_hash=hash_password(PASSWORD),
                        display_name="Outside Merchant",
                        email_verified_at=datetime.now(timezone.utc),
                    )

                    db.add_all([owner, target, outsider])
                    db.flush()

                    own = Organization(
                        name="Revocation Test Alpha",
                        slug=f"revoke-alpha-{uuid.uuid4().hex[:12]}",
                    )

                    other = Organization(
                        name="Revocation Test Beta",
                        slug=f"revoke-beta-{uuid.uuid4().hex[:12]}",
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
                            user_id=target.id,
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

                    data = {
                        "connection": connection,
                        "owner_id": owner.id,
                        "owner_email": owner.email,
                        "target_id": target.id,
                        "target_email": target.email,
                        "outsider_id": outsider.id,
                        "own_id": own.id,
                        "other_id": other.id,
                    }

            def override_db():
                with new_session(connection) as db:
                    yield db

            app.dependency_overrides[get_db] = override_db

            try:
                with TestClient(app) as client:
                    login = client.post(
                        "/api/v1/auth/login",
                        json={
                            "email": data["owner_email"],
                            "password": PASSWORD,
                        },
                    )

                    assert login.status_code == 200, login.text

                    csrf = client.get("/api/v1/auth/csrf")
                    assert csrf.status_code == 200

                    data["client"] = client
                    data["csrf"] = csrf.json()["token"]

                    yield data
            finally:
                app.dependency_overrides.pop(get_db, None)

        finally:
            if outer.is_active:
                outer.rollback()


def revoke(
    s,
    *,
    organization_id=None,
    member_id=None,
    csrf="valid",
):
    path = (
        f"/api/v1/organizations/"
        f"{organization_id or s['own_id']}"
        f"/members/{member_id or s['target_id']}/revoke"
    )

    headers = {}

    if csrf == "valid":
        headers["X-CSRF-Token"] = s["csrf"]
    elif csrf == "invalid":
        headers["X-CSRF-Token"] = "0" * 64

    return s["client"].post(
        path,
        headers=headers,
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


def get_member_status(s):
    with new_session(s["connection"]) as db:
        membership = db.scalar(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id
                == s["own_id"],
                OrganizationMembership.user_id
                == s["target_id"],
            )
        )
        return membership.status


def audit_count(s):
    with new_session(s["connection"]) as db:
        return db.scalar(
            select(func.count(AuditEvent.id)).where(
                AuditEvent.organization_id == s["own_id"],
                AuditEvent.action
                == "organization.member_revoked",
            )
        )


def test_owner_can_revoke_non_owner(sandbox):
    response = revoke(sandbox)

    assert response.status_code == 200, response.text
    assert response.json() == {
        "organization_id": str(sandbox["own_id"]),
        "user_id": str(sandbox["target_id"]),
        "status": "revoked",
    }

    assert get_member_status(sandbox) == "revoked"
    assert audit_count(sandbox) == 1


def test_repeated_revocation_is_rejected(sandbox):
    assert revoke(sandbox).status_code == 200
    assert revoke(sandbox).status_code == 404
    assert audit_count(sandbox) == 1


def test_revoked_member_loses_access_without_session_expiry(sandbox):
    client = sandbox["client"]

    # Create a login session for the target BEFORE revocation.
    target_login = client.post(
        "/api/v1/auth/login",
        json={
            "email": sandbox["target_email"],
            "password": PASSWORD,
        },
    )

    assert target_login.status_code == 200
    target_session = target_login.cookies["payflow_session"]

    # Log the owner in again so the owner can revoke the target.
    owner_login = client.post(
        "/api/v1/auth/login",
        json={
            "email": sandbox["owner_email"],
            "password": PASSWORD,
        },
    )

    assert owner_login.status_code == 200

    csrf = client.get("/api/v1/auth/csrf")
    assert csrf.status_code == 200
    sandbox["csrf"] = csrf.json()["token"]

    assert revoke(sandbox).status_code == 200

    # Reuse the target's EXISTING session.
    client.cookies.clear()
    client.cookies.set(
        "payflow_session",
        target_session,
        path="/",
    )

    # The target is still logged in globally,
    # but has no access to the revoked organization.
    assert client.get("/api/v1/auth/me").status_code == 200

    organizations = client.get(
        "/api/v1/organizations"
    )

    assert organizations.status_code == 200
    assert organizations.json() == []

    detail = client.get(
        f"/api/v1/organizations/{sandbox['own_id']}"
    )

    assert detail.status_code == 404


def test_missing_csrf_is_rejected(sandbox):
    assert revoke(sandbox, csrf="missing").status_code == 403
    assert get_member_status(sandbox) == "active"
    assert audit_count(sandbox) == 0


def test_invalid_csrf_is_rejected(sandbox):
    assert revoke(sandbox, csrf="invalid").status_code == 403
    assert get_member_status(sandbox) == "active"


@pytest.mark.parametrize(
    "role",
    ["developer", "finance", "viewer"],
)
def test_non_manager_cannot_revoke_members(sandbox, role):
    change_membership(
        sandbox,
        sandbox["owner_id"],
        role=role,
    )

    assert revoke(sandbox).status_code == 403
    assert get_member_status(sandbox) == "active"


def test_admin_can_revoke_viewer(sandbox):
    change_membership(
        sandbox,
        sandbox["owner_id"],
        role="admin",
    )

    assert revoke(sandbox).status_code == 200
    assert get_member_status(sandbox) == "revoked"


def test_admin_cannot_revoke_admin(sandbox):
    change_membership(
        sandbox,
        sandbox["owner_id"],
        role="admin",
    )

    change_membership(
        sandbox,
        sandbox["target_id"],
        role="admin",
    )

    assert revoke(sandbox).status_code == 403


def test_owner_cannot_revoke_themselves(sandbox):
    response = revoke(
        sandbox,
        member_id=sandbox["owner_id"],
    )

    assert response.status_code == 403


def test_owner_cannot_revoke_another_owner(sandbox):
    change_membership(
        sandbox,
        sandbox["target_id"],
        role="owner",
    )

    assert revoke(sandbox).status_code == 403


def test_cross_merchant_revocation_is_hidden(sandbox):
    response = revoke(
        sandbox,
        organization_id=sandbox["other_id"],
        member_id=sandbox["outsider_id"],
    )

    assert response.status_code == 404


def test_outsider_is_not_member_of_own_organization(sandbox):
    response = revoke(
        sandbox,
        member_id=sandbox["outsider_id"],
    )

    assert response.status_code == 404


@pytest.mark.parametrize(
    "membership_status",
    ["invited", "revoked"],
)
def test_inactive_target_cannot_be_revoked(
    sandbox,
    membership_status,
):
    change_membership(
        sandbox,
        sandbox["target_id"],
        status=membership_status,
    )

    assert revoke(sandbox).status_code == 404


def test_revoked_actor_cannot_revoke_members(sandbox):
    change_membership(
        sandbox,
        sandbox["owner_id"],
        status="revoked",
    )

    assert revoke(sandbox).status_code == 404


def test_suspended_organization_blocks_revocation(sandbox):
    with new_session(sandbox["connection"]) as db:
        with db.begin():
            db.get(
                Organization,
                sandbox["own_id"],
            ).status = "suspended"

    assert revoke(sandbox).status_code == 404


def test_unauthenticated_request_is_rejected(sandbox):
    sandbox["client"].cookies.clear()

    assert revoke(sandbox).status_code == 401


def test_unknown_member_is_hidden(sandbox):
    response = revoke(
        sandbox,
        member_id=uuid.uuid4(),
    )

    assert response.status_code == 404


def test_endpoint_disabled_outside_development(
    sandbox,
    monkeypatch,
):
    monkeypatch.setattr(
        "app.api.organizations.get_settings",
        lambda: SimpleNamespace(app_env="production"),
    )

    assert revoke(sandbox).status_code == 503
