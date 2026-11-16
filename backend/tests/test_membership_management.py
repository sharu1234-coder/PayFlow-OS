import uuid
from datetime import datetime, timezone

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


PASSWORD = "PayFlow-Membership-Test-2026!"


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
                    actor = User(
                        email=f"owner-{uuid.uuid4().hex}@example.com",
                        password_hash=hash_password(PASSWORD),
                        display_name="Team Owner",
                        email_verified_at=datetime.now(timezone.utc),
                    )

                    target = User(
                        email=f"member-{uuid.uuid4().hex}@example.com",
                        password_hash="test-only-hash",
                        display_name="Team Member",
                        email_verified_at=datetime.now(timezone.utc),
                    )

                    outsider = User(
                        email=f"outside-{uuid.uuid4().hex}@example.com",
                        password_hash="test-only-hash",
                        display_name="Outside Member",
                        email_verified_at=datetime.now(timezone.utc),
                    )

                    db.add_all([actor, target, outsider])
                    db.flush()

                    own = Organization(
                        name="Membership Test Alpha",
                        slug=f"role-alpha-{uuid.uuid4().hex[:12]}",
                    )

                    other = Organization(
                        name="Membership Test Beta",
                        slug=f"role-beta-{uuid.uuid4().hex[:12]}",
                    )

                    db.add_all([own, other])
                    db.flush()

                    db.add_all([
                        OrganizationMembership(
                            organization_id=own.id,
                            user_id=actor.id,
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

                    actor_id = actor.id
                    actor_email = actor.email
                    target_id = target.id
                    outsider_id = outsider.id
                    own_id = own.id
                    other_id = other.id

            def override_db():
                with new_session(connection) as db:
                    yield db

            app.dependency_overrides[get_db] = override_db

            try:
                with TestClient(app) as client:
                    login = client.post(
                        "/api/v1/auth/login",
                        json={
                            "email": actor_email,
                            "password": PASSWORD,
                        },
                    )

                    assert login.status_code == 200, login.text

                    csrf = client.get("/api/v1/auth/csrf")
                    assert csrf.status_code == 200

                    yield {
                        "client": client,
                        "connection": connection,
                        "actor_id": actor_id,
                        "target_id": target_id,
                        "outsider_id": outsider_id,
                        "own_id": own_id,
                        "other_id": other_id,
                        "csrf": csrf.json()["token"],
                    }

            finally:
                app.dependency_overrides.pop(get_db, None)

        finally:
            if outer.is_active:
                outer.rollback()


def request_role(
    s,
    role,
    *,
    organization_id=None,
    target_id=None,
    csrf=True,
):
    path = (
        f"/api/v1/organizations/"
        f"{organization_id or s['own_id']}"
        f"/members/{target_id or s['target_id']}/role"
    )

    headers = (
        {"X-CSRF-Token": s["csrf"]}
        if csrf else {}
    )

    return s["client"].patch(
        path,
        json={"role": role},
        headers=headers,
    )


def set_role(s, user_id, role=None, status=None):
    with new_session(s["connection"]) as db:
        with db.begin():
            membership = db.scalar(
                select(OrganizationMembership).where(
                    OrganizationMembership.organization_id
                    == s["own_id"],
                    OrganizationMembership.user_id == user_id,
                )
            )

            assert membership is not None

            if role is not None:
                membership.role = role

            if status is not None:
                membership.status = status


def audit_count(s):
    with new_session(s["connection"]) as db:
        return db.scalar(
            select(func.count(AuditEvent.id)).where(
                AuditEvent.organization_id == s["own_id"],
                AuditEvent.action
                == "organization.member_role_changed",
            )
        )


def test_owner_can_change_member_role(sandbox):
    response = request_role(sandbox, "finance")

    assert response.status_code == 200, response.text
    assert response.json() == {
        "organization_id": str(sandbox["own_id"]),
        "user_id": str(sandbox["target_id"]),
        "role": "finance",
    }

    with new_session(sandbox["connection"]) as db:
        target = db.scalar(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id
                == sandbox["own_id"],
                OrganizationMembership.user_id
                == sandbox["target_id"],
            )
        )
        assert target.role == "finance"

    assert audit_count(sandbox) == 1


def test_idempotent_role_change_creates_no_extra_audit(sandbox):
    assert request_role(sandbox, "viewer").status_code == 200
    assert audit_count(sandbox) == 0


def test_missing_csrf_is_rejected(sandbox):
    response = request_role(
        sandbox, "finance", csrf=False
    )

    assert response.status_code == 403
    assert audit_count(sandbox) == 0


def test_invalid_csrf_is_rejected(sandbox):
    path = (
        f"/api/v1/organizations/{sandbox['own_id']}"
        f"/members/{sandbox['target_id']}/role"
    )

    response = sandbox["client"].patch(
        path,
        json={"role": "finance"},
        headers={"X-CSRF-Token": "0" * 64},
    )

    assert response.status_code == 403
    assert audit_count(sandbox) == 0


@pytest.mark.parametrize("role", ["viewer", "finance", "developer"])
def test_non_manager_cannot_change_roles(sandbox, role):
    set_role(sandbox, sandbox["actor_id"], role=role)

    assert request_role(sandbox, "finance").status_code == 403
    assert audit_count(sandbox) == 0


def test_admin_can_change_viewer_to_finance(sandbox):
    set_role(sandbox, sandbox["actor_id"], role="admin")

    response = request_role(sandbox, "finance")

    assert response.status_code == 200
    assert response.json()["role"] == "finance"


def test_admin_cannot_grant_admin(sandbox):
    set_role(sandbox, sandbox["actor_id"], role="admin")

    assert request_role(sandbox, "admin").status_code == 403


def test_admin_cannot_change_another_admin(sandbox):
    set_role(sandbox, sandbox["actor_id"], role="admin")
    set_role(sandbox, sandbox["target_id"], role="admin")

    assert request_role(sandbox, "viewer").status_code == 403


def test_owner_role_cannot_be_changed(sandbox):
    response = request_role(
        sandbox,
        "viewer",
        target_id=sandbox["actor_id"],
    )

    assert response.status_code == 403


def test_other_organization_is_hidden(sandbox):
    response = request_role(
        sandbox,
        "finance",
        organization_id=sandbox["other_id"],
        target_id=sandbox["outsider_id"],
    )

    assert response.status_code == 404


def test_outside_user_is_not_a_member_of_own_org(sandbox):
    response = request_role(
        sandbox,
        "finance",
        target_id=sandbox["outsider_id"],
    )

    assert response.status_code == 404


@pytest.mark.parametrize("membership_status", ["invited", "revoked"])
def test_inactive_target_membership_is_hidden(
    sandbox,
    membership_status,
):
    set_role(
        sandbox,
        sandbox["target_id"],
        status=membership_status,
    )

    assert request_role(sandbox, "finance").status_code == 404


def test_invalid_new_role_is_rejected(sandbox):
    response = request_role(sandbox, "owner")

    assert response.status_code == 422
    assert audit_count(sandbox) == 0


def test_unauthenticated_role_change_is_rejected(sandbox):
    sandbox["client"].cookies.clear()

    response = request_role(sandbox, "finance")

    assert response.status_code == 401


def test_unknown_member_is_hidden(sandbox):
    response = request_role(
        sandbox,
        "finance",
        target_id=uuid.uuid4(),
    )

    assert response.status_code == 404


def test_suspended_organization_is_hidden(sandbox):
    with new_session(sandbox["connection"]) as db:
        with db.begin():
            db.get(
                Organization, sandbox["own_id"]
            ).status = "suspended"

    assert request_role(sandbox, "finance").status_code == 404


def test_role_change_takes_effect_without_relogin(sandbox):
    set_role(
        sandbox,
        sandbox["actor_id"],
        role="viewer",
    )

    assert request_role(sandbox, "finance").status_code == 403
