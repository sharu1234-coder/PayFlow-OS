import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
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


PASSWORD = "PayFlow-Tenant-Test-Password-2026!"


def session_for(connection):
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
            with session_for(connection) as db:
                with db.begin():
                    user = User(
                        email=(
                            f"tenant-{uuid.uuid4().hex}"
                            "@example.com"
                        ),
                        password_hash=hash_password(PASSWORD),
                        display_name="Tenant Test User",
                        email_verified_at=datetime.now(
                            timezone.utc
                        ),
                    )
                    db.add(user)
                    db.flush()

                    own = Organization(
                        name="Merchant Alpha",
                        slug=f"alpha-{uuid.uuid4().hex[:16]}",
                    )
                    other = Organization(
                        name="Merchant Beta",
                        slug=f"beta-{uuid.uuid4().hex[:16]}",
                    )
                    db.add_all([own, other])
                    db.flush()

                    db.add_all([
                        MerchantProfile(
                            organization_id=own.id,
                            business_name="Private Alpha Business",
                            onboarding_status="draft",
                        ),
                        MerchantProfile(
                            organization_id=other.id,
                            business_name="Private Beta Business",
                            onboarding_status="draft",
                        ),
                        OrganizationMembership(
                            organization_id=own.id,
                            user_id=user.id,
                            role="owner",
                            status="active",
                        ),
                    ])

                    user_id = user.id
                    email = user.email
                    own_id = own.id
                    other_id = other.id

            def override_db():
                with session_for(connection) as db:
                    yield db

            app.dependency_overrides[get_db] = override_db

            try:
                with TestClient(app) as client:
                    response = client.post(
                        "/api/v1/auth/login",
                        json={
                            "email": email,
                            "password": PASSWORD,
                        },
                    )
                    assert response.status_code == 200

                    yield (
                        client,
                        connection,
                        user_id,
                        own_id,
                        other_id,
                    )
            finally:
                app.dependency_overrides.pop(get_db, None)
        finally:
            if outer.is_active:
                outer.rollback()


def detail(client, organization_id):
    return client.get(
        f"/api/v1/organizations/{organization_id}"
    )


def test_list_contains_only_active_memberships(sandbox):
    client, _, _, own_id, other_id = sandbox

    response = client.get("/api/v1/organizations")

    assert response.status_code == 200

    records = response.json()

    assert len(records) == 1
    assert records[0]["id"] == str(own_id)
    assert records[0]["role"] == "owner"
    assert str(other_id) not in response.text


def test_owner_can_read_own_organization(sandbox):
    client, _, _, own_id, _ = sandbox

    response = detail(client, own_id)

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == str(own_id)
    assert data["name"] == "Merchant Alpha"
    assert data["business_name"] == (
        "Private Alpha Business"
    )
    assert data["onboarding_status"] == "draft"
    assert data["role"] == "owner"


def test_cross_merchant_access_is_denied(sandbox):
    client, _, _, _, other_id = sandbox

    response = detail(client, other_id)

    assert response.status_code == 404
    assert "Private Beta Business" not in response.text


def test_unknown_organization_is_hidden(sandbox):
    client, _, _, _, _ = sandbox

    response = detail(client, uuid.uuid4())

    assert response.status_code == 404
    assert response.json()["detail"] == (
        "Organization not found"
    )


@pytest.mark.parametrize("membership_status", [
    "invited",
    "revoked",
])
def test_inactive_membership_has_no_access(
    sandbox,
    membership_status,
):
    client, connection, user_id, own_id, _ = sandbox

    with session_for(connection) as db:
        with db.begin():
            membership = db.query(
                OrganizationMembership
            ).filter_by(
                user_id=user_id,
                organization_id=own_id,
            ).one()

            membership.status = membership_status

    assert detail(client, own_id).status_code == 404
    assert client.get(
        "/api/v1/organizations"
    ).json() == []


def test_suspended_organization_is_hidden(sandbox):
    client, connection, _, own_id, _ = sandbox

    with session_for(connection) as db:
        with db.begin():
            organization = db.get(
                Organization, own_id
            )
            organization.status = "suspended"

    assert detail(client, own_id).status_code == 404
    assert client.get(
        "/api/v1/organizations"
    ).json() == []


def test_missing_authentication_is_rejected(sandbox):
    client, _, _, own_id, _ = sandbox

    client.cookies.clear()

    assert client.get(
        "/api/v1/organizations"
    ).status_code == 401

    assert detail(client, own_id).status_code == 401


def test_unverified_user_session_is_rejected(sandbox):
    client, connection, user_id, _, _ = sandbox

    with session_for(connection) as db:
        with db.begin():
            db.get(User, user_id).email_verified_at = None

    assert client.get(
        "/api/v1/organizations"
    ).status_code == 401


def test_invalid_organization_id_is_rejected(sandbox):
    client, _, _, _, _ = sandbox

    response = client.get(
        "/api/v1/organizations/not-a-valid-uuid"
    )

    assert response.status_code == 422


def test_organization_api_disabled_in_production(
    sandbox,
    monkeypatch,
):
    client, _, _, _, _ = sandbox

    monkeypatch.setattr(
        "app.api.organizations.get_settings",
        lambda: SimpleNamespace(app_env="production"),
    )

    response = client.get("/api/v1/organizations")

    assert response.status_code == 503
