import uuid
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.dependencies import get_db
from app.core.database import engine
from app.main import app


@pytest.fixture
def registration_client():
    # All test writes are isolated in an outer transaction.
    # Application commits use SAVEPOINTs, never committing
    # the outer transaction.
    with engine.connect() as connection:
        outer_transaction = connection.begin()

        def override_db():
            with Session(
                bind=connection,
                expire_on_commit=False,
                join_transaction_mode="create_savepoint",
            ) as session:
                yield session

        app.dependency_overrides[get_db] = override_db

        try:
            with TestClient(app) as client:
                yield client, connection
        finally:
            app.dependency_overrides.pop(get_db, None)

            if outer_transaction.is_active:
                outer_transaction.rollback()


def registration_payload():
    return {
        "email": f"payflow-{uuid.uuid4().hex}@example.com",
        "password": "A-Long-Local-Test-Password-2026!",
        "display_name": "Test Merchant",
        "business_name": "Test Merchant Company",
    }


def test_merchant_registration_is_atomic(registration_client):
    client, connection = registration_client

    payload = registration_payload()

    response = client.post(
        "/api/v1/auth/register",
        json=payload,
    )

    assert response.status_code == 201, response.text

    result = response.json()

    assert result["email"] == payload["email"]
    assert result["email_verified"] is False
    assert result["status"] == "pending_email_verification"
    assert "password" not in result
    assert "password_hash" not in result

    user = connection.execute(
        text("""
            SELECT id, password_hash, email_verified_at
            FROM payflow.users
            WHERE email = :email
        """),
        {"email": payload["email"]},
    ).mappings().one()

    assert user["password_hash"].startswith("$argon2id$")
    assert payload["password"] not in user["password_hash"]
    assert user["email_verified_at"] is None

    membership = connection.execute(
        text("""
            SELECT role, status
            FROM payflow.organization_memberships
            WHERE organization_id = :org_id
              AND user_id = :user_id
        """),
        {
            "org_id": result["organization_id"],
            "user_id": result["user_id"],
        },
    ).mappings().one()

    assert membership["role"] == "owner"
    assert membership["status"] == "invited"

    profile = connection.execute(
        text("""
            SELECT onboarding_status
            FROM payflow.merchant_profiles
            WHERE organization_id = :org_id
        """),
        {"org_id": result["organization_id"]},
    ).scalar_one()

    assert profile == "draft"

    audit_count = connection.execute(
        text("""
            SELECT count(*)
            FROM payflow.audit_events
            WHERE organization_id = :org_id
              AND action = 'identity.organization_registered'
        """),
        {"org_id": result["organization_id"]},
    ).scalar_one()

    assert audit_count == 1


def test_duplicate_email_is_rejected(registration_client):
    client, connection = registration_client
    payload = registration_payload()

    first = client.post(
        "/api/v1/auth/register", json=payload
    )
    second = client.post(
        "/api/v1/auth/register", json=payload
    )

    assert first.status_code == 201
    assert second.status_code == 409

    count = connection.execute(
        text("""
            SELECT count(*)
            FROM payflow.users
            WHERE email = :email
        """),
        {"email": payload["email"]},
    ).scalar_one()

    assert count == 1


def test_invalid_registration_is_rejected(registration_client):
    client, _ = registration_client
    payload = registration_payload()

    payload["password"] = "short"
    assert client.post(
        "/api/v1/auth/register", json=payload
    ).status_code == 422

    payload = registration_payload()
    payload["email"] = "invalid-email"
    assert client.post(
        "/api/v1/auth/register", json=payload
    ).status_code == 422

    payload = registration_payload()
    payload["business_name"] = "   "
    assert client.post(
        "/api/v1/auth/register", json=payload
    ).status_code == 422


def test_registration_disabled_outside_development(
    registration_client,
    monkeypatch,
):
    client, _ = registration_client

    monkeypatch.setattr(
        "app.api.auth.get_settings",
        lambda: SimpleNamespace(app_env="production"),
    )

    response = client.post(
        "/api/v1/auth/register",
        json=registration_payload(),
    )

    assert response.status_code == 503
