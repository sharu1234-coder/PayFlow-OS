import secrets
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.api.dependencies import get_db
from app.core.database import engine
from app.core.security import (
    generate_secure_token,
    hash_secure_token,
)
from app.main import app
from app.models import (
    AuthToken,
    Organization,
    OrganizationMembership,
    User,
)
from app.services.email_verification import (
    issue_email_verification,
)


@pytest.fixture
def verification_client():
    with engine.connect() as connection:
        outer = connection.begin()

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

            if outer.is_active:
                outer.rollback()


def session_for(connection):
    return Session(
        bind=connection,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    )


def seed_identity(connection):
    with session_for(connection) as db:
        with db.begin():
            user = User(
                email=f"verify-api-{uuid.uuid4().hex}@example.com",
                password_hash="test-only-placeholder",
                display_name="Verification API Test",
            )
            db.add(user)
            db.flush()

            organization = Organization(
                name="Verification API Company",
                slug=f"verify-api-{secrets.token_hex(10)}",
            )
            db.add(organization)
            db.flush()

            db.add(
                OrganizationMembership(
                    organization_id=organization.id,
                    user_id=user.id,
                    role="owner",
                    status="invited",
                )
            )

            token = issue_email_verification(db, user.id)

        return user.id, organization.id, token


def verify(client, token):
    return client.post(
        "/api/v1/auth/verify-email",
        json={"token": token},
    )


def test_successful_email_verification(verification_client):
    client, connection = verification_client
    user_id, organization_id, token = seed_identity(connection)

    response = verify(client, token)

    assert response.status_code == 200, response.text
    assert response.json() == {"status": "verified"}
    assert token not in response.text

    with session_for(connection) as db:
        user = db.get(User, user_id)
        assert user.email_verified_at is not None

        membership = db.scalar(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == organization_id,
                OrganizationMembership.user_id == user_id,
            )
        )
        assert membership.status == "active"

        record = db.scalar(
            select(AuthToken).where(
                AuthToken.token_hash == hash_secure_token(token)
            )
        )
        assert record.consumed_at is not None


def test_replayed_token_is_rejected(verification_client):
    client, connection = verification_client
    user_id, _, token = seed_identity(connection)

    assert verify(client, token).status_code == 200

    replay = verify(client, token)

    assert replay.status_code == 400
    assert replay.json()["detail"] == (
        "Invalid or expired verification token"
    )

    count = connection.execute(
        text("""
            SELECT count(*)
            FROM payflow.audit_events
            WHERE actor_user_id = :user_id
            AND action = 'identity.email_verified'
        """),
        {"user_id": user_id},
    ).scalar_one()

    assert count == 1


def test_expired_token_is_rejected(verification_client):
    client, connection = verification_client
    user_id, _, token = seed_identity(connection)

    with session_for(connection) as db:
        with db.begin():
            record = db.scalar(
                select(AuthToken).where(
                    AuthToken.token_hash == hash_secure_token(token)
                )
            )

            record.created_at = (
                datetime.now(timezone.utc) - timedelta(days=3)
            )
            record.expires_at = (
                datetime.now(timezone.utc) - timedelta(days=2)
            )

    response = verify(client, token)

    assert response.status_code == 400

    with session_for(connection) as db:
        assert db.get(User, user_id).email_verified_at is None


def test_unknown_token_is_rejected(verification_client):
    client, _ = verification_client

    response = verify(client, generate_secure_token())

    assert response.status_code == 400


def test_password_reset_token_cannot_verify_email(
    verification_client,
):
    client, connection = verification_client
    user_id, _, _ = seed_identity(connection)

    reset_token = generate_secure_token()

    with session_for(connection) as db:
        with db.begin():
            db.add(
                AuthToken(
                    user_id=user_id,
                    purpose="password_reset",
                    token_hash=hash_secure_token(reset_token),
                    expires_at=(
                        datetime.now(timezone.utc)
                        + timedelta(minutes=30)
                    ),
                )
            )

    response = verify(client, reset_token)

    assert response.status_code == 400

    with session_for(connection) as db:
        assert db.get(User, user_id).email_verified_at is None


def test_inactive_user_cannot_verify(verification_client):
    client, connection = verification_client
    user_id, _, token = seed_identity(connection)

    with session_for(connection) as db:
        with db.begin():
            user = db.get(User, user_id)
            user.is_active = False

    assert verify(client, token).status_code == 400


def test_missing_token_is_rejected(verification_client):
    client, _ = verification_client

    response = client.post(
        "/api/v1/auth/verify-email",
        json={},
    )

    assert response.status_code == 422


def test_verification_disabled_outside_development(
    verification_client,
    monkeypatch,
):
    client, _, = verification_client

    monkeypatch.setattr(
        "app.api.auth.get_settings",
        lambda: SimpleNamespace(app_env="production"),
    )

    response = verify(client, generate_secure_token())

    assert response.status_code == 503
