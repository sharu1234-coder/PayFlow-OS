import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.dependencies import get_db
from app.core.database import engine
from app.core.security import (
    hash_password,
    hash_secure_token,
)
from app.main import app
from app.models import User, UserSession


TEST_PASSWORD = "Local-Login-Test-Password-2026!"


@pytest.fixture
def sandbox():
    with engine.connect() as connection:
        outer = connection.begin()

        def override_db():
            with Session(
                bind=connection,
                expire_on_commit=False,
                join_transaction_mode="create_savepoint",
            ) as db:
                yield db

        app.dependency_overrides[get_db] = override_db

        try:
            with TestClient(app) as client:
                yield client, connection
        finally:
            app.dependency_overrides.pop(get_db, None)

            if outer.is_active:
                outer.rollback()


def create_user(connection, verified=True, active=True):
    email = f"login-{uuid.uuid4().hex}@example.com"

    with Session(
        bind=connection,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    ) as db:
        with db.begin():
            user = User(
                email=email,
                password_hash=hash_password(TEST_PASSWORD),
                display_name="Login Test Merchant",
                is_active=active,
            )

            if verified:
                user.email_verified_at = datetime.now(
                    timezone.utc
                )

            db.add(user)
            db.flush()
            user_id = user.id

    return user_id, email


def login(client, email, password=TEST_PASSWORD):
    return client.post(
        "/api/v1/auth/login",
        json={
            "email": email,
            "password": password,
        },
    )


def test_verified_user_receives_securely_scoped_cookie(sandbox):
    client, connection = sandbox
    user_id, email = create_user(connection)

    response = login(client, email.upper())

    assert response.status_code == 200, response.text
    assert response.json() == {
        "status": "authenticated"
    }

    raw_token = response.cookies.get("payflow_session")

    assert raw_token is not None
    assert len(raw_token) >= 32
    assert raw_token not in response.text

    cookie_header = response.headers["set-cookie"].lower()

    assert "httponly" in cookie_header
    assert "samesite=lax" in cookie_header
    assert "path=/" in cookie_header
    assert "max-age=28800" in cookie_header

    with Session(bind=connection) as db:
        record = db.scalar(
            select(UserSession).where(
                UserSession.user_id == user_id
            )
        )

        assert record is not None
        assert record.token_hash == hash_secure_token(raw_token)
        assert record.token_hash != raw_token
        assert record.revoked_at is None
        assert record.expires_at > datetime.now(timezone.utc)


def test_incorrect_password_is_rejected(sandbox):
    client, connection = sandbox
    _, email = create_user(connection)

    response = login(client, email, "Incorrect-Password")

    assert response.status_code == 401
    assert response.json()["detail"] == (
        "Invalid email or password"
    )
    assert "set-cookie" not in response.headers


def test_unknown_email_has_same_error(sandbox):
    client, _ = sandbox

    response = login(
        client,
        f"unknown-{uuid.uuid4().hex}@example.com",
    )

    assert response.status_code == 401
    assert response.json()["detail"] == (
        "Invalid email or password"
    )


def test_unverified_user_cannot_login(sandbox):
    client, connection = sandbox
    _, email = create_user(connection, verified=False)

    response = login(client, email)

    assert response.status_code == 401
    assert response.json()["detail"] == (
        "Invalid email or password"
    )


def test_inactive_user_cannot_login(sandbox):
    client, connection = sandbox
    _, email = create_user(connection, active=False)

    response = login(client, email)

    assert response.status_code == 401


def test_each_successful_login_gets_a_new_session(sandbox):
    client, connection = sandbox
    user_id, email = create_user(connection)

    first = login(client, email)
    second = login(client, email)

    assert first.status_code == 200
    assert second.status_code == 200

    first_token = first.cookies["payflow_session"]
    second_token = second.cookies["payflow_session"]

    assert first_token != second_token

    with Session(bind=connection) as db:
        records = db.scalars(
            select(UserSession).where(
                UserSession.user_id == user_id
            )
        ).all()

        assert len(records) == 2
        assert len({record.token_hash for record in records}) == 2


def test_login_disabled_outside_development(
    sandbox,
    monkeypatch,
):
    client, connection = sandbox
    _, email = create_user(connection)

    monkeypatch.setattr(
        "app.api.auth.get_settings",
        lambda: SimpleNamespace(app_env="production"),
    )

    response = login(client, email)

    assert response.status_code == 503
    assert "set-cookie" not in response.headers
