import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.dependencies import get_db
from app.core.database import engine
from app.core.security import (
    generate_secure_token,
    hash_password,
    hash_secure_token,
)
from app.main import app
from app.models import User, UserSession


PASSWORD = "PayFlow-Local-Session-Test-2026!"


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


def new_session(connection):
    return Session(
        bind=connection,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    )


def sign_in(client, connection):
    email = f"session-{uuid.uuid4().hex}@example.com"

    with new_session(connection) as db:
        with db.begin():
            user = User(
                email=email,
                password_hash=hash_password(PASSWORD),
                display_name="PayFlow Session Tester",
                email_verified_at=datetime.now(timezone.utc),
            )
            db.add(user)
            db.flush()
            user_id = user.id

    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": email,
            "password": PASSWORD,
        },
    )

    assert response.status_code == 200, response.text

    return (
        user_id,
        email,
        response.cookies["payflow_session"],
    )


def test_me_requires_cookie(sandbox):
    client, _ = sandbox

    response = client.get("/api/v1/auth/me")

    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required"


def test_me_returns_safe_user_profile(sandbox):
    client, connection = sandbox
    user_id, email, raw_token = sign_in(client, connection)

    response = client.get("/api/v1/auth/me")

    assert response.status_code == 200
    assert response.json() == {
        "id": str(user_id),
        "email": email,
        "display_name": "PayFlow Session Tester",
        "email_verified": True,
    }

    assert raw_token not in response.text
    assert PASSWORD not in response.text
    assert "password_hash" not in response.text


def test_unknown_session_is_rejected(sandbox):
    client, _ = sandbox

    client.cookies.set(
        "payflow_session",
        generate_secure_token(),
        path="/",
    )

    response = client.get("/api/v1/auth/me")

    assert response.status_code == 401


def test_logout_revokes_session_and_clears_cookie(sandbox):
    client, connection = sandbox
    _, _, raw_token = sign_in(client, connection)

    assert client.get("/api/v1/auth/me").status_code == 200

    csrf_response = client.get("/api/v1/auth/csrf")
    assert csrf_response.status_code == 200
    response = client.post(
        "/api/v1/auth/logout",
        headers={
            "X-CSRF-Token": csrf_response.json()["token"]
        },
    )

    assert response.status_code == 200
    assert response.json() == {"status": "logged_out"}
    assert "max-age=0" in response.headers["set-cookie"].lower()

    with new_session(connection) as db:
        record = db.scalar(
            select(UserSession).where(
                UserSession.token_hash == hash_secure_token(raw_token)
            )
        )
        assert record.revoked_at is not None

    assert client.get("/api/v1/auth/me").status_code == 401


def test_logout_without_cookie_is_idempotent(sandbox):
    client, _ = sandbox

    first = client.post("/api/v1/auth/logout")
    second = client.post("/api/v1/auth/logout")

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json() == second.json()


def test_expired_session_is_rejected(sandbox):
    client, connection = sandbox
    _, _, raw_token = sign_in(client, connection)

    with new_session(connection) as db:
        with db.begin():
            record = db.scalar(
                select(UserSession).where(
                    UserSession.token_hash == hash_secure_token(raw_token)
                )
            )
            record.created_at = (
                datetime.now(timezone.utc) - timedelta(hours=10)
            )
            record.expires_at = (
                datetime.now(timezone.utc) - timedelta(hours=1)
            )

    assert client.get("/api/v1/auth/me").status_code == 401


def test_revoked_session_is_rejected(sandbox):
    client, connection = sandbox
    _, _, raw_token = sign_in(client, connection)

    with new_session(connection) as db:
        with db.begin():
            record = db.scalar(
                select(UserSession).where(
                    UserSession.token_hash == hash_secure_token(raw_token)
                )
            )
            record.revoked_at = datetime.now(timezone.utc)

    assert client.get("/api/v1/auth/me").status_code == 401


def test_inactive_user_session_is_rejected(sandbox):
    client, connection = sandbox
    user_id, _, _ = sign_in(client, connection)

    with new_session(connection) as db:
        with db.begin():
            user = db.get(User, user_id)
            user.is_active = False

    assert client.get("/api/v1/auth/me").status_code == 401


def test_unverified_user_session_is_rejected(sandbox):
    client, connection = sandbox
    user_id, _, _ = sign_in(client, connection)

    with new_session(connection) as db:
        with db.begin():
            user = db.get(User, user_id)
            user.email_verified_at = None

    assert client.get("/api/v1/auth/me").status_code == 401


def test_session_endpoints_disabled_outside_development(
    sandbox,
    monkeypatch,
):
    client, _ = sandbox

    monkeypatch.setattr(
        "app.api.session.get_settings",
        lambda: SimpleNamespace(app_env="production"),
    )

    assert client.get("/api/v1/auth/me").status_code == 503
    assert client.post("/api/v1/auth/logout").status_code == 503
