import re
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
from app.models import User


PASSWORD = "PayFlow-CSRF-Test-Password-2026!"


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


def sign_in(client, connection):
    email = f"csrf-{uuid.uuid4().hex}@example.com"

    with Session(
        bind=connection,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    ) as db:
        with db.begin():
            db.add(
                User(
                    email=email,
                    password_hash=hash_password(PASSWORD),
                    display_name="CSRF Test User",
                    email_verified_at=datetime.now(timezone.utc),
                )
            )

    response = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": PASSWORD},
    )

    assert response.status_code == 200, response.text

    return response.cookies["payflow_session"]


def get_token(client):
    response = client.get("/api/v1/auth/csrf")
    assert response.status_code == 200, response.text
    return response.json()["token"]


def test_csrf_requires_authentication(sandbox):
    client, _ = sandbox

    response = client.get("/api/v1/auth/csrf")

    assert response.status_code == 401


def test_csrf_token_is_session_specific_and_not_cached(sandbox):
    client, connection = sandbox
    raw_session = sign_in(client, connection)

    first = client.get("/api/v1/auth/csrf")
    second = client.get("/api/v1/auth/csrf")

    assert first.status_code == 200
    assert second.status_code == 200

    token = first.json()["token"]

    assert re.fullmatch(r"[0-9a-f]{64}", token)
    assert token == second.json()["token"]
    assert token != raw_session
    assert raw_session not in first.text
    assert first.headers["cache-control"] == "no-store"


def test_logout_without_csrf_header_is_rejected(sandbox):
    client, connection = sandbox
    sign_in(client, connection)

    response = client.post("/api/v1/auth/logout")

    assert response.status_code == 403
    assert client.get("/api/v1/auth/me").status_code == 200


def test_logout_with_invalid_csrf_is_rejected(sandbox):
    client, connection = sandbox
    sign_in(client, connection)

    response = client.post(
        "/api/v1/auth/logout",
        headers={"X-CSRF-Token": "0" * 64},
    )

    assert response.status_code == 403
    assert client.get("/api/v1/auth/me").status_code == 200


def test_csrf_from_another_session_is_rejected(sandbox):
    client, connection = sandbox

    sign_in(client, connection)
    first_token = get_token(client)

    sign_in(client, connection)
    second_token = get_token(client)

    assert first_token != second_token

    response = client.post(
        "/api/v1/auth/logout",
        headers={"X-CSRF-Token": first_token},
    )

    assert response.status_code == 403
    assert client.get("/api/v1/auth/me").status_code == 200


def test_valid_csrf_allows_logout(sandbox):
    client, connection = sandbox
    sign_in(client, connection)

    token = get_token(client)

    response = client.post(
        "/api/v1/auth/logout",
        headers={"X-CSRF-Token": token},
    )

    assert response.status_code == 200
    assert response.json() == {"status": "logged_out"}
    assert client.get("/api/v1/auth/me").status_code == 401


def test_csrf_endpoint_disabled_outside_development(
    sandbox,
    monkeypatch,
):
    client, _ = sandbox

    monkeypatch.setattr(
        "app.api.session.get_settings",
        lambda: SimpleNamespace(app_env="production"),
    )

    response = client.get("/api/v1/auth/csrf")

    assert response.status_code == 503
