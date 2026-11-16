import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.dependencies import get_db
from app.core.database import engine
from app.core.security import (
    generate_secure_token,
    hash_secure_token,
)
from app.main import app
from app.models import AuthToken, User
from app.services.email_delivery import get_verification_sender


class FakeSender:
    def __init__(self):
        self.sent = []
        self.fail = False

    def send_verification(self, recipient, token):
        if self.fail:
            raise OSError("Simulated email failure")

        self.sent.append((recipient, token))


@pytest.fixture
def sandbox():
    sender = FakeSender()

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
        app.dependency_overrides[get_verification_sender] = (
            lambda: sender
        )

        try:
            with TestClient(app) as client:
                yield client, connection, sender
        finally:
            app.dependency_overrides.pop(get_db, None)
            app.dependency_overrides.pop(
                get_verification_sender, None
            )

            if outer.is_active:
                outer.rollback()


def new_session(connection):
    return Session(
        bind=connection,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    )


def make_user(connection, verified=False):
    email = f"resend-{uuid.uuid4().hex}@example.com"

    with new_session(connection) as db:
        with db.begin():
            user = User(
                email=email,
                password_hash="isolated-test-hash",
                display_name="Resend Test",
            )

            if verified:
                user.email_verified_at = (
                    datetime.now(timezone.utc)
                )

            db.add(user)
            db.flush()
            user_id = user.id

    return user_id, email


def resend(client, email):
    return client.post(
        "/api/v1/auth/resend-verification",
        json={"email": email},
    )


def token_count(connection, user_id):
    with new_session(connection) as db:
        return db.scalar(
            select(func.count(AuthToken.id))
            .where(AuthToken.user_id == user_id)
        )


def test_resend_creates_hashed_token_and_sends(sandbox):
    client, connection, sender = sandbox
    user_id, email = make_user(connection)

    response = resend(client, email)

    assert response.status_code == 202
    assert response.json() == {"status": "accepted"}
    assert len(sender.sent) == 1

    recipient, raw_token = sender.sent[0]
    assert recipient == email
    assert raw_token not in response.text

    with new_session(connection) as db:
        record = db.scalar(
            select(AuthToken).where(
                AuthToken.user_id == user_id
            )
        )

        assert record is not None
        assert record.token_hash == hash_secure_token(raw_token)

    verification = client.post(
        "/api/v1/auth/verify-email",
        json={"token": raw_token},
    )

    assert verification.status_code == 200


def test_unknown_account_gets_generic_response(sandbox):
    client, _, sender = sandbox

    response = resend(
        client, f"unknown-{uuid.uuid4().hex}@example.com"
    )

    assert response.status_code == 202
    assert response.json() == {"status": "accepted"}
    assert sender.sent == []


def test_verified_account_cannot_request_new_token(sandbox):
    client, connection, sender = sandbox
    user_id, email = make_user(connection, verified=True)

    response = resend(client, email)

    assert response.status_code == 202
    assert response.json() == {"status": "accepted"}
    assert sender.sent == []
    assert token_count(connection, user_id) == 0


def test_immediate_resend_is_rate_limited(sandbox):
    client, connection, sender = sandbox
    user_id, email = make_user(connection)

    first = resend(client, email)
    second = resend(client, email)

    assert first.status_code == 202
    assert second.status_code == 202
    assert first.json() == second.json()
    assert len(sender.sent) == 1
    assert token_count(connection, user_id) == 1


def test_daily_token_limit(sandbox):
    client, connection, sender = sandbox
    user_id, email = make_user(connection)

    now = datetime.now(timezone.utc)

    with new_session(connection) as db:
        with db.begin():
            for _ in range(5):
                db.add(
                    AuthToken(
                        user_id=user_id,
                        purpose="email_verification",
                        token_hash=hash_secure_token(
                            generate_secure_token()
                        ),
                        created_at=now - timedelta(minutes=3),
                        expires_at=now + timedelta(hours=24),
                    )
                )

    response = resend(client, email)

    assert response.status_code == 202
    assert sender.sent == []
    assert token_count(connection, user_id) == 5


def test_delivery_failure_can_be_retried_after_cooldown(
    sandbox,
):
    client, connection, sender = sandbox
    user_id, email = make_user(connection)

    sender.fail = True
    first = resend(client, email)

    assert first.status_code == 202
    assert first.json() == {"status": "accepted"}
    assert token_count(connection, user_id) == 1

    # Simulate the cooldown elapsing without sleeping.
    with new_session(connection) as db:
        with db.begin():
            record = db.scalar(
                select(AuthToken).where(
                    AuthToken.user_id == user_id
                )
            )
            record.created_at = (
                datetime.now(timezone.utc)
                - timedelta(minutes=3)
            )

    sender.fail = False
    second = resend(client, email)

    assert second.status_code == 202
    assert len(sender.sent) == 1
    assert token_count(connection, user_id) == 2


def test_unconfigured_sender_issues_no_token(sandbox):
    client, connection, sender = sandbox
    user_id, email = make_user(connection)

    app.dependency_overrides[get_verification_sender] = (
        lambda: None
    )

    response = resend(client, email)

    assert response.status_code == 202
    assert response.json() == {"status": "accepted"}
    assert sender.sent == []
    assert token_count(connection, user_id) == 0


def test_invalid_email_is_rejected(sandbox):
    client, _, _ = sandbox

    response = resend(client, "not-an-email")

    assert response.status_code == 422


def test_resend_disabled_in_production(sandbox, monkeypatch):
    client, _, sender = sandbox

    monkeypatch.setattr(
        "app.api.auth.get_settings",
        lambda: SimpleNamespace(app_env="production"),
    )

    response = resend(
        client, f"prod-{uuid.uuid4().hex}@example.com"
    )

    assert response.status_code == 503
    assert sender.sent == []
