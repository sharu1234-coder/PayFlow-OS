import secrets
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.dependencies import get_db
from app.core.database import engine
from app.core.security import hash_secure_token
from app.main import app
from app.models import AuthToken, User
from app.services.email_delivery import (
    SmtpVerificationEmailSender,
    get_verification_sender,
)


class FakeSender:
    def __init__(self):
        self.sent = []
        self.fail = False

    def send_verification(self, recipient, token):
        self.sent.append((recipient, token))

        if self.fail:
            raise OSError("Simulated delivery failure")


@pytest.fixture
def registration_with_email():
    sender = FakeSender()

    with engine.connect() as connection:
        transaction = connection.begin()

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

            if transaction.is_active:
                transaction.rollback()


def payload():
    return {
        "email": f"email-{uuid.uuid4().hex}@example.com",
        "password": "Local-Testing-Password-2026!",
        "display_name": "Email Test User",
        "business_name": "Email Test Business",
    }


def test_registration_issues_and_sends_verification(
    registration_with_email,
):
    client, connection, sender = registration_with_email
    data = payload()

    response = client.post(
        "/api/v1/auth/register", json=data
    )

    assert response.status_code == 201, response.text
    assert response.json()["verification_delivery"] == "sent"
    assert len(sender.sent) == 1

    recipient, token = sender.sent[0]

    assert recipient == data["email"]
    assert token not in response.text

    with Session(bind=connection) as db:
        user = db.scalar(
            select(User).where(User.email == data["email"])
        )

        assert user is not None
        assert user.email_verified_at is None

        record = db.scalar(
            select(AuthToken).where(
                AuthToken.user_id == user.id
            )
        )

        assert record is not None
        assert record.token_hash == hash_secure_token(token)
        assert record.token_hash != token

    verify_response = client.post(
        "/api/v1/auth/verify-email",
        json={"token": token},
    )

    assert verify_response.status_code == 200
    assert verify_response.json() == {"status": "verified"}


def test_duplicate_registration_does_not_send_again(
    registration_with_email,
):
    client, _, sender = registration_with_email
    data = payload()

    assert client.post(
        "/api/v1/auth/register", json=data
    ).status_code == 201

    assert client.post(
        "/api/v1/auth/register", json=data
    ).status_code == 409

    assert len(sender.sent) == 1


def test_delivery_failure_keeps_account_unverified(
    registration_with_email,
):
    client, connection, sender = registration_with_email
    sender.fail = True
    data = payload()

    response = client.post(
        "/api/v1/auth/register", json=data
    )

    assert response.status_code == 201
    assert response.json()["verification_delivery"] == "failed"

    with Session(bind=connection) as db:
        user = db.scalar(
            select(User).where(User.email == data["email"])
        )

        assert user is not None
        assert user.email_verified_at is None


def test_unconfigured_delivery_issues_no_token(
    registration_with_email,
):
    client, connection, sender = registration_with_email

    app.dependency_overrides[get_verification_sender] = (
        lambda: None
    )

    data = payload()

    response = client.post(
        "/api/v1/auth/register", json=data
    )

    assert response.status_code == 201
    assert response.json()["verification_delivery"] == (
        "not_configured"
    )
    assert sender.sent == []

    with Session(bind=connection) as db:
        user = db.scalar(
            select(User).where(User.email == data["email"])
        )

        token_count = db.query(AuthToken).filter(
            AuthToken.user_id == user.id
        ).count()

        assert token_count == 0


def test_smtp_sender_requires_encrypted_connection(monkeypatch):
    events = []

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            assert host == "smtp.example.test"
            assert port == 587
            events.append("connected")

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def ehlo(self):
            events.append("ehlo")

        def has_extn(self, extension):
            assert extension == "starttls"
            return True

        def starttls(self, context):
            assert context is not None
            events.append("tls")

        def login(self, username, password):
            assert username == "test-user"
            assert password == "test-password"
            events.append("authenticated")

        def send_message(self, message):
            assert message["To"] == "merchant@example.com"
            assert "test-token" in message.get_content()
            events.append("sent")

    monkeypatch.setattr(
        "app.services.email_delivery.smtplib.SMTP",
        FakeSMTP,
    )

    sender = SmtpVerificationEmailSender(
        host="smtp.example.test",
        port=587,
        username="test-user",
        password="test-password",
        from_email="noreply@example.test",
    )

    sender.send_verification(
        "merchant@example.com",
        "test-token",
    )

    assert events.index("tls") < events.index("authenticated")
    assert events.index("authenticated") < events.index("sent")
