import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.dependencies import get_db
from app.core.database import engine
from app.core.security import hash_password
from app.main import app
from app.models import AuditEvent, User
from app.services.login_throttle import (
    FAILED_ACTION,
    FAILED_SUBJECT_TYPE,
    login_fingerprint,
)


PASSWORD = "PayFlow-Throttle-Test-2026!"
WRONG_PASSWORD = "Incorrect-Password-2026!"


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

        def override_db():
            with new_session(connection) as db:
                yield db

        app.dependency_overrides[get_db] = override_db

        try:
            with TestClient(app) as client:
                yield client, connection
        finally:
            app.dependency_overrides.pop(get_db, None)

            if outer.is_active:
                outer.rollback()


def create_user(connection, verified=True):
    email = f"throttle-{uuid.uuid4().hex}@example.com"

    with new_session(connection) as db:
        with db.begin():
            db.add(
                User(
                    email=email,
                    password_hash=hash_password(PASSWORD),
                    display_name="Throttle Test User",
                    email_verified_at=(
                        datetime.now(timezone.utc)
                        if verified else None
                    ),
                )
            )

    return email


def login(client, email, password=WRONG_PASSWORD):
    return client.post(
        "/api/v1/auth/login",
        json={
            "email": email,
            "password": password,
        },
    )


def failure_count(connection, email):
    with new_session(connection) as db:
        return db.scalar(
            select(func.count(AuditEvent.id))
            .where(
                AuditEvent.action == FAILED_ACTION,
                AuditEvent.subject_type == FAILED_SUBJECT_TYPE,
                AuditEvent.subject_id
                == login_fingerprint(email),
            )
        )


def test_correct_password_still_logs_in(sandbox):
    client, connection = sandbox
    email = create_user(connection)

    response = login(client, email, PASSWORD)

    assert response.status_code == 200
    assert "payflow_session" in response.cookies
    assert failure_count(connection, email) == 0


def test_sixth_failed_login_is_throttled(sandbox):
    client, connection = sandbox
    email = create_user(connection)

    for _ in range(5):
        response = login(client, email)
        assert response.status_code == 401

    blocked = login(client, email)

    assert blocked.status_code == 429
    assert blocked.headers["retry-after"] == "900"
    assert "set-cookie" not in blocked.headers
    assert failure_count(connection, email) == 5


def test_unknown_email_receives_same_throttle(sandbox):
    client, connection = sandbox
    email = f"unknown-{uuid.uuid4().hex}@example.com"

    for _ in range(5):
        assert login(client, email).status_code == 401

    response = login(client, email)

    assert response.status_code == 429
    assert failure_count(connection, email) == 5


def test_correct_password_cannot_bypass_lockout(sandbox):
    client, connection = sandbox
    email = create_user(connection)

    for _ in range(5):
        assert login(client, email).status_code == 401

    response = login(client, email, PASSWORD)

    assert response.status_code == 429
    assert "set-cookie" not in response.headers


def test_email_case_does_not_reset_attempts(sandbox):
    client, connection = sandbox
    email = create_user(connection)

    for _ in range(3):
        assert login(client, email.upper()).status_code == 401

    for _ in range(2):
        assert login(client, email).status_code == 401

    assert login(client, email.upper()).status_code == 429
    assert failure_count(connection, email) == 5


def test_one_identifier_does_not_block_another(sandbox):
    client, connection = sandbox
    first = create_user(connection)
    second = create_user(connection)

    for _ in range(5):
        assert login(client, first).status_code == 401

    assert login(client, first).status_code == 429

    response = login(client, second, PASSWORD)

    assert response.status_code == 200


def test_failure_audit_contains_no_plain_credentials(sandbox):
    client, connection = sandbox
    email = create_user(connection)

    assert login(client, email).status_code == 401

    with new_session(connection) as db:
        record = db.scalar(
            select(AuditEvent)
            .where(
                AuditEvent.action == FAILED_ACTION,
                AuditEvent.subject_id
                == login_fingerprint(email),
            )
        )

        assert record is not None
        assert len(record.subject_id) == 32
        assert record.subject_id != email
        assert record.actor_user_id is None
        assert record.organization_id is None
        assert email not in str(record.payload)
        assert WRONG_PASSWORD not in str(record.payload)
        assert "password" not in record.payload


def test_old_failures_are_outside_sliding_window(sandbox):
    client, connection = sandbox
    email = create_user(connection)

    old_time = (
        datetime.now(timezone.utc)
        - timedelta(minutes=30)
    )

    with new_session(connection) as db:
        with db.begin():
            for _ in range(5):
                db.add(
                    AuditEvent(
                        organization_id=None,
                        actor_user_id=None,
                        action=FAILED_ACTION,
                        subject_type=FAILED_SUBJECT_TYPE,
                        subject_id=login_fingerprint(email),
                        payload={"result": "authentication_failed"},
                        created_at=old_time,
                    )
                )

    # Expired attempts should not trigger a lockout.
    assert login(client, email).status_code == 401


def test_unverified_user_attempts_are_throttled(sandbox):
    client, connection = sandbox
    email = create_user(connection, verified=False)

    for _ in range(5):
        assert login(client, email, PASSWORD).status_code == 401

    assert login(client, email, PASSWORD).status_code == 429


def test_throttled_requests_do_not_append_failures(sandbox):
    client, connection = sandbox
    email = create_user(connection)

    for _ in range(5):
        assert login(client, email).status_code == 401

    before = failure_count(connection, email)

    for _ in range(2):
        assert login(client, email).status_code == 429

    assert before == 5
    assert failure_count(connection, email) == before
