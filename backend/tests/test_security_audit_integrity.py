import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.api.dependencies import get_db
from app.core.database import engine
from app.core.security import (
    hash_password,
    hash_secure_token,
)
from app.main import app
from app.models import AuditEvent, User, UserSession
from app.services.audit_integrity import (
    UnsafeAuditPayload,
    validate_audit_payload,
)
from app.services.login_throttle import login_fingerprint
from app.services.login_source_throttle import (
    SOURCE_ACTION,
    source_fingerprint,
)


PASSWORD = "PayFlow-Audit-Integration-Test-2026!"
WRONG_PASSWORD = "Wrong-Audit-Password-2026!"


def make_session(connection):
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
            with make_session(connection) as db:
                yield db

        app.dependency_overrides[get_db] = override_db

        try:
            with TestClient(app) as client:
                yield client, connection
        finally:
            app.dependency_overrides.pop(get_db, None)

            if outer.is_active:
                outer.rollback()


def create_verified_user(connection):
    email = f"audit-{uuid.uuid4().hex}@example.com"

    with make_session(connection) as db:
        with db.begin():
            user = User(
                email=email,
                password_hash=hash_password(PASSWORD),
                display_name="Security Audit Tester",
                email_verified_at=datetime.now(timezone.utc),
            )
            db.add(user)
            db.flush()
            user_id = user.id

    return user_id, email


def login(client, email, password=PASSWORD):
    return client.post(
        "/api/v1/auth/login",
        json={
            "email": email,
            "password": password,
        },
    )


def audit_records(
    connection,
    *,
    action,
    actor_id=None,
    subject_id=None,
):
    with make_session(connection) as db:
        statement = select(AuditEvent).where(
            AuditEvent.action == action
        )

        if actor_id is not None:
            statement = statement.where(
                AuditEvent.actor_user_id == actor_id
            )

        if subject_id is not None:
            statement = statement.where(
                AuditEvent.subject_id == subject_id
            )

        return db.scalars(statement).all()


def test_runtime_audit_privileges_are_append_only():
    with engine.connect() as conn:
        role = conn.execute(
            text("SELECT current_user")
        ).scalar_one()

        assert role == "payflow_runtime"

        for privilege in ("SELECT", "INSERT"):
            allowed = conn.execute(
                text("""
                    SELECT has_table_privilege(
                        current_user,
                        'payflow.audit_events',
                        :privilege
                    )
                """),
                {"privilege": privilege},
            ).scalar_one()

            assert allowed is True

        for privilege in ("UPDATE", "DELETE", "TRUNCATE"):
            allowed = conn.execute(
                text("""
                    SELECT has_table_privilege(
                        current_user,
                        'payflow.audit_events',
                        :privilege
                    )
                """),
                {"privilege": privilege},
            ).scalar_one()

            assert allowed is False


def test_runtime_cannot_create_schema_objects():
    with engine.connect() as conn:
        allowed = conn.execute(
            text("""
                SELECT has_schema_privilege(
                    current_user,
                    'payflow',
                    'CREATE'
                )
            """)
        ).scalar_one()

        assert allowed is False


def test_safe_nested_audit_payload_is_allowed():
    validate_audit_payload({
        "role": "finance",
        "result": "approved",
        "metadata": {
            "membership_id": str(uuid.uuid4()),
            "changes": [
                {"previous_role": "viewer"},
                {"new_role": "finance"},
            ],
        },
    })


@pytest.mark.parametrize(
    "payload",
    [
        {"password": "example"},
        {"metadata": {"raw_token": "example"}},
        {"token_hash": "example"},
        {"Authorization": "Bearer example"},
        {"api-key": "example"},
        {"client_ip": "192.0.2.1"},
    ],
)
def test_sensitive_audit_fields_are_rejected(payload):
    with pytest.raises(UnsafeAuditPayload):
        validate_audit_payload(payload)


def test_orm_rejects_sensitive_audit_event(sandbox):
    _, connection = sandbox

    with make_session(connection) as db:
        with pytest.raises(UnsafeAuditPayload):
            db.add(
                AuditEvent(
                    organization_id=None,
                    actor_user_id=None,
                    action="security.invalid_test",
                    subject_type="test",
                    subject_id=str(uuid.uuid4()),
                    payload={"raw_token": "must-not-be-stored"},
                )
            )
            db.flush()

    assert not audit_records(
        connection,
        action="security.invalid_test",
    )


def test_successful_login_creates_safe_audit_event(sandbox):
    client, connection = sandbox
    user_id, email = create_verified_user(connection)

    response = login(client, email)

    assert response.status_code == 200, response.text

    raw_token = response.cookies["payflow_session"]
    events = audit_records(
        connection,
        action="identity.login",
        actor_id=user_id,
    )

    assert len(events) == 1

    event = events[0]

    assert event.subject_type == "user"
    assert event.subject_id == str(user_id)
    assert event.organization_id is None

    assert raw_token not in str(event.payload)
    assert hash_secure_token(raw_token) not in str(
        event.payload
    )
    assert PASSWORD not in str(event.payload)

    validate_audit_payload(event.payload)


def test_failed_login_records_private_identifier(sandbox):
    client, connection = sandbox
    _, email = create_verified_user(connection)

    response = login(client, email, WRONG_PASSWORD)

    assert response.status_code == 401

    events = audit_records(
        connection,
        action="identity.login_failed",
        subject_id=login_fingerprint(email),
    )

    assert len(events) == 1

    event = events[0]

    assert event.actor_user_id is None
    assert event.organization_id is None
    assert event.subject_id != email

    assert email not in str(event.payload)
    assert WRONG_PASSWORD not in str(event.payload)

    validate_audit_payload(event.payload)


def test_unknown_user_failure_does_not_expose_email(sandbox):
    client, connection = sandbox
    email = f"unknown-{uuid.uuid4().hex}@example.com"

    response = login(client, email, WRONG_PASSWORD)

    assert response.status_code == 401

    events = audit_records(
        connection,
        action="identity.login_failed",
        subject_id=login_fingerprint(email),
    )

    assert len(events) == 1
    assert events[0].actor_user_id is None
    assert email not in str(events[0].payload)


def test_source_audit_contains_only_keyed_identifier(sandbox):
    client, connection = sandbox
    _, email = create_verified_user(connection)

    response = login(client, email, WRONG_PASSWORD)

    assert response.status_code == 401

    fingerprint = source_fingerprint(
        "testclient",
        environment="development",
    )

    records = audit_records(
        connection,
        action=SOURCE_ACTION,
        subject_id=fingerprint,
    )

    assert records

    event = records[-1]

    assert len(event.subject_id) == 32
    assert event.actor_user_id is None
    assert event.organization_id is None
    assert "testclient" not in str(event.payload)
    assert email not in str(event.payload)
    assert WRONG_PASSWORD not in str(event.payload)


def test_invalid_login_body_does_not_write_audit(sandbox):
    client, connection = sandbox

    fingerprint = source_fingerprint(
        "testclient",
        environment="development",
    )

    before = len(
        audit_records(
            connection,
            action=SOURCE_ACTION,
            subject_id=fingerprint,
        )
    )

    response = client.post(
        "/api/v1/auth/login",
        json={},
    )

    assert response.status_code == 422

    after = len(
        audit_records(
            connection,
            action=SOURCE_ACTION,
            subject_id=fingerprint,
        )
    )

    assert after == before


def test_csrf_failure_does_not_revoke_session(sandbox):
    client, connection = sandbox
    user_id, email = create_verified_user(connection)

    response = login(client, email)

    assert response.status_code == 200

    denied = client.post("/api/v1/auth/logout")

    assert denied.status_code == 403
    assert client.get("/api/v1/auth/me").status_code == 200

    events = audit_records(
        connection,
        action="identity.logout",
        actor_id=user_id,
    )

    assert events == []


def test_successful_logout_creates_audit_and_revokes_session(
    sandbox,
):
    client, connection = sandbox
    user_id, email = create_verified_user(connection)

    response = login(client, email)

    assert response.status_code == 200

    raw_token = response.cookies["payflow_session"]

    csrf = client.get("/api/v1/auth/csrf")

    assert csrf.status_code == 200

    logout = client.post(
        "/api/v1/auth/logout",
        headers={
            "X-CSRF-Token": csrf.json()["token"],
        },
    )

    assert logout.status_code == 200
    assert logout.json()["status"] == "logged_out"

    events = audit_records(
        connection,
        action="identity.logout",
        actor_id=user_id,
    )

    assert len(events) == 1
    assert events[0].subject_id == str(user_id)
    assert events[0].payload == {
        "result": "session_revoked"
    }

    assert raw_token not in str(events[0].payload)

    with make_session(connection) as db:
        session = db.scalar(
            select(UserSession).where(
                UserSession.token_hash
                == hash_secure_token(raw_token)
            )
        )

        assert session is not None
        assert session.revoked_at is not None


def test_repeated_logout_does_not_duplicate_audit(sandbox):
    client, connection = sandbox
    user_id, email = create_verified_user(connection)

    assert login(client, email).status_code == 200

    csrf = client.get("/api/v1/auth/csrf")

    assert csrf.status_code == 200

    first = client.post(
        "/api/v1/auth/logout",
        headers={
            "X-CSRF-Token": csrf.json()["token"],
        },
    )

    second = client.post("/api/v1/auth/logout")

    assert first.status_code == 200
    assert second.status_code == 200

    assert len(
        audit_records(
            connection,
            action="identity.logout",
            actor_id=user_id,
        )
    ) == 1
