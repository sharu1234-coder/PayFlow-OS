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
from app.services.login_source_throttle import (
    ClientAddressUnavailable,
    LoginSourceRateLimited,
    SOURCE_ACTION,
    SOURCE_ATTEMPT_LIMIT,
    SOURCE_TYPE,
    enforce_login_source_limit,
    normalize_client_address,
    source_fingerprint,
)


PASSWORD = "PayFlow-Source-Test-Password-2026!"
WRONG = "Incorrect-Source-Test-Password!"


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


def make_user(connection):
    email = f"source-user-{uuid.uuid4().hex}@example.com"

    with new_session(connection) as db:
        with db.begin():
            db.add(
                User(
                    email=email,
                    password_hash=hash_password(PASSWORD),
                    display_name="Source Limit Test",
                    email_verified_at=datetime.now(timezone.utc),
                )
            )

    return email


def login(client, email, password=WRONG, headers=None):
    return client.post(
        "/api/v1/auth/login",
        json={
            "email": email,
            "password": password,
        },
        headers=headers or {},
    )


def source_attempt_count(
    connection,
    host="testclient",
    environment="development",
    recent_only=False,
):
    with new_session(connection) as db:
        statement = (
            select(func.count(AuditEvent.id))
            .where(
                AuditEvent.action == SOURCE_ACTION,
                AuditEvent.subject_type == SOURCE_TYPE,
                AuditEvent.subject_id
                == source_fingerprint(
                    host,
                    environment=environment,
                ),
            )
        )

        if recent_only:
            statement = statement.where(
                AuditEvent.created_at >= (
                    datetime.now(timezone.utc)
                    - timedelta(minutes=10)
                )
            )

        return db.scalar(statement)


def test_ipv4_source_normalization():
    assert normalize_client_address(
        "192.0.2.42",
        environment="production",
    ) == "192.0.2.42"


def test_ipv6_privacy_addresses_share_network_bucket():
    first = normalize_client_address(
        "2001:db8:abcd:1234::1",
        environment="production",
    )

    second = normalize_client_address(
        "2001:db8:abcd:1234::ffff",
        environment="production",
    )

    assert first == second
    assert first.endswith("/64")


@pytest.mark.parametrize(
    "host",
    [
        None,
        "testclient",
        "example.com",
        "999.999.999.999",
        "192.0.2.1,203.0.113.2",
    ],
)
def test_invalid_production_source_is_rejected(host):
    with pytest.raises(ClientAddressUnavailable):
        normalize_client_address(
            host,
            environment="production",
        )


def test_successful_login_records_source_attempt(sandbox):
    client, connection = sandbox
    email = make_user(connection)

    response = login(client, email, PASSWORD)

    assert response.status_code == 200
    assert source_attempt_count(connection) == 1


def test_failed_login_source_audit_excludes_raw_identity(sandbox):
    client, connection = sandbox
    email = make_user(connection)

    assert login(client, email).status_code == 401

    fingerprint = source_fingerprint(
        "testclient",
        environment="development",
    )

    with new_session(connection) as db:
        record = db.scalar(
            select(AuditEvent).where(
                AuditEvent.action == SOURCE_ACTION,
                AuditEvent.subject_id == fingerprint,
            )
        )

        assert record is not None
        assert len(record.subject_id) == 32
        assert record.actor_user_id is None
        assert record.organization_id is None
        assert email not in str(record.payload)
        assert WRONG not in str(record.payload)
        assert "testclient" not in str(record.payload)


def test_many_accounts_share_one_source_limit(sandbox):
    client, connection = sandbox
    legitimate_email = make_user(connection)

    # Each email is different, avoiding the per-email bucket.
    for _ in range(SOURCE_ATTEMPT_LIMIT):
        email = f"unknown-{uuid.uuid4().hex}@example.com"

        response = login(client, email)
        assert response.status_code == 401, response.text

    blocked = login(
        client,
        legitimate_email,
        PASSWORD,
    )

    assert blocked.status_code == 429
    assert blocked.headers["retry-after"] == "900"
    assert "set-cookie" not in blocked.headers

    assert source_attempt_count(connection) == SOURCE_ATTEMPT_LIMIT


def test_per_email_throttle_does_not_erase_source_audit(sandbox):
    client, connection = sandbox
    email = make_user(connection)

    for _ in range(5):
        assert login(client, email).status_code == 401

    assert login(client, email).status_code == 429

    # The sixth request must still count at source level.
    assert source_attempt_count(connection) == 6


def test_spoofed_forwarded_headers_do_not_change_bucket(sandbox):
    client, connection = sandbox

    first = login(
        client,
        f"one-{uuid.uuid4().hex}@example.com",
        headers={"X-Forwarded-For": "192.0.2.1"},
    )

    second = login(
        client,
        f"two-{uuid.uuid4().hex}@example.com",
        headers={"X-Forwarded-For": "203.0.113.99"},
    )

    assert first.status_code == 401
    assert second.status_code == 401
    assert source_attempt_count(connection) == 2


def test_old_source_records_do_not_trigger_lockout(sandbox):
    client, connection = sandbox
    email = make_user(connection)

    old_time = (
        datetime.now(timezone.utc)
        - timedelta(minutes=30)
    )

    fingerprint = source_fingerprint(
        "testclient",
        environment="development",
    )

    with new_session(connection) as db:
        with db.begin():
            for _ in range(SOURCE_ATTEMPT_LIMIT):
                db.add(
                    AuditEvent(
                        organization_id=None,
                        actor_user_id=None,
                        action=SOURCE_ACTION,
                        subject_type=SOURCE_TYPE,
                        subject_id=fingerprint,
                        payload={"event": "login_attempt"},
                        created_at=old_time,
                    )
                )

    assert login(client, email).status_code == 401
    assert source_attempt_count(
        connection,
        recent_only=True,
    ) == 1


def test_independent_source_addresses_have_separate_buckets(
    sandbox,
):
    _, connection = sandbox

    with new_session(connection) as db:
        with db.begin():
            for _ in range(SOURCE_ATTEMPT_LIMIT):
                enforce_login_source_limit(
                    db,
                    client_address="192.0.2.10",
                    environment="production",
                )

    with new_session(connection) as db:
        with pytest.raises(LoginSourceRateLimited):
            with db.begin():
                enforce_login_source_limit(
                    db,
                    client_address="192.0.2.10",
                    environment="production",
                )

    with new_session(connection) as db:
        with db.begin():
            enforce_login_source_limit(
                db,
                client_address="192.0.2.11",
                environment="production",
            )

    assert source_attempt_count(
        connection,
        host="192.0.2.10",
        environment="production",
    ) == SOURCE_ATTEMPT_LIMIT

    assert source_attempt_count(
        connection,
        host="192.0.2.11",
        environment="production",
    ) == 1


def test_source_attempt_rolls_back_on_transaction_failure(sandbox):
    _, connection = sandbox

    with pytest.raises(RuntimeError):
        with new_session(connection) as db:
            with db.begin():
                enforce_login_source_limit(
                    db,
                    client_address="203.0.113.17",
                    environment="production",
                )

                raise RuntimeError(
                    "Simulated transaction failure"
                )

    assert source_attempt_count(
        connection,
        host="203.0.113.17",
        environment="production",
    ) == 0
