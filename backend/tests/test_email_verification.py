import secrets
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.core.database import engine
from app.core.security import hash_secure_token
from app.models import (
    AuthToken,
    Organization,
    OrganizationMembership,
    User,
)
from app.services.email_verification import (
    consume_email_verification,
    issue_email_verification,
)


@pytest.fixture
def db_connection():
    with engine.connect() as connection:
        outer_transaction = connection.begin()

        try:
            yield connection
        finally:
            if outer_transaction.is_active:
                outer_transaction.rollback()


def new_session(connection):
    return Session(
        bind=connection,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    )


@pytest.fixture
def seeded_identity(db_connection):
    with new_session(db_connection) as db:
        with db.begin():
            user = User(
                email=f"verify-{uuid.uuid4().hex}@example.com",
                password_hash="isolated-test-hash",
                display_name="Verification Test",
            )
            db.add(user)
            db.flush()

            organization = Organization(
                name="Verification Test Company",
                slug=f"verify-{secrets.token_hex(10)}",
            )
            db.add(organization)
            db.flush()

            membership = OrganizationMembership(
                organization_id=organization.id,
                user_id=user.id,
                role="owner",
                status="invited",
            )
            db.add(membership)

        return user.id, organization.id


def create_token(connection, user_id):
    with new_session(connection) as db:
        with db.begin():
            return issue_email_verification(db, user_id)


def consume_token(connection, raw_token):
    with new_session(connection) as db:
        with db.begin():
            return consume_email_verification(db, raw_token)


def test_verification_token_is_stored_as_digest(
    db_connection,
    seeded_identity,
):
    user_id, _ = seeded_identity
    raw = create_token(db_connection, user_id)

    with new_session(db_connection) as db:
        record = db.scalar(
            select(AuthToken)
            .where(AuthToken.user_id == user_id)
        )

        assert record is not None
        assert record.purpose == "email_verification"
        assert record.token_hash == hash_secure_token(raw)
        assert record.token_hash != raw
        assert record.consumed_at is None
        assert record.expires_at > datetime.now(timezone.utc)


def test_email_verification_is_single_use(
    db_connection,
    seeded_identity,
):
    user_id, organization_id = seeded_identity
    raw = create_token(db_connection, user_id)

    assert consume_token(db_connection, raw) is True
    assert consume_token(db_connection, raw) is False

    with new_session(db_connection) as db:
        user = db.get(User, user_id)

        assert user.email_verified_at is not None

        record = db.scalar(
            select(AuthToken)
            .where(AuthToken.user_id == user_id)
        )
        assert record.consumed_at is not None

        membership = db.scalar(
            select(OrganizationMembership)
            .where(
                OrganizationMembership.user_id == user_id,
                OrganizationMembership.organization_id == organization_id,
            )
        )
        assert membership.status == "active"

        audit_count = db.execute(
            text("""
                SELECT count(*)
                FROM payflow.audit_events
                WHERE actor_user_id = :user_id
                AND action = 'identity.email_verified'
            """),
            {"user_id": user_id},
        ).scalar_one()

        assert audit_count == 1


def test_invalid_token_does_not_verify_user(
    db_connection,
    seeded_identity,
):
    user_id, _ = seeded_identity

    assert consume_token(
        db_connection,
        "invalid-verification-token",
    ) is False

    with new_session(db_connection) as db:
        assert db.get(User, user_id).email_verified_at is None


def test_expired_token_cannot_be_used(
    db_connection,
    seeded_identity,
):
    user_id, _ = seeded_identity
    raw = create_token(db_connection, user_id)

    with new_session(db_connection) as db:
        with db.begin():
            record = db.scalar(
                select(AuthToken).where(
                    AuthToken.token_hash == hash_secure_token(raw)
                )
            )

            record.created_at = (
                datetime.now(timezone.utc) - timedelta(days=3)
            )
            record.expires_at = (
                datetime.now(timezone.utc) - timedelta(days=2)
            )

    assert consume_token(db_connection, raw) is False

    with new_session(db_connection) as db:
        assert db.get(User, user_id).email_verified_at is None


def test_rolled_back_token_is_not_persisted(
    db_connection,
    seeded_identity,
):
    user_id, _ = seeded_identity
    raw = None

    with new_session(db_connection) as db:
        with pytest.raises(RuntimeError):
            with db.begin():
                raw = issue_email_verification(db, user_id)
                raise RuntimeError("Simulated transaction failure")

    with new_session(db_connection) as db:
        record = db.scalar(
            select(AuthToken).where(
                AuthToken.token_hash == hash_secure_token(raw)
            )
        )

        assert record is None

    assert consume_token(db_connection, raw) is False