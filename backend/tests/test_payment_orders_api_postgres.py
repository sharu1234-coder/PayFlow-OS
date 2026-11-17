"""Rollback-isolated HTTP integration tests for payment orders.

These tests require PAYFLOW_HTTP_TEST_DB to name the approved
disposable database. They must never use the original payflow_db.

Only get_db is overridden, to connect FastAPI to the disposable
database. Cookie authentication, CSRF, authorization and payment
services execute normally.

Fixture INSERT privileges must be granted temporarily and revoked
after the targeted integration-test invocation.
"""

import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.api.dependencies import get_db
from app.core.config import get_settings
from app.core.security import hash_secure_token
from app.main import app
from app.models import (
    MerchantProfile,
    Organization,
    OrganizationMembership,
    User,
    UserSession,
)
from app.models.payments import (
    PaymentIdempotencyRecord,
    PaymentOrder,
)


TARGET_DB = (
    "payflow_payment_drill_20261117_020846_9fbac781"
)

pytestmark = pytest.mark.skipif(
    not os.environ.get("PAYFLOW_HTTP_TEST_DB"),
    reason="Requires explicit disposable PostgreSQL test database",
)

BASE_PAYLOAD = {
    "merchant_order_reference": "api-http-001",
    "amount_minor_units": 12500,
    "currency": "INR",
}

KEY = "PAYFLOW_HTTP_IDEM_2026_001"


def session_for(connection):
    return Session(
        bind=connection,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    )


def counts(connection, organization_id):
    with session_for(connection) as db:
        orders = db.scalar(
            select(func.count())
            .select_from(PaymentOrder)
            .where(
                PaymentOrder.organization_id
                == organization_id
            )
        )

        records = db.scalar(
            select(func.count())
            .select_from(PaymentIdempotencyRecord)
            .where(
                PaymentIdempotencyRecord.organization_id
                == organization_id
            )
        )

    return orders, records


@pytest.fixture
def sandbox():
    settings = get_settings()
    url = make_url(settings.database_url)

    requested = os.environ.get("PAYFLOW_HTTP_TEST_DB")

    if requested != TARGET_DB:
        raise RuntimeError(
            "Only the approved disposable DB is allowed"
        )

    if settings.app_env != "development":
        raise RuntimeError("Development mode is required")

    if url.database != "payflow_db":
        raise RuntimeError(
            "Expected original configuration was not found"
        )

    if url.username != "payflow_runtime":
        raise RuntimeError("Unexpected runtime DB role")

    if url.host not in ("localhost", "127.0.0.1"):
        raise RuntimeError("Remote database is prohibited")

    if url.port not in (None, 5432):
        raise RuntimeError("Unexpected PostgreSQL port")

    engine = create_engine(
        url.set(database=TARGET_DB),
        poolclass=NullPool,
        connect_args={"connect_timeout": 5},
    )

    original_overrides = dict(app.dependency_overrides)

    try:
        with engine.connect() as connection:
            outer = connection.begin()

            try:
                identity = connection.execute(
                    text("""
                        SELECT
                            current_database(),
                            current_user
                    """)
                ).one()

                if identity != (TARGET_DB, "payflow_runtime"):
                    raise RuntimeError(
                        "Test connection identity mismatch"
                    )

                # Fail closed if prior synthetic records remain.
                for table in (
                    "users",
                    "user_sessions",
                    "organizations",
                    "organization_memberships",
                    "merchant_profiles",
                    "payment_orders",
                    "payment_idempotency_records",
                ):
                    existing = connection.exec_driver_sql(
                        f"SELECT COUNT(*) FROM payflow.{table}"
                    ).scalar_one()

                    if existing != 0:
                        raise RuntimeError(
                            f"Disposable table is not empty: {table}"
                        )

                actors = {}
                tokens = {}

                with session_for(connection) as db:
                    with db.begin():
                        for role in (
                            "owner",
                            "admin",
                            "developer",
                            "finance",
                            "viewer",
                            "revoked",
                            "foreign",
                        ):
                            actor = User(
                                email=(
                                    "api-http-"
                                    + role
                                    + "-"
                                    + uuid.uuid4().hex
                                    + "@example.com"
                                ),
                                password_hash=(
                                    "!integration-login-disabled!"
                                ),
                                display_name=(
                                    "HTTP Test " + role
                                ),
                                is_active=True,
                                email_verified_at=(
                                    datetime.now(timezone.utc)
                                ),
                            )

                            db.add(actor)
                            actors[role] = actor

                        db.flush()

                        org_a = Organization(
                            name="HTTP Integration Alpha",
                            slug=(
                                "http-alpha-"
                                + uuid.uuid4().hex[:16]
                            ),
                            status="active",
                        )

                        org_b = Organization(
                            name="HTTP Integration Beta",
                            slug=(
                                "http-beta-"
                                + uuid.uuid4().hex[:16]
                            ),
                            status="active",
                        )

                        db.add_all([org_a, org_b])
                        db.flush()

                        db.add_all([
                            MerchantProfile(
                                organization_id=org_a.id,
                                business_name="Test Alpha",
                                onboarding_status="approved",
                            ),
                            MerchantProfile(
                                organization_id=org_b.id,
                                business_name="Test Beta",
                                onboarding_status="approved",
                            ),
                        ])

                        for role in (
                            "owner",
                            "admin",
                            "developer",
                            "finance",
                            "viewer",
                        ):
                            db.add(
                                OrganizationMembership(
                                    organization_id=org_a.id,
                                    user_id=actors[role].id,
                                    role=role,
                                    status="active",
                                )
                            )

                        db.add(
                            OrganizationMembership(
                                organization_id=org_a.id,
                                user_id=actors["revoked"].id,
                                role="owner",
                                status="revoked",
                            )
                        )

                        db.add(
                            OrganizationMembership(
                                organization_id=org_b.id,
                                user_id=actors["foreign"].id,
                                role="owner",
                                status="active",
                            )
                        )

                        for role, actor in actors.items():
                            token = secrets.token_urlsafe(40)
                            tokens[role] = token

                            db.add(
                                UserSession(
                                    user_id=actor.id,
                                    token_hash=(
                                        hash_secure_token(token)
                                    ),
                                    expires_at=(
                                        datetime.now(timezone.utc)
                                        + timedelta(hours=1)
                                    ),
                                )
                            )

                        db.flush()

                        org_ids = {
                            "a": org_a.id,
                            "b": org_b.id,
                        }

                # Override only the database connection.
                # Auth, CSRF and RBAC remain real.
                def override_db():
                    with session_for(connection) as db:
                        yield db

                app.dependency_overrides[get_db] = override_db

                with TestClient(app) as client:
                    yield {
                        "client": client,
                        "connection": connection,
                        "organizations": org_ids,
                        "tokens": tokens,
                    }

            finally:
                app.dependency_overrides.clear()
                app.dependency_overrides.update(
                    original_overrides
                )

                if outer.is_active:
                    outer.rollback()

    finally:
        engine.dispose()


def cookie_headers(sandbox, role):
    return {
        "Cookie": (
            "payflow_session="
            + sandbox["tokens"][role]
        )
    }


def csrf_headers(sandbox, role, *, key=KEY):
    headers = cookie_headers(sandbox, role)

    response = sandbox["client"].get(
        "/api/v1/auth/csrf",
        headers=headers,
    )

    assert response.status_code == 200, response.text

    headers["X-CSRF-Token"] = response.json()["token"]
    headers["Idempotency-Key"] = key

    return headers


def order_path(sandbox, *, tenant="a"):
    organization_id = sandbox["organizations"][tenant]

    return (
        f"/api/v1/organizations/"
        f"{organization_id}/payment-orders"
    )


def create(sandbox, role="owner", *, payload=None, key=KEY,
           tenant="a"):
    return sandbox["client"].post(
        order_path(sandbox, tenant=tenant),
        headers=csrf_headers(sandbox, role, key=key),
        json=BASE_PAYLOAD if payload is None else payload,
    )


def count_for(sandbox, tenant="a"):
    return counts(
        sandbox["connection"],
        sandbox["organizations"][tenant],
    )


def test_missing_cookie_rejected_on_both_methods(sandbox):
    client = sandbox["client"]
    path = order_path(sandbox)

    post = client.post(
        path,
        json=BASE_PAYLOAD,
        headers={"Idempotency-Key": KEY},
    )

    get = client.get(
        path + "/" + str(uuid.uuid4())
    )

    assert post.status_code == 401
    assert get.status_code == 401
    assert count_for(sandbox) == (0, 0)


def test_real_cookie_identity_and_csrf_endpoint(sandbox):
    client = sandbox["client"]
    headers = cookie_headers(sandbox, "owner")

    me = client.get(
        "/api/v1/auth/me",
        headers=headers,
    )

    csrf = client.get(
        "/api/v1/auth/csrf",
        headers=headers,
    )

    assert me.status_code == 200
    assert csrf.status_code == 200
    assert len(csrf.json()["token"]) == 64
    assert csrf.headers["cache-control"] == "no-store"


@pytest.mark.parametrize(
    "csrf_header",
    [
        None,
        "0" * 64,
    ],
)
def test_missing_or_invalid_csrf_prevents_mutation(
    sandbox,
    csrf_header,
):
    headers = cookie_headers(sandbox, "owner")
    headers["Idempotency-Key"] = KEY

    if csrf_header is not None:
        headers["X-CSRF-Token"] = csrf_header

    response = sandbox["client"].post(
        order_path(sandbox),
        json=BASE_PAYLOAD,
        headers=headers,
    )

    assert response.status_code == 403
    assert count_for(sandbox) == (0, 0)


def test_csrf_from_different_session_is_rejected(sandbox):
    foreign_csrf = sandbox["client"].get(
        "/api/v1/auth/csrf",
        headers=cookie_headers(sandbox, "foreign"),
    )

    assert foreign_csrf.status_code == 200

    headers = cookie_headers(sandbox, "owner")
    headers["Idempotency-Key"] = KEY
    headers["X-CSRF-Token"] = (
        foreign_csrf.json()["token"]
    )

    response = sandbox["client"].post(
        order_path(sandbox),
        json=BASE_PAYLOAD,
        headers=headers,
    )

    assert response.status_code == 403
    assert count_for(sandbox) == (0, 0)


@pytest.mark.parametrize("role", ["owner", "admin"])
def test_authorized_roles_create_real_order(sandbox, role):
    response = create(sandbox, role)

    assert response.status_code == 201, response.text
    assert response.json()["organization_id"] == str(
        sandbox["organizations"]["a"]
    )
    assert response.json()["replayed"] is False
    assert response.json()["status"] == "open"
    assert response.headers["cache-control"] == "no-store"
    assert count_for(sandbox) == (1, 1)


@pytest.mark.parametrize(
    "role",
    ["developer", "finance", "viewer"],
)
def test_read_only_roles_cannot_create(sandbox, role):
    response = create(sandbox, role)

    assert response.status_code == 403, response.text
    assert count_for(sandbox) == (0, 0)


def test_revoked_membership_cannot_create(sandbox):
    response = create(sandbox, "revoked")

    assert response.status_code == 404
    assert count_for(sandbox) == (0, 0)


def test_cross_tenant_create_is_denied(sandbox):
    response = create(sandbox, "foreign", tenant="a")

    assert response.status_code == 404
    assert count_for(sandbox) == (0, 0)


def test_idempotent_retry_replays_original_order(sandbox):
    first = create(sandbox)
    second = create(sandbox)

    assert first.status_code == 201, first.text
    assert second.status_code == 200, second.text

    assert first.json()["id"] == second.json()["id"]
    assert first.json()["replayed"] is False
    assert second.json()["replayed"] is True

    assert count_for(sandbox) == (1, 1)


def test_same_key_different_amount_returns_conflict(sandbox):
    first = create(sandbox)

    modified = dict(BASE_PAYLOAD)
    modified["amount_minor_units"] = 25000

    second = create(sandbox, payload=modified)

    assert first.status_code == 201, first.text
    assert second.status_code == 409, second.text
    assert count_for(sandbox) == (1, 1)


def test_different_key_same_reference_rolls_back(sandbox):
    first = create(sandbox)

    second = create(
        sandbox,
        key="PAYFLOW_HTTP_IDEM_2026_002",
    )

    assert first.status_code == 201, first.text
    assert second.status_code == 409, second.text

    # The rejected second request must not leave behind
    # a newly reserved idempotency record.
    assert count_for(sandbox) == (1, 1)


def test_tenant_scoped_get_and_read_permissions(sandbox):
    created = create(sandbox)

    assert created.status_code == 201, created.text

    order_id = created.json()["id"]

    url = order_path(sandbox) + "/" + order_id

    for role in (
        "owner",
        "admin",
        "developer",
        "finance",
        "viewer",
    ):
        response = sandbox["client"].get(
            url,
            headers=cookie_headers(sandbox, role),
        )

        assert response.status_code == 200, (
            role,
            response.text,
        )

        assert response.json()["id"] == order_id

    foreign = sandbox["client"].get(
        url,
        headers=cookie_headers(sandbox, "foreign"),
    )

    revoked = sandbox["client"].get(
        url,
        headers=cookie_headers(sandbox, "revoked"),
    )

    assert foreign.status_code == 404
    assert revoked.status_code == 404
    assert count_for(sandbox) == (1, 1)


def test_unknown_order_returns_404(sandbox):
    response = sandbox["client"].get(
        order_path(sandbox)
        + "/"
        + str(uuid.uuid4()),
        headers=cookie_headers(sandbox, "owner"),
    )

    assert response.status_code == 404
    assert count_for(sandbox) == (0, 0)


@pytest.mark.parametrize(
    "bad_payload",
    [
        {
            **BASE_PAYLOAD,
            "amount_minor_units": 0,
        },
        {
            **BASE_PAYLOAD,
            "amount_minor_units": True,
        },
        {
            **BASE_PAYLOAD,
            "currency": "inr",
        },
        {
            **BASE_PAYLOAD,
            "merchant_order_reference": "invalid ref",
        },
    ],
)
def test_invalid_payload_does_not_write(
    sandbox,
    bad_payload,
):
    response = create(
        sandbox,
        payload=bad_payload,
    )

    assert response.status_code == 422, response.text
    assert count_for(sandbox) == (0, 0)


def test_idempotency_key_is_tenant_scoped(sandbox):
    first = create(sandbox, "owner", tenant="a")
    second = create(sandbox, "foreign", tenant="b")

    assert first.status_code == 201, first.text
    assert second.status_code == 201, second.text

    assert first.json()["id"] != second.json()["id"]

    assert count_for(sandbox, "a") == (1, 1)
    assert count_for(sandbox, "b") == (1, 1)
