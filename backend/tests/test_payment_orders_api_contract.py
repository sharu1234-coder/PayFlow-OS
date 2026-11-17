"""HTTP boundary tests for the provider-neutral payment-order API.

These tests use fake database sessions and no live payment provider.
Authentication/CSRF are overridden for focused handler tests;
unauthenticated request tests retain the real auth dependency.

Database-backed authentication, CSRF and persistence tests are
separate integration-test responsibilities.
"""

import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.exc import SQLAlchemyError

from app.api import payment_orders as payment_api
from app.api.csrf_dependencies import require_authenticated_csrf
from app.api.dependencies import get_db
from app.api.organizations import require_user
from app.main import app
from app.payments.contracts import Money
from app.services.payment_order_idempotency import (
    IdempotentPaymentOrderResult,
    PaymentIdempotencyKeyConflict,
    PaymentIdempotencyStateUnavailable,
)
from app.services.payment_orders import (
    CreatedPaymentOrder,
    PaymentOrderAccessDenied,
    PaymentOrderReferenceConflict,
)


ORG_ID = uuid.UUID("c9d26615-e657-4b31-9083-11a43111a101")
ACTOR_ID = uuid.UUID("fc911ed1-780b-4e3b-8e89-23da98a55202")
ORDER_ID = uuid.UUID("257561f1-edb0-49f2-a7f8-6a8d6e575303")

POST_PATH = (
    f"/api/v1/organizations/{ORG_ID}/payment-orders"
)
GET_PATH = f"{POST_PATH}/{ORDER_ID}"

IDEMPOTENCY_KEY = "PAYFLOW_API_TEST_2026_001"

PAYLOAD = {
    "merchant_order_reference": "order-api-001",
    "amount_minor_units": 149900,
    "currency": "INR",
}


class FakeSession:
    def __init__(self):
        self.commits = 0
        self.rollbacks = 0
        self.statements = []
        self.order = None
        self.commit_error = None

    def commit(self):
        self.commits += 1
        if self.commit_error is not None:
            raise self.commit_error

    def rollback(self):
        self.rollbacks += 1

    def scalar(self, statement):
        self.statements.append(statement)
        return self.order


def created_result(*, replayed=False):
    return IdempotentPaymentOrderResult(
        order=CreatedPaymentOrder(
            id=ORDER_ID,
            organization_id=ORG_ID,
            merchant_order_reference=PAYLOAD[
                "merchant_order_reference"
            ],
            amount=Money(
                minor_units=149900,
                currency="INR",
            ),
            status="open",
        ),
        replayed=replayed,
    )


@pytest.fixture
def harness(monkeypatch):
    db = FakeSession()
    permission_calls = []
    existing_overrides = dict(app.dependency_overrides)

    def authorize(
        session,
        user_id,
        organization_id,
        permission,
    ):
        assert session is db
        permission_calls.append(
            (user_id, organization_id, permission)
        )
        return "owner"

    monkeypatch.setattr(
        payment_api,
        "authorize_organization_action",
        authorize,
    )

    # Focused HTTP handler tests. Actual cookie and CSRF
    # enforcement will also be tested at the integration level.
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[require_user] = (
        lambda: SimpleNamespace(id=ACTOR_ID)
    )
    app.dependency_overrides[
        require_authenticated_csrf
    ] = lambda: None

    try:
        with TestClient(app) as client:
            yield client, db, permission_calls
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(
            existing_overrides
        )


def post_order(client, *, payload=None, key=IDEMPOTENCY_KEY):
    return client.post(
        POST_PATH,
        json=PAYLOAD if payload is None else payload,
        headers={"Idempotency-Key": key},
    )


def test_create_returns_201_and_commits(harness, monkeypatch):
    client, db, permissions = harness

    def service(session, *, actor_user_id, command):
        assert session is db
        assert actor_user_id == ACTOR_ID
        assert command.organization_id == ORG_ID
        assert command.order_reference == "order-api-001"
        assert command.amount.minor_units == 149900
        assert command.amount.currency == "INR"
        assert command.idempotency_key == IDEMPOTENCY_KEY
        return created_result()

    monkeypatch.setattr(
        payment_api,
        "create_payment_order_idempotent",
        service,
    )

    response = post_order(client)

    assert response.status_code == 201, response.text
    assert response.json() == {
        "id": str(ORDER_ID),
        "organization_id": str(ORG_ID),
        "merchant_order_reference": "order-api-001",
        "amount_minor_units": 149900,
        "currency": "INR",
        "status": "open",
        "replayed": False,
    }
    assert response.headers["cache-control"] == "no-store"
    assert db.commits == 1
    assert db.rollbacks == 0
    assert permissions == [
        (ACTOR_ID, ORG_ID, "payments.create")
    ]


def test_replay_returns_200_and_original_id(
    harness,
    monkeypatch,
):
    client, db, _ = harness

    monkeypatch.setattr(
        payment_api,
        "create_payment_order_idempotent",
        lambda *args, **kwargs: created_result(
            replayed=True
        ),
    )

    response = post_order(client)

    assert response.status_code == 200, response.text
    assert response.json()["id"] == str(ORDER_ID)
    assert response.json()["replayed"] is True
    assert response.headers["cache-control"] == "no-store"
    assert db.commits == 1


@pytest.mark.parametrize(
    "payload",
    [
        {
            **PAYLOAD,
            "amount_minor_units": 0,
        },
        {
            **PAYLOAD,
            "amount_minor_units": -1,
        },
        {
            **PAYLOAD,
            "amount_minor_units": True,
        },
        {
            **PAYLOAD,
            "currency": "inr",
        },
        {
            **PAYLOAD,
            "merchant_order_reference": "invalid ref",
        },
        {
            **PAYLOAD,
            "unexpected_field": "not-allowed",
        },
    ],
)
def test_invalid_payload_rejected_without_commit(
    harness,
    payload,
):
    client, db, permissions = harness

    response = post_order(client, payload=payload)

    assert response.status_code == 422
    assert db.commits == 0
    assert permissions == []


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Idempotency-Key": "short"},
        {"Idempotency-Key": "invalid key with spaces"},
    ],
)
def test_missing_or_invalid_idempotency_key(
    harness,
    headers,
):
    client, db, _ = harness

    response = client.post(
        POST_PATH,
        json=PAYLOAD,
        headers=headers,
    )

    assert response.status_code == 422
    assert db.commits == 0


@pytest.mark.parametrize(
    "error,expected_status",
    [
        (PaymentIdempotencyKeyConflict(), 409),
        (PaymentIdempotencyStateUnavailable(), 409),
        (PaymentOrderReferenceConflict(), 409),
        (PaymentOrderAccessDenied(), 404),
        (SQLAlchemyError("internal test detail"), 503),
    ],
)
def test_service_failures_roll_back_and_use_safe_http(
    harness,
    monkeypatch,
    error,
    expected_status,
):
    client, db, _ = harness

    def service(*args, **kwargs):
        raise error

    monkeypatch.setattr(
        payment_api,
        "create_payment_order_idempotent",
        service,
    )

    response = post_order(client)

    assert response.status_code == expected_status
    assert db.commits == 0
    assert db.rollbacks == 1
    assert "internal test detail" not in response.text


@pytest.mark.parametrize("status_code", [403, 404])
def test_authorization_failure_prevents_creation(
    harness,
    monkeypatch,
    status_code,
):
    client, db, _ = harness

    def deny(*args, **kwargs):
        raise HTTPException(
            status_code=status_code,
            detail="Access denied",
        )

    monkeypatch.setattr(
        payment_api,
        "authorize_organization_action",
        deny,
    )

    response = post_order(client)

    assert response.status_code == status_code
    assert db.commits == 0
    assert db.rollbacks == 1


def test_commit_failure_rolls_back_and_returns_503(
    harness,
    monkeypatch,
):
    client, db, _ = harness

    db.commit_error = SQLAlchemyError(
        "simulated persistence failure"
    )

    monkeypatch.setattr(
        payment_api,
        "create_payment_order_idempotent",
        lambda *args, **kwargs: created_result(),
    )

    response = post_order(client)

    assert response.status_code == 503
    assert db.commits == 1
    assert db.rollbacks == 1
    assert "simulated persistence failure" not in response.text


def test_get_order_uses_tenant_and_order_filters(harness):
    client, db, permissions = harness

    db.order = SimpleNamespace(
        id=ORDER_ID,
        organization_id=ORG_ID,
        merchant_order_reference="order-api-001",
        amount_minor_units=149900,
        currency="INR",
        status="open",
    )

    response = client.get(GET_PATH)

    assert response.status_code == 200, response.text
    assert response.json()["id"] == str(ORDER_ID)
    assert response.json()["organization_id"] == str(ORG_ID)
    assert response.headers["cache-control"] == "no-store"

    assert permissions == [
        (ACTOR_ID, ORG_ID, "payments.read")
    ]

    assert len(db.statements) == 1

    compiled = db.statements[0].compile()
    sql = str(compiled)

    assert "payment_orders.organization_id" in sql
    assert "payment_orders.id" in sql
    assert ORG_ID in compiled.params.values()
    assert ORDER_ID in compiled.params.values()
    assert db.commits == 0


def test_get_missing_order_returns_404(harness):
    client, db, permissions = harness

    response = client.get(GET_PATH)

    assert response.status_code == 404
    assert db.commits == 0
    assert permissions == [
        (ACTOR_ID, ORG_ID, "payments.read")
    ]


def test_get_unauthorized_tenant_returns_404(
    harness,
    monkeypatch,
):
    client, db, _ = harness

    def deny(*args, **kwargs):
        raise HTTPException(
            status_code=404,
            detail="Organization not found",
        )

    monkeypatch.setattr(
        payment_api,
        "authorize_organization_action",
        deny,
    )

    response = client.get(GET_PATH)

    assert response.status_code == 404
    assert db.statements == []


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_real_auth_dependency_rejects_missing_session(
    method,
):
    existing_overrides = dict(app.dependency_overrides)
    db = FakeSession()

    app.dependency_overrides.clear()
    app.dependency_overrides[get_db] = lambda: db

    try:
        with TestClient(app) as client:
            if method == "POST":
                response = client.post(
                    POST_PATH,
                    json=PAYLOAD,
                    headers={
                        "Idempotency-Key": IDEMPOTENCY_KEY
                    },
                )
            else:
                response = client.get(GET_PATH)

            assert response.status_code == 401
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(
            existing_overrides
        )

    assert db.commits == 0


def test_zero_organization_uuid_is_rejected(harness):
    client, db, _ = harness

    zero = uuid.UUID(int=0)

    response = client.post(
        f"/api/v1/organizations/{zero}/payment-orders",
        json=PAYLOAD,
        headers={
            "Idempotency-Key": IDEMPOTENCY_KEY
        },
    )

    assert response.status_code == 422
    assert db.commits == 0


def test_openapi_documents_creation_and_idempotent_replay():
    path = (
        "/api/v1/organizations/"
        "{organization_id}/payment-orders"
    )

    operation = app.openapi()["paths"][path]["post"]
    responses = operation["responses"]

    assert "201" in responses
    assert "200" in responses
    assert "422" in responses

    assert responses["200"]["description"] == (
        "Idempotent replay"
    )

    assert (
        "application/json"
        in responses["200"]["content"]
    )


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_payment_api_disabled_outside_development(
    monkeypatch,
    method,
):
    from app.api import organizations as organizations_api

    monkeypatch.setattr(
        organizations_api,
        "get_settings",
        lambda: SimpleNamespace(app_env="production"),
    )

    existing_overrides = dict(app.dependency_overrides)
    db = FakeSession()

    app.dependency_overrides.clear()
    app.dependency_overrides[get_db] = lambda: db

    try:
        with TestClient(app) as client:
            if method == "GET":
                response = client.get(GET_PATH)
            else:
                response = client.post(
                    POST_PATH,
                    json=PAYLOAD,
                    headers={
                        "Idempotency-Key": IDEMPOTENCY_KEY,
                    },
                )

            assert response.status_code == 503, response.text

    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(
            existing_overrides
        )

    assert db.commits == 0
