"""Isolated HTTP contract tests. No real database connection."""

import uuid
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from app.api import payment_attempts_sandbox as api
from app.payments.contracts import Money, PaymentState
from app.services.payment_attempt_idempotency import (
    AttemptIdempotencyKeyConflict,
    AttemptIdempotencyStateUnavailable,
    IdempotentSandboxAttemptResult,
)
from app.services.payment_attempts import (
    CreatedSandboxPaymentAttempt,
    PaymentAttemptAccessDenied,
    PaymentAttemptConflict,
    PaymentAttemptOrderNotFound,
)


ACTOR = uuid.UUID("1a43188b-f293-4a1f-9f8c-95d23606c928")
ORG = uuid.UUID("bfed88b3-edeb-48d0-b671-9406a689daba")
ORDER = uuid.UUID("945e6aae-75b4-455b-bb23-a76b9d974b76")
ATTEMPT = uuid.UUID("fa027ff0-0376-4291-bf5f-06179fe44301")
KEY = "HTTP_SANDBOX_KEY_0001"

URL = (
    f"/api/v1/organizations/{ORG}"
    f"/payment-orders/{ORDER}/attempts"
)


class FakeDB:
    def __init__(self):
        self.commits = 0
        self.rollbacks = 0
        self.commit_error = None

    def commit(self):
        self.commits += 1

        if self.commit_error is not None:
            raise self.commit_error

    def rollback(self):
        self.rollbacks += 1


@pytest.fixture
def client_context(monkeypatch):
    db = FakeDB()

    context = {
        "db": db,
        "service_calls": [],
        "authorization_calls": [],
        "csrf_calls": 0,
        "auth_error": None,
        "csrf_error": None,
        "service_error": None,
        "replayed": False,
        "attempt_state": PaymentState.CREATED,
        "environment": "development",
    }

    monkeypatch.setattr(
        api,
        "get_settings",
        lambda: SimpleNamespace(
            app_env=context["environment"]
        ),
    )

    def authorize(db_arg, actor, organization, permission):
        context["authorization_calls"].append(
            (actor, organization, permission)
        )

    monkeypatch.setattr(
        api,
        "authorize_organization_action",
        authorize,
    )

    def fake_service(db_arg, *, actor_user_id, intent):
        context["service_calls"].append(
            (actor_user_id, intent)
        )

        if context["service_error"] is not None:
            raise context["service_error"]

        attempt = CreatedSandboxPaymentAttempt(
            id=ATTEMPT,
            organization_id=ORG,
            order_id=ORDER,
            attempt_number=1,
            amount=Money(
                minor_units=149900,
                currency="INR",
            ),
            provider_code="sandbox",
            state=context["attempt_state"],
        )

        return IdempotentSandboxAttemptResult(
            attempt=attempt,
            replayed=context["replayed"],
        )

    monkeypatch.setattr(
        api,
        "create_sandbox_payment_attempt_idempotent",
        fake_service,
    )

    app = FastAPI()
    app.include_router(api.router)

    def fake_auth():
        if context["auth_error"] is not None:
            raise context["auth_error"]

        return SimpleNamespace(id=ACTOR)

    def fake_csrf():
        context["csrf_calls"] += 1

        if context["csrf_error"] is not None:
            raise context["csrf_error"]

    app.dependency_overrides[api.require_user] = fake_auth
    app.dependency_overrides[api.get_db] = lambda: db
    app.dependency_overrides[
        api.require_authenticated_csrf
    ] = fake_csrf

    with TestClient(
        app,
        raise_server_exceptions=False,
    ) as client:
        yield client, context


def send(client, *, url=URL, key=KEY):
    return client.post(
        url,
        headers={"Idempotency-Key": key},
    )


def test_new_request_returns_201(client_context):
    client, context = client_context

    response = send(client)

    assert response.status_code == 201

    data = response.json()

    assert data["id"] == str(ATTEMPT)
    assert data["organization_id"] == str(ORG)
    assert data["order_id"] == str(ORDER)
    assert data["attempt_number"] == 1
    assert data["amount_minor_units"] == 149900
    assert data["currency"] == "INR"
    assert data["provider_code"] == "sandbox"
    assert data["status"] == "created"
    assert data["replayed"] is False

    assert context["db"].commits == 1
    assert context["db"].rollbacks == 0
    assert len(context["service_calls"]) == 1


def test_same_key_replay_returns_200(client_context):
    client, context = client_context

    context["replayed"] = True
    context["attempt_state"] = PaymentState.FAILED

    response = send(client)

    assert response.status_code == 200
    assert response.json()["id"] == str(ATTEMPT)
    assert response.json()["status"] == "failed"
    assert response.json()["replayed"] is True
    assert context["db"].commits == 1


def test_csrf_dependency_is_required(client_context):
    client, context = client_context

    context["csrf_error"] = HTTPException(
        status_code=403,
        detail="CSRF verification required",
    )

    response = send(client)

    assert response.status_code == 403
    assert context["service_calls"] == []
    assert context["db"].commits == 0


def test_authentication_is_required(client_context):
    client, context = client_context

    context["auth_error"] = HTTPException(
        status_code=401,
        detail="Authentication required",
    )

    response = send(client)

    assert response.status_code == 401
    assert context["service_calls"] == []
    assert context["db"].commits == 0


def test_missing_idempotency_key_rejected(client_context):
    client, context = client_context

    response = client.post(URL)

    assert response.status_code == 422
    assert context["service_calls"] == []


@pytest.mark.parametrize(
    "bad_key",
    ["short", "bad key here", "A" * 129],
)
def test_invalid_idempotency_key_rejected(
    client_context,
    bad_key,
):
    client, context = client_context

    response = send(client, key=bad_key)

    assert response.status_code == 422
    assert context["service_calls"] == []


def test_development_only_gate(client_context):
    client, context = client_context
    context["environment"] = "production"

    response = send(client)

    assert response.status_code == 404
    assert context["service_calls"] == []
    assert context["authorization_calls"] == []
    assert context["db"].commits == 0


@pytest.mark.parametrize(
    "error_type,expected_status",
    [
        (PaymentAttemptAccessDenied, 404),
        (PaymentAttemptOrderNotFound, 404),
        (PaymentAttemptConflict, 409),
        (AttemptIdempotencyKeyConflict, 409),
        (AttemptIdempotencyStateUnavailable, 409),
    ],
)
def test_domain_errors_rollback(
    client_context,
    error_type,
    expected_status,
):
    client, context = client_context
    context["service_error"] = error_type("synthetic")

    response = send(client)

    assert response.status_code == expected_status
    assert context["db"].commits == 0
    assert context["db"].rollbacks == 1
    assert "synthetic" not in response.text


def test_database_errors_are_sanitized(client_context):
    client, context = client_context

    context["service_error"] = OperationalError(
        "SELECT",
        {},
        Exception("synthetic database credential disclosure"),
    )

    response = send(client)

    assert response.status_code == 503
    assert "credential disclosure" not in response.text
    assert context["db"].rollbacks == 1


def test_failed_commit_triggers_rollback(client_context):
    client, context = client_context

    context["db"].commit_error = OperationalError(
        "COMMIT",
        {},
        Exception("synthetic commit failure"),
    )

    response = send(client)

    assert response.status_code == 503
    assert context["db"].commits == 1
    assert context["db"].rollbacks == 1


def test_unexpected_errors_trigger_rollback(client_context):
    client, context = client_context

    context["service_error"] = RuntimeError(
        "synthetic unexpected failure"
    )

    response = send(client)

    assert response.status_code == 500
    assert context["db"].commits == 0
    assert context["db"].rollbacks == 1


def test_tenant_permission_checked(client_context):
    client, context = client_context

    response = send(client)

    assert response.status_code == 201
    assert context["authorization_calls"] == [
        (ACTOR, ORG, "payments.create")
    ]

    actor, intent = context["service_calls"][0]

    assert actor == ACTOR
    assert intent.organization_id == ORG
    assert intent.order_id == ORDER
    assert intent.idempotency_key == KEY


def test_zero_uuid_rejected(client_context):
    client, context = client_context

    zero = str(uuid.UUID(int=0))

    response = send(
        client,
        url=(
            f"/api/v1/organizations/{zero}"
            f"/payment-orders/{ORDER}/attempts"
        ),
    )

    assert response.status_code == 422
    assert context["service_calls"] == []


def test_cache_disabled_on_success(client_context):
    client, _ = client_context

    response = send(client)

    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"


def test_sensitive_provider_fields_not_exposed(client_context):
    client, _ = client_context

    response = send(client)

    assert response.status_code == 201

    body = response.json()

    assert "provider_payment_id" not in body
    assert "secret" not in body
    assert "gateway_token" not in body


def test_sandbox_api_unmounted_when_flag_disabled():
    from unittest.mock import patch
    from app.main import create_app

    settings = SimpleNamespace(
        app_env="development",
        sandbox_payment_attempts_enabled=False,
    )

    with patch(
        "app.core.config.get_settings",
        return_value=settings,
    ):
        application = create_app()

    path = (
        "/api/v1/organizations/{organization_id}"
        "/payment-orders/{order_id}/attempts"
    )

    # Inspect the public OpenAPI contract, not FastAPI's
    # version-dependent internal router representation.
    paths = application.openapi().get("paths", {})

    assert "post" not in paths.get(path, {})

@pytest.mark.parametrize(
    "invalid_field",
    ("provider_code", "state"),
)
def test_invalid_result_never_commits(
    client_context,
    monkeypatch,
    invalid_field,
):
    """Malformed service results must fail before COMMIT."""

    client, context = client_context

    attempt = SimpleNamespace(
        id=ATTEMPT,
        organization_id=ORG,
        order_id=ORDER,
        attempt_number=1,
        amount=SimpleNamespace(
            minor_units=149900,
            currency="INR",
        ),
        provider_code="sandbox",
        state=SimpleNamespace(value="created"),
    )

    # Both failures happen during response construction.
    if invalid_field == "provider_code":
        attempt.provider_code = None
    else:
        attempt.state = None

    def malformed_service(*args, **kwargs):
        return SimpleNamespace(
            attempt=attempt,
            replayed=False,
        )

    monkeypatch.setattr(
        api,
        "create_sandbox_payment_attempt_idempotent",
        malformed_service,
    )

    response = send(client)

    assert response.status_code == 500

    # Crucial new invariant: no commit if the endpoint
    # cannot construct a valid HTTP response.
    assert context["db"].commits == 0
    assert context["db"].rollbacks == 1
