"""Real FastAPI security dependencies with isolated storage.

Actual components:
- require_user and require_authenticated_csrf
- GET /api/v1/auth/csrf and session-bound token verification
- UnsafeOriginGuard and configured CORS behavior
- PrelaunchReleaseGate

Test doubles replace only storage-backed user lookup,
organization authorization, and attempt persistence.

No PostgreSQL connection and no production route registration.
"""

import uuid
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient

from app.api import organizations
from app.api import session as session_api
from app.api import payment_attempts_sandbox as api
from app.api.dependencies import get_db
from app.core import browser_cors, origin_guard, release_gate
from app.payments.contracts import Money, PaymentState
from app.services.payment_attempt_idempotency import (
    IdempotentSandboxAttemptResult,
)
from app.services.payment_attempts import (
    CreatedSandboxPaymentAttempt,
)


ACTOR = uuid.UUID("1a43188b-f293-4a1f-9f8c-95d23606c928")
ORG = uuid.UUID("bfed88b3-edeb-48d0-b671-9406a689daba")
OTHER_ORG = uuid.UUID(
    "d77b3e35-6fee-440e-8728-b106aab53c43"
)
ORDER = uuid.UUID("945e6aae-75b4-455b-bb23-a76b9d974b76")
ATTEMPT = uuid.UUID(
    "fa027ff0-0376-4291-bf5f-06179fe44301"
)

KEY = "SECURITY_SANDBOX_KEY_001"

SESSION_A = "synthetic-session-token-a-001"
SESSION_B = "synthetic-session-token-b-002"

TRUSTED_ORIGIN = "http://localhost:5173"
UNTRUSTED_ORIGIN = "https://untrusted.example"

URL = (
    f"/api/v1/organizations/{ORG}"
    f"/payment-orders/{ORDER}/attempts"
)
CSRF_URL = "/api/v1/auth/csrf"


class FakeDB:
    def __init__(self):
        self.commits = 0
        self.rollbacks = 0

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


@pytest.fixture
def security_client(monkeypatch):
    db = FakeDB()

    settings = SimpleNamespace(
        app_env="development",
        browser_allowed_origins=TRUSTED_ORIGIN,
    )

    state = {
        "settings": settings,
        "valid_sessions": {SESSION_A, SESSION_B},
        "session_lookups": [],
        "authorization_calls": [],
        "service_calls": [],
        "permission": "allowed",
        "replayed": False,
        "db": db,
    }

    # Use the ACTUAL dependencies and middleware.
    # Only their environment configuration is controlled.
    for module in (
        organizations,
        session_api,
        api,
        origin_guard,
        browser_cors,
        release_gate,
    ):
        monkeypatch.setattr(
            module,
            "get_settings",
            lambda settings=settings: settings,
        )

    # Replace the storage lookup, not require_user.
    def lookup_authenticated_user(db_arg, token):
        state["session_lookups"].append(token)

        if token not in state["valid_sessions"]:
            return None

        return SimpleNamespace(id=ACTOR)

    monkeypatch.setattr(
        organizations,
        "get_authenticated_user",
        lookup_authenticated_user,
    )

    monkeypatch.setattr(
        session_api,
        "get_authenticated_user",
        lookup_authenticated_user,
    )

    # Preserve actual HTTP RBAC wiring. Substitute the
    # database-backed permission result only.
    def authorize(
        db_arg,
        actor_user_id,
        organization_id,
        permission,
    ):
        state["authorization_calls"].append(
            (actor_user_id, organization_id, permission)
        )

        if organization_id != ORG:
            raise HTTPException(
                status_code=404,
                detail="Organization not found",
            )

        if state["permission"] != "allowed":
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions",
            )

        return "owner"

    monkeypatch.setattr(
        api,
        "authorize_organization_action",
        authorize,
    )

    # No attempt creation or database writes.
    def fake_attempt_service(
        db_arg,
        *,
        actor_user_id,
        intent,
    ):
        state["service_calls"].append(
            (actor_user_id, intent)
        )

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
            state=PaymentState.CREATED,
        )

        return IdempotentSandboxAttemptResult(
            attempt=attempt,
            replayed=state["replayed"],
        )

    monkeypatch.setattr(
        api,
        "create_sandbox_payment_attempt_idempotent",
        fake_attempt_service,
    )

    # An ISOLATED test app; app.main is not modified.
    app = FastAPI()

    app.include_router(session_api.router)
    app.include_router(api.router)

    app.dependency_overrides[get_db] = lambda: db

    # Match the real application's middleware order.
    app.add_middleware(origin_guard.UnsafeOriginGuard)

    app.add_middleware(
        CORSMiddleware,
        **browser_cors.browser_cors_options(),
    )

    app.add_middleware(
        release_gate.PrelaunchReleaseGate
    )

    with TestClient(
        app,
        raise_server_exceptions=False,
    ) as client:
        yield client, state


def headers(
    *,
    session_token=SESSION_A,
    csrf_token=None,
    key=KEY,
    origin=None,
    fetch_site=None,
    referer=None,
):
    result = {}

    if key is not None:
        result["Idempotency-Key"] = key

    if session_token is not None:
        result["Cookie"] = (
            f"payflow_session={session_token}"
        )

    if csrf_token is not None:
        result["X-CSRF-Token"] = csrf_token

    if origin is not None:
        result["Origin"] = origin

    if fetch_site is not None:
        result["Sec-Fetch-Site"] = fetch_site

    if referer is not None:
        result["Referer"] = referer

    return result


def csrf_token(client, *, session_token=SESSION_A):
    response = client.get(
        CSRF_URL,
        headers={
            "Cookie": (
                f"payflow_session={session_token}"
            )
        },
    )

    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"

    return response.json()["token"]


def post_attempt(
    client,
    *,
    session_token=SESSION_A,
    token=None,
    key=KEY,
    origin=None,
    fetch_site=None,
    referer=None,
    url=URL,
):
    return client.post(
        url,
        headers=headers(
            session_token=session_token,
            csrf_token=token,
            key=key,
            origin=origin,
            fetch_site=fetch_site,
            referer=referer,
        ),
    )


def test_actual_csrf_endpoint_requires_session(security_client):
    client, state = security_client

    response = client.get(CSRF_URL)

    assert response.status_code == 401
    assert state["service_calls"] == []


def test_actual_csrf_endpoint_issues_session_token(
    security_client,
):
    client, state = security_client

    token = csrf_token(client)

    assert isinstance(token, str)
    assert len(token) > 10
    assert SESSION_A in state["session_lookups"]


def test_cookie_and_real_csrf_allow_creation(security_client):
    client, state = security_client

    token = csrf_token(client)

    response = post_attempt(
        client,
        token=token,
    )

    assert response.status_code == 201
    assert response.json()["id"] == str(ATTEMPT)
    assert response.json()["replayed"] is False
    assert state["db"].commits == 1
    assert state["db"].rollbacks == 0

    assert len(state["service_calls"]) == 1

    actor, intent = state["service_calls"][0]

    assert actor == ACTOR
    assert intent.organization_id == ORG
    assert intent.order_id == ORDER
    assert intent.idempotency_key == KEY


def test_real_csrf_allows_replay_response(security_client):
    client, state = security_client

    state["replayed"] = True

    response = post_attempt(
        client,
        token=csrf_token(client),
    )

    assert response.status_code == 200
    assert response.json()["id"] == str(ATTEMPT)
    assert response.json()["replayed"] is True


def test_missing_cookie_rejected(security_client):
    client, state = security_client

    response = post_attempt(
        client,
        session_token=None,
    )

    assert response.status_code == 401
    assert state["service_calls"] == []


def test_wrong_cookie_name_rejected(security_client):
    client, state = security_client

    response = client.post(
        URL,
        headers={
            "Cookie": (
                "not_payflow_session=" + SESSION_A
            ),
            "Idempotency-Key": KEY,
        },
    )

    assert response.status_code == 401
    assert state["service_calls"] == []


def test_unknown_session_rejected(security_client):
    client, state = security_client

    response = post_attempt(
        client,
        session_token="unknown-session",
    )

    assert response.status_code == 401
    assert state["service_calls"] == []


@pytest.mark.parametrize(
    "reason",
    ["expired", "revoked"],
)
def test_invalidated_session_rejected(
    security_client,
    reason,
):
    client, state = security_client

    token = csrf_token(client)

    # Storage-boundary simulation of expiry/revocation.
    state["valid_sessions"].remove(SESSION_A)

    response = post_attempt(
        client,
        token=token,
    )

    assert response.status_code == 401
    assert state["service_calls"] == []


def test_missing_csrf_header_rejected(security_client):
    client, state = security_client

    response = post_attempt(client)

    assert response.status_code == 403
    assert state["service_calls"] == []


def test_invalid_csrf_header_rejected(security_client):
    client, state = security_client

    response = post_attempt(
        client,
        token="invalid-csrf-value",
    )

    assert response.status_code == 403
    assert state["service_calls"] == []


def test_other_session_csrf_rejected(security_client):
    client, state = security_client

    token_b = csrf_token(
        client,
        session_token=SESSION_B,
    )

    response = post_attempt(
        client,
        session_token=SESSION_A,
        token=token_b,
    )

    assert response.status_code == 403
    assert state["service_calls"] == []


def test_missing_idempotency_key_rejected(security_client):
    client, state = security_client

    response = post_attempt(
        client,
        token=csrf_token(client),
        key=None,
    )

    assert response.status_code == 422
    assert state["service_calls"] == []


def test_permission_denied_before_service(security_client):
    client, state = security_client

    token = csrf_token(client)
    state["permission"] = "denied"

    response = post_attempt(
        client,
        token=token,
    )

    assert response.status_code == 403
    assert state["service_calls"] == []
    assert state["db"].commits == 0


def test_cross_organization_hidden(security_client):
    client, state = security_client

    token = csrf_token(client)

    other_url = (
        f"/api/v1/organizations/{OTHER_ORG}"
        f"/payment-orders/{ORDER}/attempts"
    )

    response = post_attempt(
        client,
        token=token,
        url=other_url,
    )

    assert response.status_code == 404
    assert state["service_calls"] == []


def test_untrusted_origin_blocked_first(security_client):
    client, state = security_client

    response = post_attempt(
        client,
        origin=UNTRUSTED_ORIGIN,
    )

    assert response.status_code == 403
    assert response.json()["detail"] == (
        "Untrusted browser origin"
    )

    assert state["session_lookups"] == []
    assert state["service_calls"] == []


def test_cross_site_without_origin_blocked(security_client):
    client, state = security_client

    response = post_attempt(
        client,
        fetch_site="cross-site",
    )

    assert response.status_code == 403
    assert state["service_calls"] == []


def test_conflicting_origin_and_referer_blocked(
    security_client,
):
    client, state = security_client

    response = post_attempt(
        client,
        origin=TRUSTED_ORIGIN,
        referer=UNTRUSTED_ORIGIN + "/page",
    )

    assert response.status_code == 403
    assert state["service_calls"] == []


def test_trusted_origin_and_csrf_allowed(security_client):
    client, state = security_client

    token = csrf_token(client)

    response = post_attempt(
        client,
        token=token,
        origin=TRUSTED_ORIGIN,
    )

    assert response.status_code == 201
    assert response.headers[
        "access-control-allow-origin"
    ] == TRUSTED_ORIGIN

    assert len(state["service_calls"]) == 1


def test_trusted_cors_preflight_supports_headers(
    security_client,
):
    client, state = security_client

    response = client.options(
        URL,
        headers={
            "Origin": TRUSTED_ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": (
                "Idempotency-Key,X-CSRF-Token"
            ),
        },
    )

    assert response.status_code == 200

    allowed = response.headers[
        "access-control-allow-headers"
    ].lower()

    assert "idempotency-key" in allowed
    assert "x-csrf-token" in allowed
    assert state["service_calls"] == []


def test_untrusted_cors_preflight_has_no_access(
    security_client,
):
    client, state = security_client

    response = client.options(
        URL,
        headers={
            "Origin": UNTRUSTED_ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": (
                "Idempotency-Key,X-CSRF-Token"
            ),
        },
    )

    assert response.status_code == 400
    assert (
        "access-control-allow-origin"
        not in response.headers
    )

    assert state["service_calls"] == []


@pytest.mark.parametrize(
    "environment",
    ["staging", "production"],
)
def test_non_development_release_gate_blocks_attempts(
    security_client,
    environment,
):
    client, state = security_client

    state["settings"].app_env = environment

    response = post_attempt(
        client,
        origin=TRUSTED_ORIGIN,
    )

    assert response.status_code == 503
    assert response.json()["detail"] == (
        "Service unavailable"
    )
    assert state["service_calls"] == []
    assert state["db"].commits == 0


def test_get_method_does_not_create_attempt(security_client):
    client, state = security_client

    response = client.get(URL)

    assert response.status_code == 405
    assert state["service_calls"] == []


def test_router_is_still_unmounted_in_real_app():
    from pathlib import Path

    main_path = (
        Path(__file__).resolve().parents[1]
        / "app"
        / "main.py"
    )

    source = main_path.read_text(encoding="utf-8")

    assert "payment_attempts_sandbox" not in source
