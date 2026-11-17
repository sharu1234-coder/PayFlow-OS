from types import SimpleNamespace

import pytest
from fastapi import Response
from fastapi.testclient import TestClient

from app.core import browser_cors, cookie_policy
from app.main import app


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_development_cookie_is_httponly_and_lax(monkeypatch):
    monkeypatch.setattr(
        cookie_policy,
        "get_settings",
        lambda: SimpleNamespace(app_env="development"),
    )

    response = Response()

    cookie_policy.set_auth_session_cookie(
        response,
        "local-test-session",
        28800,
    )

    header = response.headers["set-cookie"].lower()

    assert "httponly" in header
    assert "samesite=lax" in header
    assert "path=/" in header
    assert "max-age=28800" in header
    assert "secure" not in header
    assert "domain=" not in header
    assert response.headers["cache-control"] == "no-store"


def test_production_cookie_requires_secure(monkeypatch):
    monkeypatch.setattr(
        cookie_policy,
        "get_settings",
        lambda: SimpleNamespace(app_env="production"),
    )

    response = Response()

    cookie_policy.set_auth_session_cookie(
        response,
        "production-test-session",
        28800,
    )

    header = response.headers["set-cookie"].lower()

    assert "secure" in header
    assert "httponly" in header
    assert "samesite=lax" in header
    assert "path=/" in header
    assert "domain=" not in header


def test_unknown_environment_fails_secure(monkeypatch):
    monkeypatch.setattr(
        cookie_policy,
        "get_settings",
        lambda: SimpleNamespace(app_env="unknown"),
    )

    assert cookie_policy.secure_cookie_required() is True


def test_production_logout_clears_secure_cookie(monkeypatch):
    monkeypatch.setattr(
        cookie_policy,
        "get_settings",
        lambda: SimpleNamespace(app_env="production"),
    )

    response = Response()

    cookie_policy.clear_auth_session_cookie(response)

    header = response.headers["set-cookie"].lower()

    assert "secure" in header
    assert "httponly" in header
    assert "max-age=0" in header
    assert "path=/" in header
    assert response.headers["cache-control"] == "no-store"


def test_local_logout_clears_local_cookie(monkeypatch):
    monkeypatch.setattr(
        cookie_policy,
        "get_settings",
        lambda: SimpleNamespace(app_env="development"),
    )

    response = Response()

    cookie_policy.clear_auth_session_cookie(response)

    header = response.headers["set-cookie"].lower()

    assert "max-age=0" in header
    assert "secure" not in header


def test_trusted_origin_preflight_allows_credentials(client):
    response = client.options(
        "/api/v1/auth/login",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": (
                "content-type,x-csrf-token"
            ),
        },
    )

    assert response.status_code == 200, response.text

    assert response.headers[
        "access-control-allow-origin"
    ] == "http://localhost:5173"

    assert response.headers[
        "access-control-allow-credentials"
    ] == "true"

    allowed_headers = response.headers[
        "access-control-allow-headers"
    ].lower()

    assert "x-csrf-token" in allowed_headers


def test_untrusted_origin_preflight_is_rejected(client):
    response = client.options(
        "/api/v1/auth/login",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "POST",
        },
    )

    assert response.status_code == 400
    assert (
        "access-control-allow-origin"
        not in response.headers
    )


def test_preflight_rejects_unapproved_header(client):
    response = client.options(
        "/api/v1/auth/login",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": (
                "x-unapproved-secret-header"
            ),
        },
    )

    assert response.status_code == 400


def test_trusted_browser_get_receives_cors_headers(client):
    response = client.get(
        "/api/v1/health/live",
        headers={"Origin": "http://localhost:5173"},
    )

    assert response.status_code == 200

    assert response.headers[
        "access-control-allow-origin"
    ] == "http://localhost:5173"

    assert response.headers[
        "access-control-allow-credentials"
    ] == "true"


def test_untrusted_browser_get_has_no_cors_access(client):
    response = client.get(
        "/api/v1/health/live",
        headers={"Origin": "https://evil.example"},
    )

    assert response.status_code == 200

    assert (
        "access-control-allow-origin"
        not in response.headers
    )


def test_trusted_browser_login_reaches_validation(client):
    response = client.post(
        "/api/v1/auth/login",
        json={},
        headers={"Origin": "http://localhost:5173"},
    )

    assert response.status_code == 422

    assert response.headers[
        "access-control-allow-origin"
    ] == "http://localhost:5173"


def test_untrusted_browser_login_stays_rejected(client):
    response = client.post(
        "/api/v1/auth/login",
        json={},
        headers={"Origin": "https://evil.example"},
    )

    assert response.status_code == 403

    assert (
        "access-control-allow-origin"
        not in response.headers
    )


def test_production_requires_https_origins(monkeypatch):
    monkeypatch.setattr(
        browser_cors,
        "get_settings",
        lambda: SimpleNamespace(
            app_env="production",
            browser_allowed_origins="http://localhost:5173",
        ),
    )

    with pytest.raises(RuntimeError):
        browser_cors.browser_cors_origins()


def test_production_accepts_explicit_https_origin(monkeypatch):
    monkeypatch.setattr(
        browser_cors,
        "get_settings",
        lambda: SimpleNamespace(
            app_env="production",
            browser_allowed_origins="https://merchant.example",
        ),
    )

    assert browser_cors.browser_cors_origins() == [
        "https://merchant.example"
    ]


def test_production_rejects_empty_origins(monkeypatch):
    monkeypatch.setattr(
        browser_cors,
        "get_settings",
        lambda: SimpleNamespace(
            app_env="production",
            browser_allowed_origins="",
        ),
    )

    with pytest.raises(RuntimeError):
        browser_cors.browser_cors_origins()


def test_payment_order_trusted_preflight_allows_required_headers(client):
    response = client.options(
        "/api/v1/organizations/"
        "12345678-1234-4234-8234-123456789012/"
        "payment-orders",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": (
                "content-type,idempotency-key,x-csrf-token"
            ),
        },
    )

    assert response.status_code == 200, response.text

    assert response.headers[
        "access-control-allow-origin"
    ] == "http://localhost:5173"

    assert response.headers[
        "access-control-allow-credentials"
    ] == "true"

    allowed_headers = {
        header.strip().lower()
        for header in response.headers[
            "access-control-allow-headers"
        ].split(",")
    }

    assert {
        "content-type",
        "idempotency-key",
        "x-csrf-token",
    }.issubset(allowed_headers)


def test_payment_order_untrusted_preflight_is_rejected(client):
    response = client.options(
        "/api/v1/organizations/"
        "12345678-1234-4234-8234-123456789012/"
        "payment-orders",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": (
                "idempotency-key,x-csrf-token"
            ),
        },
    )

    assert response.status_code == 400

    assert (
        "access-control-allow-origin"
        not in response.headers
    )


def test_payment_order_unapproved_header_is_rejected(client):
    response = client.options(
        "/api/v1/organizations/"
        "12345678-1234-4234-8234-123456789012/"
        "payment-orders",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": (
                "idempotency-key,"
                "x-csrf-token,"
                "x-unapproved-secret-header"
            ),
        },
    )

    assert response.status_code == 400
