from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.main import app


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def known_origin():
    value = get_settings().browser_allowed_origins
    origin = value.split(",")[0].strip()

    assert origin.startswith("http")
    return origin


def attempt_login(client, headers=None):
    # Invalid body intentionally avoids credential checks
    # and avoids inserting login audit records.
    return client.post(
        "/api/v1/auth/login",
        json={},
        headers=headers or {},
    )


def test_trusted_origin_reaches_validation(client, known_origin):
    response = attempt_login(
        client,
        {"Origin": known_origin},
    )

    assert response.status_code == 422


def test_trusted_referer_reaches_validation(client, known_origin):
    response = attempt_login(
        client,
        {"Referer": known_origin + "/signin"},
    )

    assert response.status_code == 422


def test_local_development_cli_request_remains_supported(client):
    response = attempt_login(client)

    assert response.status_code == 422


@pytest.mark.parametrize(
    "origin",
    [
        "https://evil.example",
        "null",
        "http://localhost.evil.example:5173",
        "http://localhost:5173/malicious",
    ],
)
def test_untrusted_origin_is_rejected(client, origin):
    response = attempt_login(
        client,
        {"Origin": origin},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == (
        "Untrusted browser origin"
    )


def test_untrusted_referer_is_rejected(client):
    response = attempt_login(
        client,
        {"Referer": "https://evil.example/attack"},
    )

    assert response.status_code == 403


def test_conflicting_origin_and_referer_are_rejected(
    client,
    known_origin,
):
    response = attempt_login(
        client,
        {
            "Origin": known_origin,
            "Referer": "https://evil.example/attack",
        },
    )

    assert response.status_code == 403


def test_unidentified_cross_site_request_is_rejected(client):
    response = attempt_login(
        client,
        {"Sec-Fetch-Site": "cross-site"},
    )

    assert response.status_code == 403


def test_explicitly_trusted_frontend_is_allowed(
    client,
    known_origin,
):
    response = attempt_login(
        client,
        {
            "Origin": known_origin,
            "Sec-Fetch-Site": "cross-site",
        },
    )

    assert response.status_code == 422


def test_unsafe_logout_rejects_untrusted_origin(client):
    response = client.post(
        "/api/v1/auth/logout",
        headers={"Origin": "https://evil.example"},
    )

    assert response.status_code == 403


def test_safe_get_is_not_blocked_by_origin_guard(client):
    response = client.get(
        "/api/v1/health/live",
        headers={"Origin": "https://evil.example"},
    )

    assert response.status_code == 200


def test_production_cookie_mutation_requires_source(
    client,
    monkeypatch,
):
    monkeypatch.setattr(
        "app.core.origin_guard.get_settings",
        lambda: SimpleNamespace(
            app_env="production",
            browser_allowed_origins="https://payflow.example",
        ),
    )

    response = client.post(
        "/api/v1/auth/login",
        json={},
        headers={
            "Cookie": "payflow_session=test-session",
        },
    )

    assert response.status_code == 403


def test_production_auth_mutation_requires_source(
    client,
    monkeypatch,
):
    monkeypatch.setattr(
        "app.core.origin_guard.get_settings",
        lambda: SimpleNamespace(
            app_env="production",
            browser_allowed_origins="https://payflow.example",
        ),
    )

    response = attempt_login(client)

    assert response.status_code == 403
