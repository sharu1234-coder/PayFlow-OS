from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.core.release_gate import (
    DeploymentConfigurationError,
    validate_deployment_configuration,
)
from app.main import app


def production_settings(**overrides):
    values = {
        "app_env": "production",
        "csrf_secret": SecretStr("c" * 48),
        "login_throttle_secret": SecretStr("l" * 48),
        "browser_allowed_origins": (
            "https://merchant.payflow.example"
        ),
        "database_url": (
            "postgresql+psycopg://payflow_runtime:"
            "dummy@db.example/payflow_db?sslmode=verify-full"
        ),
        "migration_database_url": (
            "postgresql+psycopg://payflow_migrator:"
            "dummy@db.example/payflow_db?sslmode=verify-full"
        ),
    }

    values.update(overrides)
    return SimpleNamespace(**values)


@pytest.fixture
def client():
    with TestClient(app) as instance:
        yield instance


def test_development_preserves_local_configuration():
    validate_deployment_configuration(
        SimpleNamespace(app_env="development")
    )


def test_valid_production_configuration_passes_policy():
    validate_deployment_configuration(
        production_settings()
    )


def test_valid_staging_configuration_passes_policy():
    validate_deployment_configuration(
        production_settings(app_env="staging")
    )


def test_unknown_environment_is_rejected():
    with pytest.raises(DeploymentConfigurationError):
        validate_deployment_configuration(
            production_settings(app_env="unknown")
        )


@pytest.mark.parametrize(
    "secret_name",
    ["csrf_secret", "login_throttle_secret"],
)
def test_short_production_secrets_are_rejected(secret_name):
    with pytest.raises(DeploymentConfigurationError):
        validate_deployment_configuration(
            production_settings(**{
                secret_name: SecretStr("too-short"),
            })
        )


def test_reused_production_secrets_are_rejected():
    with pytest.raises(DeploymentConfigurationError):
        validate_deployment_configuration(
            production_settings(
                login_throttle_secret=SecretStr("c" * 48)
            )
        )


def test_missing_production_frontend_origin_is_rejected():
    with pytest.raises(DeploymentConfigurationError):
        validate_deployment_configuration(
            production_settings(browser_allowed_origins="")
        )


def test_http_production_frontend_is_rejected():
    with pytest.raises(DeploymentConfigurationError):
        validate_deployment_configuration(
            production_settings(
                browser_allowed_origins=(
                    "http://merchant.payflow.example"
                )
            )
        )


@pytest.mark.parametrize(
    "origin",
    [
        "https://localhost:5173",
        "https://127.0.0.1:5173",
        "https://10.0.0.5",
    ],
)
def test_local_production_origins_are_rejected(origin):
    with pytest.raises(DeploymentConfigurationError):
        validate_deployment_configuration(
            production_settings(
                browser_allowed_origins=origin,
            )
        )


def test_insecure_database_ssl_mode_is_rejected():
    with pytest.raises(DeploymentConfigurationError):
        validate_deployment_configuration(
            production_settings(
                database_url=(
                    "postgresql+psycopg://payflow_runtime:"
                    "dummy@db.example/payflow_db?sslmode=require"
                )
            )
        )


def test_non_postgresql_database_is_rejected():
    with pytest.raises(DeploymentConfigurationError):
        validate_deployment_configuration(
            production_settings(
                database_url="sqlite:///test.db"
            )
        )


def test_same_runtime_and_migration_role_is_rejected():
    settings = production_settings()

    with pytest.raises(DeploymentConfigurationError):
        validate_deployment_configuration(
            production_settings(
                migration_database_url=settings.database_url
            )
        )


def test_administrative_runtime_role_is_rejected():
    with pytest.raises(DeploymentConfigurationError):
        validate_deployment_configuration(
            production_settings(
                database_url=(
                    "postgresql+psycopg://postgres:"
                    "dummy@db.example/payflow_db"
                    "?sslmode=verify-full"
                )
            )
        )


def test_development_routes_remain_available(client):
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401


def test_production_live_health_remains_available(
    client,
    monkeypatch,
):
    monkeypatch.setattr(
        "app.core.release_gate.get_settings",
        production_settings,
    )

    response = client.get("/api/v1/health/live")
    assert response.status_code == 200


@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/docs"),
        ("GET", "/openapi.json"),
        ("GET", "/api/v1/auth/me"),
        ("GET", "/api/v1/organizations"),
        ("POST", "/api/v1/auth/login"),
        ("POST", "/api/v1/auth/register"),
        ("POST", "/api/v1/auth/logout"),
        ("GET", "/api/v1/unknown-feature"),
    ],
)
def test_production_api_routes_are_locked(
    client,
    monkeypatch,
    method,
    path,
):
    monkeypatch.setattr(
        "app.core.release_gate.get_settings",
        production_settings,
    )

    response = client.request(method, path)

    assert response.status_code == 503
    assert response.json()["detail"] == "Service unavailable"
    assert response.headers["cache-control"] == "no-store"


def test_staging_api_routes_are_also_locked(
    client,
    monkeypatch,
):
    monkeypatch.setattr(
        "app.core.release_gate.get_settings",
        lambda: production_settings(app_env="staging"),
    )

    response = client.get("/api/v1/auth/me")

    assert response.status_code == 503


def test_invalid_production_configuration_blocks_health(
    client,
    monkeypatch,
):
    monkeypatch.setattr(
        "app.core.release_gate.get_settings",
        lambda: production_settings(
            browser_allowed_origins=""
        ),
    )

    response = client.get("/api/v1/health/live")

    assert response.status_code == 503


def test_unknown_environment_blocks_health(
    client,
    monkeypatch,
):
    monkeypatch.setattr(
        "app.core.release_gate.get_settings",
        lambda: production_settings(app_env="unknown"),
    )

    response = client.get("/api/v1/health/live")

    assert response.status_code == 503
