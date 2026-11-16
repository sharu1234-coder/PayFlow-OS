import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.core.release_gate import (
    DeploymentConfigurationError,
    validate_deployment_configuration,
)


def valid_settings(**overrides):
    values = {
        "database_url": (
            "postgresql+psycopg://runtime:"
            "example@localhost:5432/payflow_db"
        ),
        "migration_database_url": (
            "postgresql+psycopg://migrator:"
            "example@localhost:5432/payflow_db"
        ),
        "csrf_secret": "c" * 48,
        "login_throttle_secret": "l" * 48,
    }

    values.update(overrides)
    return values


def test_app_environment_is_required():
    assert Settings.model_fields["app_env"].is_required()


def test_missing_environment_fails_closed(monkeypatch):
    monkeypatch.delenv("APP_ENV", raising=False)

    with pytest.raises(ValidationError) as exc:
        Settings(
            _env_file=None,
            **valid_settings(),
        )

    assert any(
        error["loc"] == ("app_env",)
        for error in exc.value.errors()
    )


@pytest.mark.parametrize(
    "environment",
    ["", "Production", "preview", "testing", "unknown"],
)
def test_invalid_environment_is_rejected(
    monkeypatch,
    environment,
):
    monkeypatch.delenv("APP_ENV", raising=False)

    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            **valid_settings(app_env=environment),
        )


@pytest.mark.parametrize(
    "environment",
    ["development", "staging", "production"],
)
def test_declared_environment_is_accepted(
    monkeypatch,
    environment,
):
    monkeypatch.delenv("APP_ENV", raising=False)

    settings = Settings(
        _env_file=None,
        **valid_settings(app_env=environment),
    )

    assert settings.app_env == environment


def test_explicit_development_preserves_local_mode(
    monkeypatch,
):
    monkeypatch.delenv("APP_ENV", raising=False)

    settings = Settings(
        _env_file=None,
        **valid_settings(app_env="development"),
    )

    validate_deployment_configuration(settings)


def test_production_still_requires_secure_configuration(
    monkeypatch,
):
    monkeypatch.delenv("APP_ENV", raising=False)

    settings = Settings(
        _env_file=None,
        **valid_settings(app_env="production"),
    )

    with pytest.raises(DeploymentConfigurationError):
        validate_deployment_configuration(settings)
