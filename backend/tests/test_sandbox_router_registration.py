"""Sandbox router registration contract tests.

No PostgreSQL, HTTP requests, or payment processing.
"""

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app.core.config import Settings
from app.main import create_app


SANDBOX_PATH = (
    "/api/v1/organizations/{organization_id}"
    "/payment-orders/{order_id}/attempts"
)


@pytest.mark.parametrize(
    "environment,enabled,expected",
    [
        ("development", False, False),
        ("development", True, True),
        ("staging", False, False),
        ("staging", True, False),
        ("production", False, False),
        ("production", True, False),
    ],
)
def test_sandbox_router_registration(
    environment,
    enabled,
    expected,
):
    settings = SimpleNamespace(
        app_env=environment,
        sandbox_payment_attempts_enabled=enabled,
    )

    with patch(
        "app.core.config.get_settings",
        return_value=settings,
    ) as mocked_settings:
        application = create_app()
        mocked_settings.assert_called_once_with()

    # FastAPI 0.163.1 may use _IncludedRouter objects.
    # OpenAPI exposes the effective registered endpoints.
    paths = application.openapi().get("paths", {})

    registered = "post" in paths.get(SANDBOX_PATH, {})

    assert registered is expected, (
        f"Environment={environment}, enabled={enabled}, "
        f"registered={registered}, "
        f"available_paths={list(paths)}"
    )


def test_feature_flag_defaults_to_disabled():
    field = Settings.model_fields[
        "sandbox_payment_attempts_enabled"
    ]

    assert field.default is False
