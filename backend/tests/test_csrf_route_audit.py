import inspect

import pytest
from fastapi import HTTPException
from fastapi.params import Depends as DependsParameter

from app.api.csrf_dependencies import (
    require_authenticated_csrf,
    require_optional_csrf,
)
from app.api.membership_management import update_member_role
from app.api.membership_revocation import revoke_member
from app.api.session import logout
from app.main import app
from app.services.session_csrf import csrf_token_for_session


# These routes do not use cookie-session authorization.
# They must remain separately reviewed for abuse controls.
PUBLIC_AUTH_MUTATIONS = {
    ("POST", "/api/v1/auth/register"),
    ("POST", "/api/v1/auth/verify-email"),
    ("POST", "/api/v1/auth/resend-verification"),
    ("POST", "/api/v1/auth/login"),
}


# These operations use an authenticated browser session.
SESSION_MUTATIONS = {
    ("POST", "/api/v1/auth/logout"),
    (
        "PATCH",
        "/api/v1/organizations/"
        "{organization_id}/members/{member_id}/role",
    ),
    (
        "POST",
        "/api/v1/organizations/"
        "{organization_id}/members/{member_id}/revoke",
    ),
}


UNSAFE_METHODS = {
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
}


def dependency_calls(handler):
    signature = inspect.signature(handler)

    return {
        parameter.default.dependency
        for parameter in signature.parameters.values()
        if isinstance(
            parameter.default,
            DependsParameter,
        )
    }


def test_all_unsafe_api_routes_are_classified():
    # Fails if a new state-changing endpoint is added
    # without a security-policy review.
    paths = app.openapi().get("paths", {})

    actual = {
        (method.upper(), path)
        for path, operations in paths.items()
        if path.startswith("/api/v1/")
        for method in operations
        if method.upper() in UNSAFE_METHODS
    }

    expected = PUBLIC_AUTH_MUTATIONS | SESSION_MUTATIONS

    assert actual == expected, (
        f"Unreviewed or missing unsafe routes: "
        f"{actual.symmetric_difference(expected)}"
    )


def test_team_mutations_use_strict_csrf_dependency():
    for handler in (
        update_member_role,
        revoke_member,
    ):
        dependencies = dependency_calls(handler)

        assert require_authenticated_csrf in dependencies
        assert require_optional_csrf not in dependencies


def test_logout_uses_optional_csrf_dependency():
    dependencies = dependency_calls(logout)

    assert require_optional_csrf in dependencies
    assert require_authenticated_csrf not in dependencies


def test_strict_guard_requires_session_cookie():
    with pytest.raises(HTTPException) as error:
        require_authenticated_csrf(
            session_token=None,
            csrf_header=None,
        )

    assert error.value.status_code == 401


def test_strict_guard_rejects_missing_csrf_header():
    with pytest.raises(HTTPException) as error:
        require_authenticated_csrf(
            session_token="session-one-example-token-2026",
            csrf_header=None,
        )

    assert error.value.status_code == 403


def test_strict_guard_rejects_invalid_csrf_header():
    with pytest.raises(HTTPException) as error:
        require_authenticated_csrf(
            session_token="session-one-example-token-2026",
            csrf_header="invalid",
        )

    assert error.value.status_code == 403


def test_csrf_token_from_another_session_is_rejected():
    first_session = "first-browser-session-2026-example-123456"
    second_session = "second-browser-session-2026-example-12345"

    first_csrf = csrf_token_for_session(first_session)

    with pytest.raises(HTTPException) as error:
        require_authenticated_csrf(
            session_token=second_session,
            csrf_header=first_csrf,
        )

    assert error.value.status_code == 403


def test_strict_guard_accepts_matching_csrf():
    session_token = "valid-local-session-test-token-2026"
    csrf = csrf_token_for_session(session_token)

    assert require_authenticated_csrf(
        session_token=session_token,
        csrf_header=csrf,
    ) is None


def test_optional_guard_allows_cookie_less_logout():
    assert require_optional_csrf(
        session_token=None,
        csrf_header=None,
    ) is None


def test_optional_guard_rejects_cookie_without_csrf():
    with pytest.raises(HTTPException) as error:
        require_optional_csrf(
            session_token="logout-session-test-token-2026",
            csrf_header=None,
        )

    assert error.value.status_code == 403


def test_optional_guard_accepts_matching_csrf():
    session_token = "logout-session-test-token-2026"
    csrf = csrf_token_for_session(session_token)

    assert require_optional_csrf(
        session_token=session_token,
        csrf_header=csrf,
    ) is None
