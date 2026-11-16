import ipaddress
from urllib.parse import urlsplit

from sqlalchemy.engine import make_url
from starlette.responses import JSONResponse

from app.core.config import get_settings
from app.core.origin_guard import trusted_origins


VALID_ENVIRONMENTS = frozenset({
    "development",
    "staging",
    "production",
})

PRELAUNCH_HEALTH_PATHS = frozenset({
    "/api/v1/health/live",
    "/api/v1/health/ready",
})


class DeploymentConfigurationError(RuntimeError):
    pass


def _check_secret(value, name: str) -> str:
    try:
        secret = value.get_secret_value()
    except (AttributeError, TypeError):
        raise DeploymentConfigurationError(
            f"{name} is not properly configured"
        ) from None

    if not isinstance(secret, str) or len(
        secret.encode("utf-8")
    ) < 32:
        raise DeploymentConfigurationError(
            f"{name} does not meet minimum strength"
        )

    return secret


def _check_database_url(value: str, name: str):
    try:
        url = make_url(value)
    except Exception:
        raise DeploymentConfigurationError(
            f"{name} has invalid connection configuration"
        ) from None

    if url.get_backend_name() != "postgresql":
        raise DeploymentConfigurationError(
            f"{name} must use PostgreSQL"
        )

    if not url.username or not url.password:
        raise DeploymentConfigurationError(
            f"{name} requires a dedicated database account"
        )

    if url.query.get("sslmode") != "verify-full":
        raise DeploymentConfigurationError(
            f"{name} requires sslmode=verify-full"
        )

    return url


def validate_deployment_configuration(settings) -> None:
    environment = settings.app_env

    if environment not in VALID_ENVIRONMENTS:
        raise DeploymentConfigurationError(
            "Unrecognized application environment"
        )

    if environment == "development":
        # Local development keeps its existing database,
        # HTTP cookies and localhost frontend configuration.
        return

    csrf_secret = _check_secret(
        settings.csrf_secret,
        "CSRF secret",
    )

    throttle_secret = _check_secret(
        settings.login_throttle_secret,
        "Login throttle secret",
    )

    if csrf_secret == throttle_secret:
        raise DeploymentConfigurationError(
            "Security secrets must be independent"
        )

    try:
        origins = trusted_origins(
            settings.browser_allowed_origins
        )
    except (RuntimeError, ValueError):
        raise DeploymentConfigurationError(
            "Trusted browser origins are invalid"
        ) from None

    if not origins:
        raise DeploymentConfigurationError(
            "At least one HTTPS browser origin is required"
        )

    for origin in origins:
        parsed = urlsplit(origin)
        host = parsed.hostname

        if parsed.scheme != "https" or not host:
            raise DeploymentConfigurationError(
                "Nondevelopment browser origins require HTTPS"
            )

        if host == "localhost" or host.endswith(".localhost"):
            raise DeploymentConfigurationError(
                "Localhost is not a deployable browser origin"
            )

        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            if (
                address.is_loopback
                or address.is_private
                or address.is_link_local
            ):
                raise DeploymentConfigurationError(
                    "Private browser origins are not permitted"
                )

    runtime_url = _check_database_url(
        settings.database_url,
        "Runtime database",
    )

    migration_url = _check_database_url(
        settings.migration_database_url,
        "Migration database",
    )

    if runtime_url.username == migration_url.username:
        raise DeploymentConfigurationError(
            "Runtime and migration roles must differ"
        )

    if runtime_url.username.lower() in {
        "postgres",
        "root",
        "payflow_migrator",
    }:
        raise DeploymentConfigurationError(
            "Runtime database cannot use an administrative role"
        )


def _blocked_response():
    return JSONResponse(
        status_code=503,
        content={"detail": "Service unavailable"},
        headers={
            "Cache-Control": "no-store",
            "Retry-After": "3600",
            "X-Content-Type-Options": "nosniff",
        },
    )


class PrelaunchReleaseGate:
    """
    Development: pass requests through unchanged.

    Staging/production: expose only GET health endpoints.
    Everything else stays unavailable until an explicit
    release review replaces this temporary lockdown.

    This deliberately does NOT have a bypass flag.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        scope_type = scope["type"]

        if scope_type == "lifespan":
            await self.app(scope, receive, send)
            return

        try:
            settings = get_settings()
            validate_deployment_configuration(settings)
            environment = settings.app_env
        except Exception:
            environment = None

        if environment == "development":
            await self.app(scope, receive, send)
            return

        if scope_type == "websocket":
            await send({
                "type": "websocket.close",
                "code": 1008,
            })
            return

        if scope_type != "http":
            return

        if (
            environment in {"staging", "production"}
            and scope.get("method") == "GET"
            and scope.get("path") in PRELAUNCH_HEALTH_PATHS
        ):
            await self.app(scope, receive, send)
            return

        response = _blocked_response()
        await response(scope, receive, send)
