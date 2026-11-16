from urllib.parse import urlsplit

from starlette.datastructures import Headers
from starlette.responses import JSONResponse

from app.core.config import get_settings


UNSAFE_METHODS = frozenset({
    "POST", "PUT", "PATCH", "DELETE",
})

FETCH_SITE_VALUES = frozenset({
    "same-origin",
    "same-site",
    "cross-site",
    "none",
})


def source_origin(
    value: str,
    *,
    referer: bool = False,
) -> str | None:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or any(c.isspace() for c in value)
        or chr(92) in value
    ):
        return None

    try:
        parts = urlsplit(value)

        if (
            parts.scheme not in ("http", "https")
            or not parts.netloc
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
        ):
            return None

        if not referer and (
            parts.path or parts.query or parts.fragment
        ):
            return None

        hostname = parts.hostname.lower()
        port = parts.port

        if "%" in hostname:
            return None

        if ":" in hostname:
            hostname = f"[{hostname}]"

        if (
            parts.scheme == "https" and port == 443
        ) or (
            parts.scheme == "http" and port == 80
        ):
            port = None

        authority = hostname

        if port is not None:
            authority += f":{port}"

        return f"{parts.scheme}://{authority}"

    except (ValueError, AttributeError):
        return None


def trusted_origins(value: str) -> frozenset[str]:
    origins = set()

    for raw in value.split(","):
        candidate = raw.strip()

        if not candidate:
            continue

        origin = source_origin(candidate)

        if origin is None:
            raise RuntimeError(
                "Invalid BROWSER_ALLOWED_ORIGINS configuration"
            )

        origins.add(origin)

    return frozenset(origins)


def is_trusted_browser_request(
    headers: Headers,
    *,
    path: str,
    environment: str,
    allowed_origins: frozenset[str],
) -> bool:
    origin_header = headers.get("origin")
    referer_header = headers.get("referer")
    fetch_site = headers.get("sec-fetch-site")

    if (
        fetch_site is not None
        and fetch_site not in FETCH_SITE_VALUES
    ):
        return False

    origin = None
    referer_origin = None

    if origin_header is not None:
        origin = source_origin(origin_header)

        if origin is None or origin not in allowed_origins:
            return False

    if referer_header is not None:
        referer_origin = source_origin(
            referer_header,
            referer=True,
        )

        if (
            referer_origin is None
            or referer_origin not in allowed_origins
        ):
            return False

    if (
        origin is not None
        and referer_origin is not None
        and origin != referer_origin
    ):
        return False

    # Explicitly trusted browser origins may use a
    # separate frontend site.
    if origin is not None or referer_origin is not None:
        return True

    # A cross-site browser request without a verified
    # source origin is not trusted.
    if fetch_site == "cross-site":
        return False

    # Existing local API tests and CLI workflows have
    # no browser provenance headers. Allow these only
    # in development; CSRF tokens remain mandatory on
    # protected state-changing session endpoints.
    if environment == "development":
        return True

    cookie_header = headers.get("cookie", "")

    # Fail closed for browser-session mutations and
    # auth/organization routes outside development.
    if (
        "payflow_session=" in cookie_header
        or path.startswith("/api/v1/auth/")
        or path.startswith("/api/v1/organizations")
    ):
        return False

    # Future non-browser API-key/webhook flows require
    # their own independent authentication controls.
    return True


class UnsafeOriginGuard:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if (
            scope["type"] != "http"
            or scope.get("method") not in UNSAFE_METHODS
            or not scope.get("path", "").startswith("/api/v1/")
        ):
            await self.app(scope, receive, send)
            return

        settings = get_settings()
        allowed = trusted_origins(
            settings.browser_allowed_origins
        )

        headers = Headers(scope=scope)

        if not is_trusted_browser_request(
            headers,
            path=scope["path"],
            environment=settings.app_env,
            allowed_origins=allowed,
        ):
            response = JSONResponse(
                status_code=403,
                content={
                    "detail": "Untrusted browser origin"
                },
                headers={
                    "Cache-Control": "no-store",
                    "Vary": "Origin, Referer, Sec-Fetch-Site",
                },
            )

            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)
