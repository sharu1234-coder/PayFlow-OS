from app.core.config import get_settings
from app.core.origin_guard import trusted_origins


def browser_cors_origins() -> list[str]:
    settings = get_settings()

    origins = sorted(
        trusted_origins(settings.browser_allowed_origins)
    )

    if settings.app_env != "development":
        if not origins:
            raise RuntimeError(
                "Nondevelopment environments require "
                "explicit trusted HTTPS browser origins"
            )

        for origin in origins:
            if not origin.startswith("https://"):
                raise RuntimeError(
                    "Nondevelopment browser origins "
                    "must use HTTPS"
                )

    return origins


def browser_cors_options() -> dict:
    return {
        "allow_origins": browser_cors_origins(),
        "allow_credentials": True,
        "allow_methods": [
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
            "OPTIONS",
        ],
        "allow_headers": [
            "Content-Type",
            "X-CSRF-Token",
            "Idempotency-Key",
        ],
        "max_age": 600,
    }
