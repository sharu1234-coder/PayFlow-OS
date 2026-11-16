import re
from collections.abc import Mapping

from sqlalchemy import event
from sqlalchemy.orm import Session

from app.models import AuditEvent


class UnsafeAuditPayload(ValueError):
    pass


FORBIDDEN_FIELD_PATTERNS = (
    "password",
    "token",
    "secret",
    "authorization",
    "cookie",
    "private_key",
    "api_key",
    "cvv",
    "card_number",
    "bank_account",
    "client_ip",
    "source_ip",
    "ip_address",
)


def _normalize_field_name(name: str) -> str:
    return re.sub(
        r"[^a-z0-9]+",
        "_",
        name.casefold(),
    )


def validate_audit_payload(payload: object) -> None:
    """
    Reject known sensitive field names in new audit payloads.

    This is defense in depth. It cannot identify a secret
    hidden under an innocent-looking field name, so audit
    payloads must still use approved, minimal data.
    """
    if not isinstance(payload, Mapping):
        raise UnsafeAuditPayload(
            "Audit payload must be a mapping"
        )

    def walk(value: object, depth: int) -> None:
        if depth > 12:
            raise UnsafeAuditPayload(
                "Audit payload nesting exceeds limit"
            )

        if isinstance(value, Mapping):
            for key, item in value.items():
                if not isinstance(key, str):
                    raise UnsafeAuditPayload(
                        "Audit payload field names must be strings"
                    )

                normalized = _normalize_field_name(key)

                if any(
                    pattern in normalized
                    for pattern in FORBIDDEN_FIELD_PATTERNS
                ):
                    raise UnsafeAuditPayload(
                        "Audit payload contains a sensitive field"
                    )

                walk(item, depth + 1)

        elif isinstance(value, (list, tuple)):
            for item in value:
                walk(item, depth + 1)

    walk(payload, 0)


def _protect_audit_events(
    session: Session,
    flush_context,
    instances,
) -> None:
    for item in session.new:
        if isinstance(item, AuditEvent):
            validate_audit_payload(item.payload)


def register_audit_guard() -> None:
    if not event.contains(
        Session,
        "before_flush",
        _protect_audit_events,
    ):
        event.listen(
            Session,
            "before_flush",
            _protect_audit_events,
        )
