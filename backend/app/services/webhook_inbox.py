"""Atomic ingestion of verified synthetic sandbox webhooks.

No public HTTP route, real gateway connection, financial-state
mutation, automatic retries, or event-processing worker.

The tenant ID and signing secret must come from trusted
server-side configuration, never the incoming event body.

The caller owns the SQLAlchemy transaction: commit on success
and rollback on any error. PostgreSQL READ COMMITTED is the
intended isolation level. Higher isolation may raise a
serialization error, which callers must not silently retry.

The inbox only records delivery evidence. It never confirms
that the corresponding payment or refund is settled.
"""

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.webhooks import VerifiedProviderEvent
from app.payments.webhook_contracts import (
    verify_sandbox_webhook,
)


IDENTITY_CONSTRAINT = "uq_provider_event_inbox_identity"


class WebhookInboxDisabled(Exception):
    """Synthetic event ingestion disabled by deployment policy."""


class WebhookInboxConflict(Exception):
    """An event identity already references different content."""


class WebhookInboxUnavailable(Exception):
    """An inserted or existing event cannot safely be resolved."""


@dataclass(frozen=True, slots=True)
class WebhookInboxResult:
    record_id: UUID
    organization_id: UUID
    provider_code: str
    event_id: str
    status: str
    replayed: bool


def receive_sandbox_webhook(
    db: Session,
    *,
    expected_organization_id: UUID,
    signing_secret: bytes,
    timestamp: str,
    signature: str,
    raw_body: bytes,
    now: int,
) -> WebhookInboxResult:
    """Verify and insert/replay one sandbox event atomically.

    The unique constraint serializes conflicting claims for the
    same (organization, provider, event ID).

    An identical re-signed delivery may have a different
    signature timestamp; the authenticated raw-body hash and
    event details must remain identical.

    REPLAYED means already recorded, not already processed.
    """

    settings = get_settings()

    if (
        settings.app_env != "development"
        or settings.sandbox_payment_attempts_enabled is not True
    ):
        raise WebhookInboxDisabled(
            "Sandbox webhook ingestion disabled"
        )

    # Always verify inside this service. Never accept a
    # caller-constructed VerifiedSandboxEvent as proof.
    event = verify_sandbox_webhook(
        expected_organization_id=expected_organization_id,
        signing_secret=signing_secret,
        timestamp=timestamp,
        signature=signature,
        raw_body=raw_body,
        now=now,
    )

    statement = (
        pg_insert(VerifiedProviderEvent)
        .values(
            organization_id=event.organization_id,
            provider_code=event.provider_code,
            event_id=event.event_id,
            event_type=event.event_type.value,
            provider_object_id=event.provider_object_id,
            occurred_at=event.occurred_at,
            signed_at=event.signed_at,
            payload_sha256=event.payload_sha256,
            status="received",
        )
        .on_conflict_do_nothing(
            constraint=IDENTITY_CONSTRAINT
        )
        .returning(VerifiedProviderEvent.id)
    )

    # One atomic database conflict decision. No SELECT-then-
    # INSERT race and no UPDATE of an existing event.
    inserted_id = db.execute(
        statement
    ).scalar_one_or_none()

    stored = db.scalar(
        select(VerifiedProviderEvent).where(
            VerifiedProviderEvent.organization_id
            == event.organization_id,
            VerifiedProviderEvent.provider_code
            == event.provider_code,
            VerifiedProviderEvent.event_id
            == event.event_id,
        )
    )

    if stored is None:
        raise WebhookInboxUnavailable(
            "Verified webhook record not available"
        )

    # The identity key is unique, but the same event ID must
    # never silently represent different business content.
    if (
        stored.organization_id != event.organization_id
        or stored.provider_code != event.provider_code
        or stored.event_id != event.event_id
        or stored.event_type != event.event_type.value
        or stored.provider_object_id != event.provider_object_id
        or stored.occurred_at != event.occurred_at
        or stored.payload_sha256 != event.payload_sha256
    ):
        raise WebhookInboxConflict(
            "Webhook event identity conflicts with existing content"
        )

    if (
        inserted_id is not None
        and inserted_id != stored.id
    ):
        raise WebhookInboxUnavailable(
            "Webhook insertion identity mismatch"
        )

    return WebhookInboxResult(
        record_id=stored.id,
        organization_id=stored.organization_id,
        provider_code=stored.provider_code,
        event_id=stored.event_id,
        status=stored.status,
        replayed=(inserted_id is None),
    )
