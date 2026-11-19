"""Pure quarantine review policy for synthetic sandbox webhooks.

This module does not execute, authorize or persist a quarantine.

It accepts the result of the existing read-only linked triage
inspector and classifies what an authorized worker should consider.

IMPORTANT:
A supplied inspection is not proof of merchant authorization,
an authenticated provider, or a current database state.

A future writer MUST independently re-read and revalidate
the tenant-scoped event and reference under transaction locks
before applying any durable transition.

No SQL, gateway calls, event status writes, financial changes,
refund processing, retries or transaction management.
"""

import re

from dataclasses import dataclass
from enum import Enum
from uuid import UUID

from app.payments.webhook_processing_policy import (
    TriageAction,
    TriageReason,
)
from app.services.webhook_linked_triage import (
    LinkedWebhookTriageInspection,
)
from app.services.webhook_payment_linkage import (
    PaymentLinkKind,
)


_EVENT_ID_PATTERN = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z",
    flags=re.ASCII,
)


class QuarantinePolicyError(ValueError):
    """Inspection cannot be safely classified."""


class QuarantineReviewDisposition(str, Enum):
    REVIEW_QUARANTINE = "review_quarantine"
    HOLD_FOR_RECONCILIATION = "hold_for_reconciliation"
    NO_CHANGE = "no_change"


class QuarantineReviewReason(str, Enum):
    UNLINKED_PAYMENT = "unlinked_payment"
    REFUND_LINKAGE_UNAVAILABLE = "refund_linkage_unavailable"
    PROVIDER_READ_REQUIRED = "provider_read_required"
    ALREADY_RESOLVED = "already_resolved"


@dataclass(frozen=True, slots=True)
class QuarantineReviewProposal:
    organization_id: UUID
    record_id: UUID
    event_id: str
    disposition: QuarantineReviewDisposition
    reason: QuarantineReviewReason
    persisted: bool = False

    # Deliberately no:
    # - database operation or transaction instruction
    # - new inbox lifecycle status
    # - provider confirmation
    # - payment/refund state
    # - retry authorization
    # - privileged role or actor claim


def _valid_uuid(value: object) -> bool:
    return isinstance(value, UUID) and value.int != 0


def propose_quarantine_review(
    inspection: LinkedWebhookTriageInspection,
) -> QuarantineReviewProposal:
    """Classify a read-only inspection without granting write authority.

    This is a pure review policy. A future authorized processor
    must independently re-fetch, lock and revalidate the event.
    """

    if not isinstance(
        inspection,
        LinkedWebhookTriageInspection,
    ):
        raise TypeError(
            "Expected linked webhook triage inspection"
        )

    if (
        not _valid_uuid(inspection.organization_id)
        or not _valid_uuid(inspection.record_id)
    ):
        raise QuarantinePolicyError(
            "Invalid tenant or inbox record identity"
        )

    if (
        type(inspection.event_id) is not str
        or _EVENT_ID_PATTERN.fullmatch(
            inspection.event_id
        ) is None
    ):
        raise QuarantinePolicyError(
            "Invalid stored event identity"
        )

    if inspection.persisted is not False:
        raise QuarantinePolicyError(
            "Inspection must be non-persisted"
        )

    if (
        not isinstance(inspection.action, TriageAction)
        or not isinstance(inspection.reason, TriageReason)
    ):
        raise QuarantinePolicyError(
            "Invalid triage decision"
        )

    if (
        inspection.linkage_kind is not None
        and not isinstance(
            inspection.linkage_kind,
            PaymentLinkKind,
        )
    ):
        raise QuarantinePolicyError(
            "Invalid linkage category"
        )

    has_any_local_id = (
        inspection.local_attempt_id is not None
        or inspection.local_order_id is not None
    )

    if has_any_local_id:
        if (
            not _valid_uuid(inspection.local_attempt_id)
            or not _valid_uuid(inspection.local_order_id)
        ):
            raise QuarantinePolicyError(
                "Incomplete local payment identity"
            )

    def proposal(
        disposition: QuarantineReviewDisposition,
        reason: QuarantineReviewReason,
    ) -> QuarantineReviewProposal:
        return QuarantineReviewProposal(
            organization_id=inspection.organization_id,
            record_id=inspection.record_id,
            event_id=inspection.event_id,
            disposition=disposition,
            reason=reason,
            persisted=False,
        )

    # Previously resolved inbox event. Never process twice.
    if (
        inspection.action is TriageAction.NO_ACTION
        and inspection.reason
        is TriageReason.ALREADY_RESOLVED
        and inspection.linkage_kind is None
        and not has_any_local_id
    ):
        return proposal(
            QuarantineReviewDisposition.NO_CHANGE,
            QuarantineReviewReason.ALREADY_RESOLVED,
        )

    # A matching LOCAL reference warrants a future,
    # independently authorized read-only provider check.
    # Local state is not provider-confirmed state.
    if (
        inspection.action is TriageAction.RECONCILE
        and inspection.reason
        is TriageReason.READ_CONFIRMATION_REQUIRED
        and inspection.linkage_kind
        is PaymentLinkKind.LOCAL_REFERENCE
        and has_any_local_id
    ):
        return proposal(
            QuarantineReviewDisposition.HOLD_FOR_RECONCILIATION,
            QuarantineReviewReason.PROVIDER_READ_REQUIRED,
        )

    # Unknown local payment reference.
    # REVIEW_QUARANTINE is not a durable DB update.
    if (
        inspection.action is TriageAction.QUARANTINE
        and inspection.reason is TriageReason.UNKNOWN_OBJECT
        and inspection.linkage_kind
        is PaymentLinkKind.UNLINKED
        and not has_any_local_id
    ):
        return proposal(
            QuarantineReviewDisposition.REVIEW_QUARANTINE,
            QuarantineReviewReason.UNLINKED_PAYMENT,
        )

    # Refund linkage does not yet have a trusted durable model.
    if (
        inspection.action is TriageAction.QUARANTINE
        and inspection.reason is TriageReason.UNKNOWN_OBJECT
        and inspection.linkage_kind
        is PaymentLinkKind.REFUND_UNSUPPORTED
        and not has_any_local_id
    ):
        return proposal(
            QuarantineReviewDisposition.REVIEW_QUARANTINE,
            QuarantineReviewReason.REFUND_LINKAGE_UNAVAILABLE,
        )

    # All conflicting or incomplete combinations fail closed.
    raise QuarantinePolicyError(
        "Inconsistent webhook triage observation"
    )
