"""Offline prototype of a payment-reference lock identity.

NOT a deployed reference writer or quarantine processor.

No database connections, SQL, payment state changes, commits,
credentials, authorization, or worker activation.

The key design is only one candidate component of a future
database-enforced serialization protocol.

It does not protect against non-participating writers or
late-arriving payment references.
"""

import hashlib
import re
from uuid import UUID


_DOMAIN = b"payflow.payment.reference.lock.v1\x00"

_PAYMENT_REFERENCE = re.compile(
    r"sim_pay_[0-9a-f]{32}\Z",
    flags=re.ASCII,
)

_SUPPORTED_PROVIDER = "sandbox_sim"


class ReferenceLockContractError(ValueError):
    """An invalid reference-lock identity was supplied."""


def _validate_identity(
    organization_id,
    provider_code,
):
    if (
        not isinstance(organization_id, UUID)
        or organization_id.int == 0
    ):
        raise ReferenceLockContractError(
            "Valid tenant UUID required"
        )

    if (
        type(provider_code) is not str
        or provider_code != _SUPPORTED_PROVIDER
    ):
        raise ReferenceLockContractError(
            "Unsupported sandbox provider"
        )


def _validate_reference(reference):
    if (
        type(reference) is not str
        or _PAYMENT_REFERENCE.fullmatch(reference) is None
    ):
        raise ReferenceLockContractError(
            "Invalid sandbox payment reference"
        )


def payment_reference_lock_key(
    organization_id,
    provider_code,
    provider_payment_id,
):
    """Derive a deterministic signed PostgreSQL int64 lock key.

    Exact reference bytes are retained; no case normalization
    or approximate matching occurs.

    SHA-256 truncation can collide. A collision reduces
    concurrency, and this key must NEVER grant authorization.
    """

    _validate_identity(
        organization_id,
        provider_code,
    )

    _validate_reference(provider_payment_id)

    material = (
        _DOMAIN
        + organization_id.bytes
        + b"\x00"
        + provider_code.encode("ascii")
        + b"\x00"
        + provider_payment_id.encode("ascii")
    )

    digest = hashlib.sha256(material).digest()

    return int.from_bytes(
        digest[:8],
        byteorder="big",
        signed=True,
    )


def reference_change_lock_keys(
    organization_id,
    provider_code,
    previous_reference,
    next_reference,
):
    """Plan transaction lock keys for an INSERT or UPDATE.

    NULL -> reference: acquire the new-reference lock.
    reference -> NULL: acquire the old-reference lock.
    old -> new: acquire both keys.
    same -> same: acquire once.
    NULL -> NULL: no reference lock required.

    Keys are acquired in sorted order to reduce deadlock risk.

    This is a pure planning helper. It acquires no locks and
    does not authorize a payment reference update.
    """

    _validate_identity(
        organization_id,
        provider_code,
    )

    references = (
        previous_reference,
        next_reference,
    )

    keys = set()

    for reference in references:
        if reference is None:
            continue

        _validate_reference(reference)

        keys.add(
            payment_reference_lock_key(
                organization_id,
                provider_code,
                reference,
            )
        )

    return tuple(sorted(keys))
