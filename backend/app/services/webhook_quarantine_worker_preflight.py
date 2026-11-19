"""Diagnostic-only security preflight for a future quarantine worker.

The dedicated payflow_quarantine_worker role does not yet exist.

A future worker should have EXECUTE permission on one reviewed
database operation, not direct access to the inbox, financial
tables or quarantine audit records.

This preflight verifies PostgreSQL connection identity and the
absence of direct table privileges.

It does NOT authorize work, establish tenant access, issue a
capability token, process events, change status, or create roles.

No inserts, updates, deletes, commits, rollbacks, or gateway calls.

Even a successful diagnostic is NOT sufficient to activate a
durable quarantine processor. Trusted job authorization, a
reviewed atomic database operation, and real PostgreSQL tests
are separately required.
"""

from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import get_settings


EXPECTED_ROLE = "payflow_quarantine_worker"

PROTECTED_RELATIONS = (
    "payflow.provider_event_inbox",
    "payflow.webhook_quarantine_audit",
    "payflow.payment_orders",
    "payflow.payment_attempts",
    "payflow.payment_idempotency_records",
    "payflow.payment_attempt_idempotency_records",
)

DIRECT_PRIVILEGES = (
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "TRUNCATE",
    "REFERENCES",
    "TRIGGER",
)


class QuarantineWorkerPreflightUnavailable(Exception):
    """Worker environment or database permissions are unsafe."""


@dataclass(frozen=True, slots=True)
class QuarantineWorkerPreflight:
    database_role: str
    direct_table_permissions_absent: bool
    diagnostic_only: bool = True

    # No tenant identity, authorization approval, payment
    # state, mutation permission, retry token or write action.


def inspect_quarantine_worker_privileges(
    db: Session,
) -> QuarantineWorkerPreflight:
    """Check database security properties without modifying state.

    Never use this result as authorization to process an event.
    """

    settings = get_settings()

    if (
        settings.app_env != "development"
        or settings.sandbox_payment_attempts_enabled is not True
    ):
        raise QuarantineWorkerPreflightUnavailable(
            "Sandbox quarantine worker inspection disabled"
        )

    if not db.in_transaction():
        raise QuarantineWorkerPreflightUnavailable(
            "Caller-owned transaction required"
        )

    bind = db.get_bind()

    if bind is None or bind.dialect.name != "postgresql":
        raise QuarantineWorkerPreflightUnavailable(
            "PostgreSQL transaction required"
        )

    # Read actual database identities, not caller-supplied
    # strings or environment-provided role claims.
    identity = db.execute(
        text("""
            SELECT
                current_user,
                session_user,
                current_setting('transaction_read_only'),
                current_setting('transaction_isolation')
        """)
    ).one()

    effective_role, login_role, read_only, isolation = identity

    if (
        effective_role != EXPECTED_ROLE
        or login_role != EXPECTED_ROLE
    ):
        raise QuarantineWorkerPreflightUnavailable(
            "Dedicated worker database identity required"
        )

    if read_only != "off":
        raise QuarantineWorkerPreflightUnavailable(
            "Unexpected read-only transaction configuration"
        )

    if isolation != "read committed":
        raise QuarantineWorkerPreflightUnavailable(
            "Unexpected transaction isolation level"
        )

    # This worker must not receive broad table permissions.
    # A future tightly scoped database function, if approved,
    # will be the only mutation mechanism.
    for relation in PROTECTED_RELATIONS:
        for privilege in DIRECT_PRIVILEGES:
            permitted = db.execute(
                text("""
                    SELECT has_table_privilege(
                        current_user,
                        :relation,
                        :privilege
                    )
                """),
                {
                    "relation": relation,
                    "privilege": privilege,
                },
            ).scalar_one()

            if permitted is not False:
                raise QuarantineWorkerPreflightUnavailable(
                    "Unexpected direct database table privilege"
                )

    return QuarantineWorkerPreflight(
        database_role=effective_role,
        direct_table_permissions_absent=True,
        diagnostic_only=True,
    )
