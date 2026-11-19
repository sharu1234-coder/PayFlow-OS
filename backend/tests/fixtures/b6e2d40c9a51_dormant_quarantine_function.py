"""Dormant sandbox-only atomic quarantine function.

Revision ID: b6e2d40c9a51
Revises: a7c4e91d2b30

Security constraints:
- Approved disposable database only
- Dedicated worker session identity only
- No EXECUTE grants to any application or worker role
- No new database roles
- No direct table privilege changes
- No payment, refund, or settlement state changes

This migration is a non-activated security prototype.
"""

from alembic import op
import sqlalchemy as sa


revision = "b6e2d40c9a51"
down_revision = "a7c4e91d2b30"
branch_labels = None
depends_on = None


FUNCTION_NAME = "payflow.quarantine_sandbox_webhook"

FUNCTION_SIGNATURE = (
    "payflow.quarantine_sandbox_webhook(uuid, uuid)"
)

DISPOSABLE_DB = (
    "payflow_payment_drill_20261117_020846_9fbac781"
)


FUNCTION_SQL = r"""
CREATE FUNCTION payflow.quarantine_sandbox_webhook(
    p_organization_id uuid,
    p_record_id uuid
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $payflow_quarantine$
DECLARE
    v_event payflow.provider_event_inbox%ROWTYPE;
    v_has_attempt boolean;
    v_reason text;
    v_updated_id uuid;
    v_audit_count bigint;
BEGIN
    -- This function is deliberately locked to the approved
    -- disposable database until a separate activation review.
    IF pg_catalog.current_database()
       <> 'payflow_payment_drill_20261117_020846_9fbac781'
    THEN
        RAISE EXCEPTION 'Quarantine function disabled in this database'
            USING ERRCODE = '42501';
    END IF;

    -- SECURITY DEFINER changes current_user to the owner.
    -- session_user retains the authenticated login identity.
    -- No SET ROLE impersonation should satisfy this check.
    IF session_user <> 'payflow_quarantine_worker' THEN
        RAISE EXCEPTION 'Dedicated quarantine login required'
            USING ERRCODE = '42501';
    END IF;

    IF pg_catalog.current_setting('transaction_read_only')
       <> 'off'
    THEN
        RAISE EXCEPTION 'Writable transaction required'
            USING ERRCODE = '25006';
    END IF;

    IF pg_catalog.current_setting('transaction_isolation')
       <> 'read committed'
    THEN
        RAISE EXCEPTION 'READ COMMITTED transaction required'
            USING ERRCODE = '25001';
    END IF;

    IF p_organization_id IS NULL OR p_record_id IS NULL THEN
        RAISE EXCEPTION 'Valid event identity required'
            USING ERRCODE = '22023';
    END IF;

    -- The row lock protects the durable status transition,
    -- including against non-cooperating database writers.
    -- Always scope by BOTH tenant and inbox-record identity.
    SELECT e.*
      INTO v_event
      FROM payflow.provider_event_inbox AS e
     WHERE e.organization_id = p_organization_id
       AND e.id = p_record_id
     FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Verified inbox event not found'
            USING ERRCODE = 'P0002';
    END IF;

    IF v_event.provider_code <> 'sandbox_sim' THEN
        RAISE EXCEPTION 'Unsupported provider'
            USING ERRCODE = '22023';
    END IF;

    -- An already quarantined record must have exactly one
    -- matching audit row. Never create a second transition.
    IF v_event.status = 'quarantined' THEN
        SELECT COUNT(*)
          INTO v_audit_count
          FROM payflow.webhook_quarantine_audit AS a
         WHERE a.organization_id = v_event.organization_id
           AND a.provider_code = v_event.provider_code
           AND a.event_id = v_event.event_id
           AND a.from_status = 'received'
           AND a.to_status = 'quarantined';

        IF v_audit_count <> 1 THEN
            RAISE EXCEPTION 'Quarantine audit integrity failure'
                USING ERRCODE = '23514';
        END IF;

        RETURN 'already_quarantined';
    END IF;

    IF v_event.status = 'processed' THEN
        RETURN 'already_resolved';
    END IF;

    IF v_event.status <> 'received'
       OR v_event.processed_at IS NOT NULL
    THEN
        RAISE EXCEPTION 'Unsafe inbox lifecycle'
            USING ERRCODE = '23514';
    END IF;

    -- Local association is NOT provider settlement evidence.
    -- A matching payment reference is never quarantined here.
    -- It must remain received for separate reconciliation.
    IF v_event.event_type LIKE 'payment.%' THEN
        SELECT EXISTS (
            SELECT 1
              FROM payflow.payment_attempts AS a
             WHERE a.organization_id = v_event.organization_id
               AND a.provider_code = v_event.provider_code
               AND a.provider_payment_id = v_event.provider_object_id
        )
        INTO v_has_attempt;

        IF v_has_attempt THEN
            RETURN 'hold_for_reconciliation';
        END IF;

        v_reason := 'unlinked_payment';

    ELSIF v_event.event_type LIKE 'refund.%' THEN
        -- No durable, trusted refund-reference linkage exists.
        v_reason := 'refund_linkage_unavailable';

    ELSE
        RAISE EXCEPTION 'Unsupported webhook event type'
            USING ERRCODE = '22023';
    END IF;

    -- Both writes are part of this one SQL function call
    -- and the caller-owned PostgreSQL transaction.
    -- Errors must propagate; never swallow audit failures.
    UPDATE payflow.provider_event_inbox AS e
       SET status = 'quarantined',
           processed_at = pg_catalog.transaction_timestamp()
     WHERE e.organization_id = v_event.organization_id
       AND e.id = v_event.id
       AND e.status = 'received'
       AND e.processed_at IS NULL
     RETURNING e.id INTO v_updated_id;

    IF v_updated_id IS DISTINCT FROM v_event.id THEN
        RAISE EXCEPTION 'Conditional quarantine transition failed'
            USING ERRCODE = '23514';
    END IF;

    INSERT INTO payflow.webhook_quarantine_audit (
        organization_id,
        provider_code,
        event_id,
        reason_code,
        processor_identity,
        from_status,
        to_status
    )
    VALUES (
        v_event.organization_id,
        v_event.provider_code,
        v_event.event_id,
        v_reason,
        session_user,
        'received',
        'quarantined'
    );

    RETURN 'quarantined';
END;
$payflow_quarantine$
"""


def upgrade() -> None:
    op.execute(FUNCTION_SQL)

    # CREATE FUNCTION grants EXECUTE to PUBLIC by default.
    # Revoke in the SAME migration transaction. The migration
    # runner must not use autocommit for this revision.
    #
    # Crucially: do not grant EXECUTE to the worker yet.
    op.execute(
        "REVOKE ALL PRIVILEGES ON FUNCTION "
        + FUNCTION_SIGNATURE
        + " FROM PUBLIC, payflow_runtime"
    )

    # No GRANT. The function remains dormant.
    # No new roles or table privileges.


def downgrade() -> None:
    # Never remove the operation while audit history exists.
    bind = op.get_bind()

    has_audit = bind.execute(
        sa.text(
            "SELECT EXISTS ("
            "SELECT 1 "
            "FROM payflow.webhook_quarantine_audit"
            ")"
        )
    ).scalar_one()

    if has_audit:
        raise RuntimeError(
            "Refusing to drop quarantine function with audit history"
        )

    op.execute(
        "DROP FUNCTION " + FUNCTION_SIGNATURE
    )
