# PayFlow OS — Restricted Webhook Quarantine Audit Foundation

## Phase 3C.3E.2A

A database schema foundation only. No active quarantine writer.

Production activation approval: NOT GRANTED.

## Schema

Table: `payflow.webhook_quarantine_audit`

It contains:

- Audit ID
- Organization ID
- Synthetic provider code
- Verified provider event ID
- Explicit quarantine reason code
- Processor identity label
- From/to lifecycle descriptions
- Database-generated transition timestamp

The composite foreign key points to the existing verified
inbox uniqueness constraint on organization, provider and
event ID. It avoids introducing a new inbox unique index.

Only one quarantine audit row per verified inbox identity is
allowed by the database unique constraint.

The two supported reason codes are:

- `unlinked_payment`
- `refund_linkage_unavailable`

Only the `received` -> `quarantined` transition is represented.

## Security boundary

The table is not accessible by the public application runtime.

The migration explicitly revokes all table privileges from
PUBLIC and `payflow_runtime`.

No worker role is created, no privileges are granted, and
no SECURITY DEFINER function is installed in this phase.

No HTTP endpoints or financial operations are implemented.

A processor identity string is metadata, not evidence of
authorization. Authorization must be established independently
before a later worker inserts any audit row.

## Important limitations

The audit schema does not enforce atomicity with the inbox
status update by itself. The future authorized processor must
perform both changes in one transaction and fail closed if
either operation fails.

The audit table is not yet externally writable. The database
migration owner still has owner privileges; this design does
not claim an immutable WORM audit log.

The existing API runtime still cannot update inbox lifecycle
status, and this migration must not change that.

The current `processed_at` constraint requires a database
timestamp when an inbox row becomes quarantined. No such
transition is implemented in Phase 3C.3E.2A.

## Validation gates

1. Offline migration SQL and ORM constraints
2. Complete backend regression
3. Existing credential and dependency checks
4. Approved disposable PostgreSQL migration/rollback drill
5. Actual PostgreSQL role privilege checks

No schema application to the main development database,
staging or production until these gates are reviewed.

## Future Phase 3C.3E.2B

Verify the audit migration against the approved disposable
database, including foreign-key tenant integrity, unique
event identity, restricted runtime privileges, rollback,
and complete baseline restoration.

A later subphase will consider a dedicated worker and atomic
status/audit transition only after an explicit security review.
