# PayFlow OS — Webhook Quarantine Security Design

## Scope

Phase 3C.3E.1 creates a deterministic quarantine REVIEW policy.

It does not update the database, execute a quarantine, grant
privileges, mark events processed, or modify payment state.

The policy result is NOT an authorization token.

## Current database constraints

The verified provider event inbox uses three lifecycle states:

- received
- quarantined
- processed

The existing check constraint requires `processed_at` to be
non-null for quarantined or processed rows.

The current application runtime role has SELECT and INSERT
permissions on `payflow.provider_event_inbox`.

It must continue to have NO UPDATE, DELETE, or TRUNCATE.

The `processed` lifecycle must not be used merely because an
event has been inspected or a local payment reference exists.

## Decision matrix

| Existing inspection | Review result |
| --- | --- |
| Unknown local payment reference | Review quarantine |
| Refund without durable trusted linkage | Review quarantine |
| Matching local payment reference | Hold for separate read-only reconciliation |
| Already resolved inbox event | No change |
| Incomplete or conflicting inspection | Reject and investigate |

A local payment reference is not proof of payment success,
provider confirmation, settlement, or refund completion.

## Future durable transition requirements

A later implementation must satisfy ALL requirements before
any durable quarantine operation is enabled.

1. A separately authorized, development-only processor identity
   must be established. The public API runtime identity must not
   receive unrestricted inbox UPDATE privileges.

2. Merchant authorization and tenant identity must come from
   a trusted application/worker boundary, never from an
   arbitrary caller-supplied organization UUID.

3. The worker must start a database transaction and lock the
   exact tenant-scoped inbox row using a row lock. Existing
   advisory locks alone are not sufficient because they only
   coordinate participating callers.

4. The worker must re-read and re-evaluate local references
   inside the same controlled transaction. A previously issued
   review proposal cannot itself authorize the transition.

5. Reconciliation candidates must stay in `received` until
   a separately designed and authorized reconciliation process
   resolves them.

6. Only a verified `received` inbox event that still meets
   the quarantine rules may transition to `quarantined`.
   Concurrent workers must not perform duplicate transitions.

7. The transition must be conditional on organization ID,
   inbox record ID and current lifecycle. A failed conditional
   update must not silently claim success.

8. `processed_at` must use the database clock for a durable
   quarantine, to satisfy the existing status/timestamp
   constraint. It must not use webhook occurrence time.

9. Persist a structured quarantine audit reason, authorized
   processor identity and transition timestamp. Do not persist
   raw webhook bodies, signing credentials, card details or
   unfiltered gateway responses.

10. The audit write and status transition must succeed or fail
    atomically. A missing audit record must not leave an
    apparently successful quarantine transition.

11. Never modify payment orders, payment attempts, refunds,
    idempotency records, or settlement states while
    quarantining an inbox event.

12. Reconciliation and release from quarantine require
    separate explicitly reviewed workflows, not a generic
    status update endpoint.

13. Migration and PostgreSQL permission tests must prove
    public/runtime roles cannot perform direct financial or
    unauthorized inbox mutations.

14. Tests must cover cross-tenant access, concurrent workers,
    duplicate delivery, missing records, already-resolved
    events, rollback, permission denial and audit integrity.

15. No live gateway credentials, real-money processing,
    public webhook routes or production worker activation
    are authorized by this phase.

## Next implementation boundary

Phase 3C.3E.2 may implement a separately reviewed migration,
quarantine audit schema and restricted processor permission
boundary.

The permission design must be reviewed before any migration
is applied to a non-disposable database.
