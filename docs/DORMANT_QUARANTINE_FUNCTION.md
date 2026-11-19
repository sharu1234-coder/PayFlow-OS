# Phase 3C.3E.3B.1 — Dormant Atomic Quarantine Function

## Status

Offline implementation only. NOT ACTIVATED.

This migration is a security prototype for an approved
disposable PostgreSQL database. It must not be interpreted
as authorization to run a quarantine worker.

## Function

`payflow.quarantine_sandbox_webhook(uuid, uuid)`

The database function checks the authenticated session identity,
the approved disposable database name, and the transaction mode.

It acquires a tenant-scoped inbox row lock, checks lifecycle
status, and independently rechecks exact local payment linkage.

For an unlinked synthetic payment, it classifies the event as
`unlinked_payment`.

For an unsupported synthetic refund, it classifies the event
as `refund_linkage_unavailable`.

A linked payment remains `received` and requires separate
provider reconciliation.

An eligible event is conditionally changed from `received`
to `quarantined`; the matching audit record is inserted in
the same transaction. Any error must roll back the operation.

## Permission boundary

No worker login or role is created in this phase.

No EXECUTE permission is granted to the future worker.

The migration revokes PUBLIC and payflow_runtime execution
permissions in the same transaction as function creation.

The function also checks session_user to reject invocations
from other login identities, including the migration owner.

The application runtime retains no audit-table access or
inbox UPDATE privileges.

## Security limitations

The future worker is an internal cross-tenant processor.
It must consume authorized jobs from a trusted internal
boundary. This function does not itself authenticate a
merchant or validate a job token.

The current sandbox webhook inbox is verified at ingestion.
This operation does not re-verify HMAC signatures.

The function does not establish provider settlement, payment
success, refund completion, or authorization to retry charges.

It is deliberately hard-coded to the disposable database
identity so accidental use in another database fails closed.

The function is not independently tested on real PostgreSQL
until the dedicated worker role and execution permissions
are separately reviewed and provisioned.

## Next gates

1. Offline function and migration tests
2. Full existing backend regression
3. Review of role creation and cluster-level effects
4. Controlled disposable PostgreSQL function-install drill
5. Verified PUBLIC/runtime execution denial
6. Dedicated worker identity and least-privilege test
7. Concurrency, rollback, idempotency and cross-tenant tests
8. Explicit review before any deployment outside the drill DB

No production approval is granted by this phase.

## Test-only packaging safeguard

The privileged-function prototype is stored in
`backend/tests/fixtures/`, not in the normal Alembic
`versions/` directory.

The normal migration head remains `a7c4e91d2b30`.

Only the explicitly approved disposable PostgreSQL drill
may invoke the prototype's upgrade and downgrade helpers.

No application deployment runs this fixture through Alembic.
A future production migration requires a separate security
review, dedicated authorization model and new implementation.
