# PayFlow OS — Quarantine Worker Activation Security Gates

Status: **BLOCKED — NOT AUTHORIZED FOR EXECUTION**

This document describes mandatory requirements before enabling
the future sandbox webhook quarantine worker.

It does not authorize execution, credentials, permissions,
production deployment, settlement, or financial mutations.

## Current verified state

- The PostgreSQL 18 lab is isolated on 127.0.0.1:55432.
- The approved database is disposable and contains synthetic data only.
- The normal Alembic head remains a7c4e91d2b30.
- The privileged quarantine function is a test-only fixture.
- The worker role has no password, database CONNECT, or schema USAGE.
- No worker EXECUTE grant exists.
- Successful denial tests do not constitute activation approval.

## BLOCKED — trusted job authorization

The current SQL function checks session_user but does not
independently authorize a specific tenant/event work item.

Knowing an organization UUID and inbox record UUID is not
permission to mutate a tenant's webhook lifecycle.

Before activation, implement a trusted internal authorization
boundary with the following requirements:

1. Work is created only by an approved internal scheduler.
2. A work claim is bound to an exact organization and inbox ID.
3. The trusted claim cannot be created by merchant-controlled input.
4. An authenticated worker cannot substitute another tenant or event.
5. Each claim has a durable identity and an explicit expiry policy.
6. Duplicate and replayed claims cannot cause extra transitions.
7. Claims must be validated atomically with the protected operation.
8. Revoked, stale, malformed, mismatched or absent claims fail closed.
9. The worker must retain no direct protected-table privileges.
10. All authorization decisions require auditable evidence.

Current status: NO trusted durable work-claim enforcement exists
inside the dormant quarantine function.

A database login role alone is not sufficient authorization.

## BLOCKED — payment-reference race

The current function checks whether a matching payment attempt
exists before quarantining an apparently unlinked event.

Under READ COMMITTED, a concurrent transaction may create or
link a payment attempt after that existence check.

The inbox row lock alone does not serialize writes to
payflow.payment_attempts.

Before activation:

1. Define a shared serialization rule for attempt-reference
   creation, reference updates, and quarantine decisions.
2. Ensure every relevant writer participates, including legacy
   or asynchronous reconciliation paths.
3. Prove behavior for concurrent INSERT and UPDATE of
   provider_payment_id.
4. Prove behavior when a competing transaction commits.
5. Prove behavior when a competing transaction rolls back.
6. Prove behavior for a reference initially set to NULL.
7. Prevent a legitimately linked payment from being
   permanently treated as an orphan.
8. Ensure an uncertain reference is held for reconciliation,
   not silently considered settled or permanently invalid.
9. Test duplicate event IDs and tenant-separated references.
10. Test crash recovery and all transaction boundary cases.

Current status: NO complete shared reference-locking protocol
has been proved against actual concurrent PostgreSQL writers.

Do not assume SELECT EXISTS plus an inbox FOR UPDATE lock
provides serialization against payment-attempt inserts.

## BLOCKED — refund association

The current schema lacks durable, trusted refund linkage.

An unmatched refund webhook must not change payment,
refund, settlement, or ledger state.

Refund reconciliation requires separate schema and
authorization design before activation.

## BLOCKED — successful worker execution

The following are explicitly prohibited in this phase:

- Setting a quarantine-worker password
- Granting database CONNECT or schema USAGE to the worker
- Granting EXECUTE on the privileged function
- Granting direct payment, inbox, or audit-table access
- Creating a public quarantine processing endpoint
- Running a background quarantine processor
- Moving the test-only function into production migrations
- Treating synthetic webhook evidence as provider settlement

## Required future adversarial tests

- Valid claim for an exact tenant and event
- Missing claim
- Expired or revoked claim
- Wrong organization or record ID
- Claim replay and duplicate worker execution
- Concurrent workers targeting one inbox row
- Different tenants with similar provider references
- Concurrent payment-reference INSERT
- Concurrent payment-reference UPDATE
- Concurrent rollback and commit order reversals
- Database deadlock and lock timeout handling
- Audit failure causes transaction rollback
- Repeated invocation has no duplicate audit effect
- Worker cannot mutate payment, refund or settlement records
- Complete cleanup and isolated baseline restoration

## GO/NO-GO decision

Current decision: **NO-GO — WORKER MUST REMAIN DORMANT**

A future GO decision requires:

1. Reviewed trusted-job authorization implementation
2. Reviewed payment-reference serialization design
3. Real PostgreSQL adversarial concurrency tests
4. Verified worker least-privilege boundaries
5. Verified transaction rollback and audit atomicity
6. Full backend regression and CI
7. Independent security review of the final diff
8. Separate approval for every proposed privilege change

A green offline test suite alone does not satisfy these gates.

No production approval is granted by this document.
