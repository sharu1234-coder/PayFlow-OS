# PayFlow OS - Payment Reference Serialization Design

Status: PROTOTYPE ONLY - NOT DEPLOYED

## Problem reproduced

The isolated PostgreSQL drill demonstrated that a webhook
inbox FOR UPDATE lock does not serialize concurrent INSERT
or UPDATE operations on payment_attempts.provider_payment_id.

An unlinked observation can become stale while the inbox
row remains locked.

This is a concurrency safety gap. The reproduction did not
execute the privileged quarantine function or persist an
incorrect quarantine transition.

## Existing implementation boundaries

The read-only webhook triage service uses a tenant and inbox
record advisory lock.

The payment-reference linkage inspector uses that same
inbox-oriented cooperative lock.

The sandbox payment-attempt creator locks the parent order
before creating an attempt and initially uses provider_code
sandbox with a NULL provider_payment_id.

The synthetic inbox and reference-race fixtures use
provider_code sandbox_sim.

The existing order lock is not equivalent to a provider
reference lock, and the synthetic direct database writers
do not share an established reference-locking protocol.

## Proposed reference lock identity

Use the exact tuple:

- organization_id
- provider_code
- provider_payment_id

The test-only prototype supports sandbox_sim and payment
object identifiers of the form sim_pay_<32 lowercase hex>.

This identity deliberately differs from a webhook event ID.

Its domain-separated SHA-256 digest is truncated to a
signed 64-bit PostgreSQL advisory-lock key.

Hash collisions are theoretically possible. Locks are a
coordination mechanism, never authorization evidence.

## Reference changes

For NULL to reference, acquire the new reference lock.

For reference to NULL, acquire the old reference lock.

For old reference to new reference, acquire both locks.

Acquire multiple reference locks in deterministic ascending
key order to reduce deadlock risk.

For unchanged references, acquire the key once.

For NULL to NULL, there is no provider reference to lock.

## Mandatory transaction discipline

A future implementation must acquire the appropriate
transaction-scoped lock before checking linkage, changing
a payment reference, or deciding on quarantine.

The provider reference must be rechecked after acquiring
the lock and before acting on its absence.

Locks must be held until the transaction completes.

The implementation must define lock ordering alongside
order-row and inbox-row locks, with deadlock tests.

No current payment or webhook service is changed in
this phase.

## Important limitation: cooperative locking

An advisory lock cannot protect a transaction against
another writer that never acquires that same lock.

The security design must inventory and review every
reference writer, including raw SQL, data repair,
background jobs, admin operations and future integrations.

An application helper alone is insufficient.

Before activation, investigate a database-enforced
reference ownership boundary, such as a reviewed
reference registry and restricted write interfaces.

Any trigger, stored procedure, ACL change or migration
requires separate design, review and real PostgreSQL tests.

## Important limitation: late-arriving references

Even perfect serialization of concurrent transactions does
not prevent a reference from appearing after a quarantine
transaction has committed.

Absence at one instant is not permanent proof that an
event is unrelated to a valid payment.

An unlinked payment event must therefore remain eligible
for safe reconciliation. The system must define an
authoritative finality policy and late-link handling before
durable automatic quarantine can be approved.

No payment may be marked failed, settled or refunded
solely because of this lock contract.

## Trusted-job authorization

Reference locking does not authenticate a job or authorize
access to a tenant's inbox record.

Trusted work-item authorization remains a separate blocker.

No quarantine worker credentials, permissions, routes,
processors or successful function execution are added.

## Required future real PostgreSQL tests

1. Two writers acquiring the same reference lock.
2. Different tenants with equal provider references.
3. INSERT versus quarantine inspection.
4. UPDATE versus quarantine inspection.
5. Reference replacement in both directions.
6. Commit and rollback interleavings.
7. Lock acquisition and deadlock timeouts.
8. A non-cooperating direct SQL writer.
9. An old reference and a new reference transition.
10. A payment reference arriving after the decision commits.
11. Crash recovery with transaction-scoped locks.
12. All synthetic financial and webhook records removed.

## Decision

NO-GO: worker activation remains blocked.

The current phase validates only deterministic identity
and lock-order planning.

It does not enforce the protocol in PostgreSQL, grant
permissions, authorize work, resolve the reproduced race,
or approve production use.
