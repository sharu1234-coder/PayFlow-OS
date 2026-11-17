# PayFlow OS ? Payment Persistence Design

## Status

Phase 2B.1B ? ORM schema design and offline tests.

No payment database migration has been applied.

Production launch approval: NOT GRANTED.

## Tables

### payment_orders

- Tenant-owned merchant order
- Globally unique internal UUID identifier
- Tenant-scoped merchant order reference
- Positive signed-64-bit amount in minor units
- Three-letter uppercase currency code
- Order status: open, paid, cancelled

A composite uniqueness constraint covers organization, order ID,
amount and currency.

### payment_attempts

- Internal attempt UUID and organization ID
- Order UUID and positive attempt sequence number
- Amount and currency
- Provider code and optional provider payment ID
- Normalized payment status

A composite foreign key includes organization, order, amount
and currency. This prevents cross-tenant order references and
different-money attempts at the database relationship level.

Provider payment identity is unique within tenant and provider
when populated. PostgreSQL's normal UNIQUE semantics allow
multiple NULL provider identifiers.

An attempt is a record of an operation; it does not itself
authorize or initiate a provider request.

### payment_idempotency_records

- Tenant ID, operation and idempotency key
- Canonical request fingerprint in hexadecimal SHA-256 format
- Reservation and outcome state
- Creation timestamp

A composite unique constraint prevents duplicate keys for the
same tenant and operation.

The schema alone does not implement locking, outcome replay,
request comparison, safe provider retries or reconciliation.
Those require transaction-safe services and integration tests.

## Security

- All tables belong to schema payflow
- Organization relationships use RESTRICT deletion rules
- Tenant access must be checked in authenticated services
- Runtime database DDL privileges remain prohibited
- No raw card credentials or unredacted gateway responses
- Currency code format does not guarantee currency support
- No public payment API or gateway access in this phase

Foreign keys enforce relationship integrity; they do not by
themselves provide row-level security for arbitrary SQL reads.

## Implementation stages

1. Phase 2B.1B: ORM definitions and offline tests
2. Phase 2B.1C: reviewed Alembic migration, local-only execution
3. Phase 2B.2: database integration and tenant-isolation tests
4. Phase 2B.3: transactional idempotency and state services
5. Phase 2C: provider webhooks and reconciliation

Migration execution must be reviewed separately and must use
the dedicated payflow_migrator role. Existing audit-event
privilege protections must remain intact.

Production launch approval: NOT GRANTED.
