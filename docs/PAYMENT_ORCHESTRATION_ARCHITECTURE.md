# PayFlow OS ? Payment Orchestration Architecture

## Status

Phase 2A.2: provider-independent contract foundation.

No live gateway integration, provider credentials, payment API
route, durable payment record or transaction execution exists.

Production launch approval: NOT GRANTED.

## Payment boundary

PayFlow orchestrates supported payment providers on behalf
of merchants. It is not designed to hold customer funds or
store raw card credentials.

Payment providers are accessed only through reviewed adapters.

## Domain contracts

- `Money`: positive integer minor units plus currency code
- `CreatePaymentCommand`: organization, reference, amount, key
- `FetchPaymentCommand`: organization and provider payment ID
- `CreateRefundCommand`: organization, payment, amount, key
- `PaymentResult`: normalized payment state and provider ID
- `RefundResult`: normalized refund state and provider ID
- `ProviderError`: sanitized error category with retry policy
- `PaymentProvider`: provider adapter interface

The currency format check is syntactic only. A later service
must enforce allowed currencies and provider-specific limits.

## Trust boundaries

Organization identity must be derived from authenticated
tenant access, never trusted from an unverified client field.

Adapters must be selected using server-controlled merchant
configuration and scoped provider credentials.

A provider payment identifier must never be used alone to
authorize access to another organization's payment.

Provider credentials, raw card details and unredacted provider
error responses must not be persisted in application records.

## Internal idempotency

Later orchestration services must atomically persist a key
scoped by organization and operation, plus a canonical request
fingerprint.

- Same key and same request: return the original result
- Same key and different request: reject as a conflict
- Concurrent requests: guarantee only one creation attempt
- Uncertain provider outcome: reconcile before retrying

Provider-specific idempotency headers and their constraints
must be implemented in each adapter. A PayFlow key by itself
does not make an external operation idempotent.

## Payment state model

Provider statuses will be normalized to:

- created
- requires_action
- processing
- authorized
- succeeded
- failed
- cancelled

Refunds have separate pending, succeeded and failed states.

These are contract states only. Allowed transitions, capture,
partial refunds, refund totals and concurrency rules will be
implemented and tested in Phase 2B.

## Webhooks and reconciliation

Phase 2C will add raw-body signature verification, event
deduplication, timestamp/replay policy where supported,
out-of-order event handling and provider reconciliation.

An authenticated webhook alone is not proof that a repeated
event is a new transaction.

## Explicit exclusions for Phase 2A.2

- No HTTP API endpoints
- No database migrations
- No gateway SDK or network calls
- No gateway keys
- No real transactions
- No webhook activation
- No live payment state changes

The production prelaunch release gate remains unchanged.
