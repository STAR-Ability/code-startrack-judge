# ADR 0002: Persist asynchronous tasks and callback outbox in PostgreSQL

- Status: Accepted
- Date: 2026-10-07
- Accountable roles: repository lead; database, judge/runtime and backend owners
- Evidence: [API contract](../contracts/v0.2/api.md) §§5/6/9; [database contract](../contracts/v0.2/database.md) §§8/10/11/13

## Context

Judgment, package validation and callback delivery outlive an HTTP connection. Crashes, POST response loss, lease expiry and callbacks arriving before task mapping must not duplicate submissions or lose terminal facts. The upstream demo's in-memory channels/MongoDB are examples rather than this service's durable truth.

## Decision

Use the judge PostgreSQL schema as the persistent queue/fact store. Accept a JudgeTask only after its required task/source registration/outbox facts are durable. Workers claim via short transactions and `SKIP LOCKED`, use expiring leases and fencing tokens, and execute outside transactions. Visible revisions advance monotonically; terminal task/result/case facts and their callback snapshot commit atomically. Persist callback retry state/dead letters with stable event identity, and support backend polling/by-request reconciliation.

## Reasons

One durable store preserves the atomic boundaries a small team can operate. It makes restart recovery, idempotency and event audit possible without a separate message broker as an initial prerequisite.

## Consequences

Claim/recovery logic must reject stale leases; terminal facts never regress. The contract's heartbeats, expiry, retry backoff and dead-letter policies need clock-aware tests. Event delivery is at least once: backend must acknowledge duplicates/old revisions and detect conflicting equal revisions. Canonical hash vectors and the exact recovery graph remain [open questions](../contracts/open-questions.md). Object writes use staged registration and orphan reconciliation because PostgreSQL cannot transact with the object store.

## Alternatives

In-memory channels and Redis pubsub cannot be the acceptance truth. A durable external broker could become useful at larger scale, but it would still need a transactional publication strategy and cannot replace database facts without a reviewed migration.

## Revisit / upgrade conditions

Measure queue contention, delivery latency and operational load before introducing a broker or splitting workers. Preserve task IDs, request identity, immutable results, revision semantics and recovery behavior in any upgrade.
