# Callback delivery and retained dead letters

Refs #19. The [published callback contract](../contracts/v0.2/api.md#6-judge--backend-结果事件), [Q-006](../contracts/v0.2/clarifications.md#q-006-duplicate-rejection-replay-and-recovery), and [ADR 0002](../adr/0002-persistent-asynchronous-judging.md) govern this implementation.

`internal/callbacks` sends only to `http://backend:8081/internal/v2/events/judge`, with the independent `JUDGE_BACKEND_TOKEN`. The client disables environment proxies and redirects. It sends the frozen canonical event body and its original `X-Request-Id`; it verifies the stored hash and contract identity before sending. Only HTTP 200 with the complete `ApiResponse<CallbackAck>`, matching request ID and `accepted:true` marks delivery. A duplicate ACK is a successful delivery. Other status codes, incomplete bodies, timeout and network failures retain the event. Receiver error bodies and raw transport errors never enter logs or persisted diagnostics.

The PostgreSQL dispatcher uses short `SKIP LOCKED` claims, a fresh UUID lease token and a 60-second lease. Network I/O runs outside the transaction with a 10-second timeout. Completion checks both matching token and an unexpired database-time lease. A crashed reservation consumes its delivery attempt and is reclaimed after lease expiry. PostgreSQL stores all authoritative queue state; restarting the process does not regenerate identities or extend deadlines. Acknowledgements only change outbox delivery state.

Failures wait 1, 2, 4, 8, 16, then 30 seconds, continuing every 30 seconds through the **original `created_at + 24h`** window. A due or expired reservation beyond that window becomes `DEAD_LETTER`; rows remain retained. An already reserved live attempt may finish after the deadline; a valid ACK still proves delivery. No fresh automatic attempt starts beyond the deadline. Logs contain only event/request IDs, attempt counts, fixed error codes and duplicate flags. Authentication, conflict and integrity failures emit error-level reconciliation diagnostics.

## Operator reconciliation

Provision a separate non-admin `judge_outbox_operator` after migrations using [grant-outbox-operator.sql](../../scripts/grant-outbox-operator.sql), from a direct PostgreSQL operator session with the same secret logging policy as [database provisioning](database-provisioning.md). Its password comes from `JUDGE_OUTBOX_OPERATOR_PASSWORD`, with at least 32 characters and independent of other credentials. Existing passwords remain unchanged. The script refuses unsafe role attributes, memberships, ownership and prior/PUBLIC privileges; it does not repair another role silently.

The operator role may read the outbox and replay audit, mutate only delivery-state columns, and insert replay request/outcome facts. It has no task/result/ledger writes or schema creation privileges. `judge_runtime` can finish/reap append-only replay outcomes, but cannot insert replay requests. Do not supply operator database credentials to the service or sandbox worker.

Build the trusted tool using the pinned native toolchain:

```sh
GOTOOLCHAIN=local .local/toolchains/go1.26.8/go/bin/go build -o .local/bin/judge-outbox ./cmd/judge-outbox
```

Set `JUDGE_OUTBOX_DATABASE_URL` through the approved secret environment mechanism. List up to 100 retained events without their payloads, private object references or logs:

```sh
.local/bin/judge-outbox list -limit 100
.local/bin/judge-outbox list -limit 100 -after-event 00000000-0000-4000-8000-000000000001
```

Use the reported original task/request ID to reconcile with Backend's authorized task reads and inbox/projection evidence. Resolve a missing mapping, restore the independent token/transport, or have the Backend owner resolve a conflicting inbox record. A conflict ACK does not authorize replacing Judge facts, hashes, event IDs or frozen payloads. Do not edit terminal tasks or original results to obtain an ACK.

After resolving the cause, supply the outbound token only to the trusted operator invocation and request **one** replay:

```sh
.local/bin/judge-outbox redeliver \
  -event 00000000-0000-4000-8000-000000000001 \
  -operator alice@example.org -reason MAPPING_RECONCILED
```

Allowed reasons are `MAPPING_RECONCILED`, `AUTH_RESTORED`, `TRANSPORT_RESTORED`, and `CONFLICT_RESOLVED`; operator references use 1..128 ASCII letters/digits or `_.@-`. The tool accepts no destination, body, hash, request ID or task mutation flags. The UUID above is an inert example, not an existing event.

The command records an append-only `callback_redelivery_requests` row with a replay ID and fresh lease token, then one append-only outcome (`DELIVERED`, `FAILED`, or `INTERRUPTED`). A failed or crashed replay returns to retained `DEAD_LETTER`. It preserves the original event identity, body, occurrence time, creation time and 24-hour deadline; it does not restart automatic retries. Concurrent replay and stale completions are fenced. Missing outcomes mean a reserved action is still in flight until lease expiry; the normal dispatcher records interrupted evidence on its next sweep. The CLI reports only event/replay IDs, accepted/duplicate flags and a fixed diagnostic code; a failed delivery exits nonzero after persisting the outcome.

## Verification boundary

Portable client/worker tests exercise strict ACKs, fixed routing, redirects, network failures, duplicate/stale/conflicting receiver behavior and the full retry clock. PostgreSQL integration tests create isolated databases and roles, apply the real migration chain and cover concurrent claims, restart, live/expired fencing, immutable snapshots, original deadline expiry, replay interruption and privilege denials. Run with an absolute private `JUDGE_TEST_ADMIN_DSN_FILE` path. These tests qualify transport and persistence, not the external Backend inbox or Linux sandbox; cross-service acceptance remains required.

On 2026-10-08, Go 1.26.8 client/worker race tests and five PostgreSQL integration suites passed against the pinned PostgreSQL 17.10 development container in the isolated `colima-startrack-v02` Linux environment, driven from macOS x86_64. The tests applied migrations 000001–000004 to newly named disposable databases and exercised an observed row-lock wait extending beyond lease expiry. The shipped operator SQL also passed repeat application and rejected unsafe role inheritance, membership, task reads, payload-column updates and migration-ledger insertion. Credential canaries were absent from captured client output. `go vet` and the operator CLI build passed; full repository validation still requires the integration owner to advance the repository migration pointer and refresh the measured command license closure before the final check. These are local qualification facts, not a deployment record.
