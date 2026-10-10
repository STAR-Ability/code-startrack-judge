# V0.2 engineering clarifications and amendments

Decision date: 2026-10-08. Scope: service release `0.2.0`, contract baseline `0.2.0`, `/internal/v2`, initial schema before shared migration history.

Authority is the owner's supplied complete-implementation instruction, which explicitly assigns Q-002 and Q-004 through Q-008 to engineering, approves final ADMIN human license review, and limits the release to `cpp17`. This record preserves the [API baseline](api.md), [database baseline](database.md), and [integration baseline](integration.md). It identifies amendments instead of silently modifying them. Q-002 through Q-006 design received independent engineering review and main implementation-owner acceptance on 2026-10-08; this records engineering-role review under the owner's mandate, not external service-owner sign-off. Independent implementation review, consumer fixtures, Linux qualification, and release acceptance remain separate gates. No Backend owner sign-off or deployed compatibility is asserted.

## Q-001: recovered integration evidence

Resolved missing-document condition. The exact supplied integration contract and supporting reference documents are preserved with [provenance](provenance.md). Its bottom-level interface is private REST at `127.0.0.1:5050`, with an independent token. Judge does not call Algorithm or access Backend business tables.

## Q-002: canonical serialization and hash boundaries

All structured hashes are lowercase hexadecimal SHA-256 over the exact UTF-8 output of RFC 8785 JSON Canonicalization Scheme (JCS), without BOM or trailing newline. Object members use JCS's UTF-16 code-unit ordering, not locale, UTF-8 byte order, or an ad hoc alphabetical serializer. Arrays retain their defined order. Strings retain Unicode scalar values without NFC/NFD normalization; JSON escapes are canonicalized. `null` remains `null`, and an absent member is different from a member containing `null`. Required nullable DTO members are always present.

Reject malformed UTF-8, unpaired surrogate escapes, duplicate object members, nonfinite numbers, and values outside the DTO's numeric domain before hashing. IDs remain strings. Counters and resource integers must be nonnegative safe integers, with the baseline's stricter positive checks where applicable. Numeric serialization follows RFC 8785/ECMAScript; lexical variants such as `1.0` and `1e0` represent the same number. Do not use decimal pretty-printing as a substitute for JCS. Pass/fail scores are explicitly `null`.

Validation precedes normalization. Header/body `requestId` equality is checked before any canonical UUID rendering. UUID values render as lowercase standard hyphenated strings; bigint IDs render as canonical positive decimal strings in `1..9223372036854775807` without leading zeros. Checksums render lowercase. Only baseline-defined normalization is permitted: metadata tags are trimmed and deduplicated while retaining first occurrence order. There is no source-code trimming, newline conversion, case conversion, or Unicode normalization. Input tag-count limits apply before deduplication.

`packagePaths` must already be canonical POSIX relative directory paths under `problems/`: reject absolute paths, backslashes, control characters, empty segments, `.` and `..` segments, trailing slash, URLs, or encoded separator/traversal interpretations. No filesystem resolution or silent path repair is performed. Request package-path order is retained because it defines ImportItem order. The immutable manifest separately freezes its own test/file ordering.

| Stored hash | Exact input projection |
|---|---|
| Judge/import/management `request_hash` | JCS of `{operation,problemId,body}`. `operation` is `JUDGE`, `IMPORT`, `PUBLISH`, `WITHDRAW`, or `METADATA_VERSION`; `problemId` is the canonical path ID for management and `null` otherwise. `body` contains every normalized request member except `requestId`, including explicit nullable members. The key already includes `requestId`; sourceCode and sourceSha256 both remain in Judge's body. |
| `source_sha256` for submitted code | SHA-256 of the decoded `sourceCode` string's exact valid UTF-8 bytes, including original newlines. This is not a JSON hash. |
| Version `metadata_hash` | JCS of `packageArtifactId,title,statementFormat,statementContent,statementInput,statementOutput,samples,tags,difficulty,difficultyScale,ratingBasis,timeLimitMs,wallLimitMs,memoryLimitBytes,outputLimitBytes,languageIds,judgeMode,checkerConfig`, as one object with those camelCase names. Excludes version/problem IDs, display version number, base-version lineage, timestamps, and publication markers. |
| Result `result_hash` | JCS of the complete public `JudgeResult`: verdict, timeMs, memoryBytes, passedTestCount, totalTestCount, score, compileLog, diagnosticCode, judgedAt. All nullable members are present. |
| Outbox `payload_hash` / event-body integrity | JCS of the complete `CallbackEvent<JudgeTask>`, including eventId, eventType, occurredAt, requestId, aggregateId, revision, and the complete task snapshot. Stored bytes and event identity never change on retry. |
| Backend same-revision conflict comparison | JCS of the complete `JudgeTask` payload only. The event-body hash separately guards reuse of eventId with conflicting envelope content. A stale revision is acknowledged after envelope/mapping validation; equal revision with a different task hash is `EVENT_CONFLICT`. |
| Package source/normalized checksums | SHA-256 of the exact archived bytes stored under immutable private keys. A separately recorded manifest hash covers JCS of the typed manifest; neither checksum is a filesystem-directory listing hash. Archive construction, file order, modes, timestamps and normalization are frozen by the compatibility profile. |
| Artifact `evidence_set_hash` | JCS of the exact evidence binding described in Q-005. |

The shared [golden fixture](../../../testdata/canonical-golden.json) covers empty objects, absent/null, key ordering including non-BMP keys, Unicode preservation, escapes/newlines, array order, JCS numeric exponent boundaries, and complete management/Judge/import/event examples. Separate DTO/admission tests enforce safe counters and traversal. Invalid canonical vectors include duplicate keys, surrogate errors, malformed UTF-8 and nonfinite overflow. Backend and Judge must independently reproduce the fixture bytes and hashes; existence of a fixture alone does not prove interoperability.

## Q-003: final human approval and rejected-package retention

Owner-authorized policy: automatic evidence collection and suggestions cannot set `VERIFIED`. A final ADMIN human approval must record reviewer identity, reviewedAt, scope, license-file checksums, complete source/notice, and the approval evidence. License approval and problem publication are separate operations. No import request's caller-controlled string may masquerade as an ADMIN approval.

Before human approval, an accepted asynchronous import may finish its item as `REJECTED` with `MISSING` or `REVIEW_REQUIRED`; it does not invent a valid problem/version. Original package bytes, provenance, adaptations, license evidence and validation diagnostics are retained in a private ingestion evidence record independent of the eventual problem identity. Following human approval, re-import uses a new operation requestId and can create the immutable validated DRAFT. The original rejected ImportJob and its evidence remain unchanged. This resolves retention without nullifying the baseline's nonnullable artifact/version ownership.

Add append-only `rejected_package_evidence`: UUID primary key; `import_item_id uuid` local FK; fixed `repository_url`, 40-hex `source_revision`, canonical `package_path`; `failure_stage text` (`SOURCE_UNAVAILABLE`, `INVALID_STRUCTURE`, `UNSUPPORTED`, `LICENSE_REVIEW`, `VALIDATION_FAILED`); nullable `source_archive_key/source_sha256` pair; nullable `normalized_archive_key/normalized_sha256` pair; nullable local `license_evidence_id`; required JSON objects `provenance` and `source_metadata`; required JSON arrays `adaptations` and bounded redacted `errors`; nullable private `validation_log_key`; `evidence_sha256 char(64)`; `created_at`. There is no problem/version FK. `evidence_sha256` hashes the JCS object containing all listed evidence fields in camelCase except id, importItemId, evidenceSha256 and createdAt; nullable fields are explicit. UNIQUE(import_item_id,evidence_sha256) prevents accidental duplicate observations on recovery. A row is inserted once with a rejected item's committed terminal evidence and cannot be updated/deleted as ordinary workflow. Multiple independently retained evidence observations may reference the same item, each with a distinct ID. Pair-nullability preserves truthful source-fetch failure without inventing bytes. Hashes and keys refer only to safely stored content-addressed objects; an unsafe archive may be retained inert but is never extracted outside the controlled validation boundary. Raw logs and source metadata stay private and do not enter ImportItem DTOs.

The concrete approval intake must be a service-controlled ADMIN workflow with auditable trusted actor evidence. The original API has no approval endpoint; any added HTTP administrative workflow requires an explicitly documented DTO and Backend proxy/authorization fixture. An offline administrative command is acceptable only if its operator authorization and evidence source are documented and enforced. Neither approach permits automatic final verification.

## Q-004: initial execution, recovery and fencing

`attempt_count` in JudgeTask and ImportJob counts reserved recovery attempts, not the initial execution: initial `0`, first recovery `1`, second `2`, third `3`. There are at most four isolated execution reservations including the initial one. This explicitly resolves the baseline's ambiguous “actual recovery execution” wording conservatively: a crash after reserving a recovery but before the bottom runtime acknowledges it still consumes that reservation. Delivery attempts in callback outbox are a separate counter. Deterministic user verdicts and deterministic package rejection never consume recovery budget.

Admission creates QUEUED/revision 1, error/result/finishedAt null, with no lease or startedAt. Judge acquisition in a short `FOR UPDATE SKIP LOCKED` transaction assigns a fresh UUID fencing token, lease deadline = database time + 180 seconds, status DISPATCHING, startedAt = database time, and increments visible revision with a same-transaction outbox snapshot. RUNNING means the controlled runtime has acknowledged dispatch and similarly increments revision. Worker heartbeat every 30 seconds renews only a still-live matching token; it changes neither visible revision nor visible task timestamps.

For expired DISPATCHING or RUNNING leases, recovery atomically replaces the old lease with a fresh UUID token and deadline, enters DISPATCHING, increments `attempt_count` and revision, and creates an outbox snapshot. It starts a fresh isolated work directory and runtime execution. `started_at` retains the first execution start timestamp; recovery does not overwrite historical start. The same task ID, requestId, submissionId and frozen inputs remain. Expired owners cannot write, heartbeat, append a case, or finalize a result even before another worker claims the task: every write checks token equality and a lease deadline strictly later than database time. The new token also fences a delayed successful response from an old runtime execution. A recovery creates a new visible revision/event even if the previous status was also DISPATCHING.

Each fencing-token reservation starts one logical execution attempt, dispatched to the controlled judger at most once. Within it, the compiler and each named case/checker/validator step necessarily use separate sandbox operations; each `(fencingToken,step identity)` dispatches at most once. An ambiguous upstream transport failure cannot silently rerun that step or whole attempt under the same token; stop its heartbeats and preserve the uncertain attempt until lease recovery reserves a fresh counted attempt. This prevents transport retries from bypassing the execution budget while allowing the frozen test sequence to execute.

When the expired execution already has `attempt_count=3`, recovery creates immutable FAILED/IE with `JUDGE_INTERRUPTED`, finishedAt, cleared lease, a result and final outbox snapshot in one transaction. A terminal exhausted error is not retryable. A worker crash after its final transaction cannot revive the task; a crash before commit can only recover the same task. User TLE completes normally and never triggers lease recovery.

Import uses the same initial-plus-three recovery budget and fencing checks with QUEUED/RUNNING states. Committed VALIDATED/REJECTED items remain terminal; recovery retries pending work and does not duplicate validated versions. Expired RUNNING recovery atomically reacquires RUNNING with a fresh token, retained first startedAt, reserved recovery count increment and higher revision. Exhaustion rejects still-pending items, computes SUCCEEDED/PARTIAL/FAILED from all terminal items, and preserves every earlier successful DRAFT and failure record.

Final Judge states COMPLETED, FAILED and CANCELLED never change; final result/cases are immutable. COMPLETED has a non-IE user verdict and null error; FAILED has IE and nonnull error; CANCELLED has no result and nonnull error. Maintenance cancellation needs the same fencing/atomic-event guarantees and is not a public v0.2 API.

Per-case work is staged by `(judgeTaskId,fencingToken)` or held in the current isolated attempt. Immutable `judge_case_results` are inserted only in the final live-token transaction with task/result/outbox, using the current attempt's cases. Partially completed or stale-attempt cases cannot contribute AC counts or resource aggregates to a recovered result. No unfenced insert may survive as an authoritative case fact.

## Q-005: evidence-bound immutable artifact identity

This is an explicit additive schema amendment to database §§4/5/7. The baseline's four-field unique artifact key cannot accommodate its required new artifact when license evidence alone changes. Do not fabricate an adapter-version change or update historical evidence to avoid that contradiction.

Add immutable `evidence_set_hash char(64)`, immutable `validation_context jsonb`, and `content_identity_id uuid` to `package_artifacts`. Replace uniqueness on `(repository_url,source_revision,package_path,adapter_version)` with uniqueness on `(repository_url,source_revision,package_path,adapter_version,evidence_set_hash)`.

The expanded artifact key must not permit differing byte content to masquerade as an evidence-only revision. Two additive immutable identity tables preserve the original byte invariants:

- `package_source_identities`: UUID primary key, repository_url, source_revision, package_path, source_sha256, created_at; UNIQUE(repository_url,source_revision,package_path). The source checksum cannot change across adapter versions.
- `package_content_identities`: UUID primary key, source_identity_id local FK, adapter_version, source_format, manifest_version, normalized_sha256, manifest_sha256, manifest JSON object, created_at; UNIQUE(source_identity_id,adapter_version). The manifest hash covers Q-002 JCS of the complete typed byte-derived manifest, excluding license/validation bindings. Normalized bytes and manifest cannot change under one fixed adapter version.

Artifacts reference the content row. Their legacy source/adapter/checksum/manifest columns must agree with the frozen source/content records using constraints and owner validation; conflicts fail registration. Concurrent insertion is serialized by unique identities and locks, with exact byte/hash equality checked after a conflict. Evidence-only changes share the immutable content row. A normalization or execution-semantic change requires a real adapter-version change.

The exact evidence-set object is:

```json
{
  "licenseEvidenceId": "<UUID>",
  "validationContext": {
    "problemtoolsVersion": "<exact release and commit>",
    "adapterVersion": "ojlab-kattis-v0.2.1",
    "toolchainVersion": "<complete controlled compiler/tool combination>",
    "imageDigest": "sha256:<actual image digest>",
    "configSha256": "<64 lowercase hex>",
    "sourceSha256": "<64 lowercase hex>",
    "normalizedSha256": "<64 lowercase hex>"
  }
}
```

Hash this object using Q-002. `validationRunId` is deliberately excluded: repeated auditing of the same qualification context does not alter artifact identity. The selected PASSED run must match every context member and source/normalized checksum. Same base identity plus same evidence-set hash and checksums reuses the existing artifact; differing checksums under that identity are an integrity conflict, never an overwrite.

Original and normalized byte objects remain content addressed and immutable. License-evidence rows are append-only from insertion. Human review inserts a new complete VERIFIED record; the earlier automatic-analysis record remains intact. An optional same-source `previous_evidence_id` local FK records review lineage. No pending/rejected evidence record may be made publishable by in-place mutation. Artifacts for validated versions bind only approved VERIFIED evidence. An evidence-only re-review appends a new license-evidence record and produces a new artifact/version sharing the original byte objects. Adoption of a new validation context likewise produces a new artifact/version even when package bytes and license evidence remain the same. A pure audit appends a validation run without changing the selected historical evidence. An execution/format change requires the actual adapter-version change and new normalized bytes as applicable.

| Record/field | Allowed mutation |
|---|---|
| Original/normalized objects, manifest, checksums, artifact provenance, evidence_set_hash, validation_context, license binding | Never after registration. |
| Artifact validation_run_id | At most one `null` → matching terminal PASSED selection before any referencing version is published; never redirected or cleared. Registration may insert the selected run/artifact together using deferred local constraints. |
| Source/content identity records | Never after insertion; original source bytes also agree across adapters. |
| License evidence | Never after insertion; collection and human approval each append a new complete record with source-scoped lineage. |
| Validation run | PENDING → RUNNING → PASSED/FAILED for that run; terminal fields/logs are immutable. A new audit creates a new run. |
| Problem version | Immutable metadata/package binding; first_published_at only null → first timestamp. |

The selected qualification pointer is therefore stable even before publication once chosen. No update may silently change the history used by a published version/task. Private rejected-package ingestion evidence has separate identity and does not need a fictitious problem row.

Pointer initialization uses a compare-and-set `validation_run_id IS NULL` while locking artifact, approved evidence, content identity and selected terminal run in the publication/selection transaction. All context members must match, not merely the source checksums. A conflicting second selection fails rather than silently replacing the first; publication validates the same locked immutable binding to avoid write skew.

Each new artifact obtains its own actual qualifying validation run, including evidence-only artifact variants. An old run is never reparented or represented as a new execution. Every appended run must match its artifact's source/normalized checksums and adapter; an audit under another toolchain/profile may be retained but cannot be selected for an artifact whose frozen context differs. Shared byte objects remain retained while any immutable artifact or ingestion-evidence record references them; cleanup cannot delete content solely because one artifact/work directory is no longer active.

## Q-006: duplicate, rejection, replay and recovery

After authentication and strict syntactic/DTO/hash validation, look up accepted request identity before testing current readiness, current publication, or current language activation. An accepted Judge/import replay with matching normalized hash returns HTTP 200 and the current persisted task/job, even after withdrawal, a new problem version, or readiness loss. Same requestId with a different normalized body is `409 IDEMPOTENCY_CONFLICT`. A fresh requestId targeting an already accepted submissionId is also `409 IDEMPOTENCY_CONFLICT`, even when its other inputs match. Concurrent unique constraints and transaction handling must produce one task, never an extra attempt.

Management replay returns its stored complete response DTO and original catalog version with the current HTTP envelope requestId. Metadata creation is 201 on first success and 200 on replay; publish/withdraw are 200. Same operation/requestId with a different problem path or hash is conflict. An already PROCESSING operation returns `409 REQUEST_IN_PROGRESS` with `Retry-After: 2`; failed deterministic management operations retain their frozen error. Different requestIds cannot reinterpret a no-op publication as a new public catalog change.

No accepted task exists after deterministic admission rejection. A Judge/import admission 4xx does not reserve a requestId or submissionId key; frozen management-operation failures are the separate exception. New DRAFT and WITHDRAWN submission attempts return `409 PROBLEM_NOT_SUBMITTABLE`; a published problem with a wrong or cross-problem version returns `409 PROBLEM_VERSION_CONFLICT`; nonexistent problem returns `404 PROBLEM_NOT_FOUND`. A successful replay bypasses these changed-current-state admission checks. Backend deterministically rejected Submissions become its local FAILED/no remote task/no judgeResult; they are not fabricated remote IE tasks and are not automatically resurrected. Network timeouts are not deterministic rejection: recover by original requestId, then repeat the original request only if absent.

Withdrawing an initial DRAFT that has never had a published current version returns `409 PROBLEM_NOT_SUBMITTABLE`; this explicitly adds the already-defined global error to the withdraw row's edge case. It does not invent a current version. Repeated withdrawal of the same already-WITHDRAWN problem is a no-op for catalog/public timestamps; the stored operation result remains replayable. Existing frozen tasks continue after withdrawal.

Before import acceptance, malformed fixed-source/commit/path DTOs are 400; known statically invalid package selection may be `422 PACKAGE_INVALID` only when the rejection is established before durable job admission. Once accepted with 202, fetching/structure/license/validation failures are committed item/job errors returned by GET 200. A later worker failure cannot retroactively change the POST HTTP response. Unsupported packages and original evidence are preserved, publication remains blocked, and no validated problem/version is fabricated.

Callback retries preserve eventId and exact event-body hash. A validated duplicate eventId or stale revision is acknowledged 200 without overwriting a newer projection. Reusing eventId with conflicting content or presenting the same aggregate/revision with a different task payload is `409 EVENT_CONFLICT`. Unknown mapping is 404 and remains retryable in Judge outbox; authentication/conflict errors are retained and alerted, never marked delivered. Outbox backoff is 1,2,4,8,16,30 seconds then 30 seconds through its original 24-hour delivery window; expiry creates retained dead letter. Delivery acknowledgement does not mutate Judge facts.

## Q-007 and Q-008: implementation-owner evidence gates

Q-007's typed immutable manifest, deterministic archive/conversion profile, original-to-normalized file mapping, test order, resource conversions/defaults, checker/input-validator protocol and exact validation checkpoint schema are frozen in [package-protocol.md](package-protocol.md), [manifest-schema.json](manifest-schema.json), and [validation-results-schema.json](validation-results-schema.json). The specification/schema received independent package-protocol engineering review on 2026-10-08; implementation and qualification are separate gates. Synthetic schema and byte fixtures are separate from real package/checker/sandbox regression qualification. The mature pinned checker remains authoritative; no TrimSpace comparison is substituted.

Q-008's authoritative integration interface is private REST `127.0.0.1:5050` only. Pinned demo's gRPC execution client cannot be pointed at that HTTP listener unchanged. An owned transport adapter must preserve reviewed execution/test semantics while using the pinned runtime's REST interface; it must not enable an extra raw listener, expose caller-selected commands, or weaken isolation. Exact pins, request mappings, token/bind behavior, source provenance and Linux runtime tests must be recorded by the runtime owner before the question is marked implemented/qualified.

## Verification and compatibility status

This record defines engineering decisions; implementation and acceptance are not proven by its publication. Independent review must exercise conflicting requests, lease expiry and delayed old-token responses, four-execution boundaries, same-source new evidence, repeated audit identity, immutable selection, DRAFT withdrawal, asynchronous failures and callback conflicts. Golden JCS fixtures must be consumed by a Backend implementation or explicitly retained as an outstanding consumer gate. Linux isolation and actual image qualification remain mandatory for public-production claims.
