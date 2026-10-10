# Contract resolution register

The supplied V0.2 API/database/integration contracts remain unchanged. This register preserves Phase 0 questions and records owner-authorized engineering resolutions in the separate [V0.2 clarification/amendment](v0.2/clarifications.md). An unresolved gate blocks affected behavior, not unrelated implementation. Track implemented and verified evidence in GitHub Issues; a decision record alone does not prove acceptance.

GitHub resolution tracker: [#2](https://github.com/STAR-Ability/code-startrack-judge/issues/2).

Status updated 2026-10-08 after the owner authorized full V0.2 implementation and explicitly delegated engineering questions. Q-001 supplied-document recovery is resolved. Q-003's final human ADMIN approval policy is owner-approved. Q-002/Q-004/Q-005/Q-006/Q-007/Q-008 have explicit engineering decisions and owned implementations; independent acceptance, final Linux qualification and consumer compatibility remain separate gates. No Backend sign-off or real Linux qualification is asserted by this register. IDs remain stable.

## Q-001 — Missing whole-system architecture contract

**Phase 0 evidence:** both supplied documents' introductions defer cross-service boundaries/full integration to `V0.2-整体架构与联调说明.md`, which was absent then.

**Resolution:** the exact owner-supplied `0.2.0` document was recovered from the owner's local documentation repository and preserved at the root and [v0.2/integration.md](v0.2/integration.md). SHA-256 `f7ff9604edf08a4028766c3eba062bca1d2829c0ceab7a6e841bee65be61e503`; [source provenance](v0.2/provenance.md). The missing-document condition is resolved; integration test gates are not waived.

**Question:** where is the exact authoritative whole-system architecture/integration document, which revision applies, and who owns it? Supply or link the original evidence and reconcile any conflicts with the two current contracts.

**Gate:** does not block service-local scaffolding. Blocks asserting a verified four-service topology, real-backend compatibility, or final end-to-end acceptance until the referenced integration contract is available and reviewed. Owner: project/backend integration lead.

## Q-002 — Canonical hashing and operation identity

**Engineering decision:** RFC8785/JCS over strict valid UTF-8, exact field projections and path-bound operation wrappers; raw submitted-source bytes are separately hashed without normalization. [Q-002 specification](v0.2/clarifications.md#q-002-canonical-serialization-and-hash-boundaries). Shared golden fixtures and independent Backend consumption remain implementation/compatibility gates.

**Evidence:** API §§2/6 use normalized request hashes and fixed-field canonical event JSON; database §§3/10/11/13 persist metadata/request/result/payload hashes. The exact canonicalization profile and cross-service test vectors are not supplied.

**Question:** specify field ordering, Unicode/UTF-8 treatment, numeric representation, missing versus null fields, array-order semantics, and each hash's included fields. For management operations keyed by `(operation, requestId)`, confirm how path `problemId` participates in request identity so reuse against another problem cannot replay the wrong result. Do not normalize source bytes before `sourceSha256` calculation.

**Gate:** settle before hash/idempotency/event implementations diverge across owners. Produce shared golden vectors for backend and judge, including malformed and conflict cases. Owner: API/backend integration owners with database review.

## Q-003 — License evidence intake and review workflow

**Owner decision:** automatic evidence analysis plus final ADMIN human approval; approval and publication remain separate. Evidence rows are append-only, final approval inserts a new complete record, and rejected originals use problem-independent private evidence retention. [Q-003 workflow and additive retention model](v0.2/clarifications.md#q-003-final-human-approval-and-rejected-package-retention). Concrete trusted approval intake and tests remain implementation work.

**Evidence:** API §7 requires per-package license review; database §5 requires nonempty evidence/files plus `reviewed_by` and `reviewed_at` for VERIFIED. Imports become VALIDATED only when technical checks and license review both pass. The API lists no license-review mutation endpoint and its import request has no reviewer/evidence fields.

**Question:** what approved administrative workflow supplies reviewed evidence or the explicit import-policy identity, and how does an initially REJECTED package get reviewed and safely re-imported? Define authorization and append-only publication rules without assuming the repository's MIT license covers every problem. Also define where rejected/unsupported original packages, provenance and validation evidence are retained: unsupported packages must be preserved, but a failed import must not create a fictitious validated problem/version, and validation-run/artifact rows require a problem identity. DEFERRABLE foreign keys solve successful transaction insertion order; they do not define failed-package retention.

**Gate:** before imports can create publishable DRAFT versions or production packages can be published. Safe extraction and technical adapter work can proceed against fixtures. Owner: project/compliance lead and import owner; backend owner if a public administrative action is introduced.

## Q-004 — Recovery graph and retry budget

**Engineering decision:** initial execution reservation 0 plus three recovery reservations; direct atomic expired-lease reacquisition with a fresh UUID token, preserved first start timestamp, higher visible revision and current-attempt-only case facts. [Q-004 semantics](v0.2/clarifications.md#q-004-initial-execution-recovery-and-fencing). Fencing/crash/boundary tests remain required.

**Evidence:** API §5 draws the normal forward task path; database §10 explicitly permits visible nonterminal state rollback with a higher revision during recovery. API §9 and database §§8/10 describe up to three recovery executions and counters `0..3`. These requirements are compatible, but the exact recovery transitions and boundary fixtures still need a shared design.

**Question:** define the allowed nonterminal recovery transitions and associated lease/start timestamps/events. Make initial-versus-recovery counter semantics explicit in acceptance fixtures, including exhaustion, so owners implement the same bounded policy. Define the same semantics for import leases where applicable. Confirm fencing tests for every transition.

**Gate:** before persistent worker/scheduler recovery is implemented. Terminal states never revive, ordinary TLE is a completed user verdict, and expired lease owners cannot write under either interpretation. Owner: judge/runtime and database owners; backend owner reviews observed transitions.

## Q-005 — Immutable artifact versus validation pointer

**Explicit schema amendment:** immutable source/content identities preserve byte invariants; artifact uniqueness additionally binds an immutable license-evidence/validation-context hash. Evidence-only or qualification-context changes append new artifacts/versions sharing bytes; one-time successful selection never redirects. [Q-005 amendment](v0.2/clarifications.md#q-005-evidence-bound-immutable-artifact-identity). Independent review and PostgreSQL integrity/mutation tests gate shared migration delivery.

**Evidence:** database §4 calls package artifacts immutable but contains `validation_run_id`; §§4/7 permit new validation runs for tool upgrades and preserve old runs. The permitted lifecycle of that pointer, especially after publication, is not explicit. More concretely, database §5 requires post-publication license re-review to append new evidence and a new artifact/version, while §4 uniquely identifies artifacts by `(repository_url, source_revision, package_path, adapter_version)`. Evidence-only re-review at unchanged source/adapter cannot create that required new artifact.

**Question:** reconcile evidence-only re-review with the unique artifact identity; do not mutate published evidence or invent an adapter bump. Publish an allowed-mutability matrix for artifact registration/validation linking and published artifacts. Can a validation-only upgrade change an old artifact's pointer, or must a new artifact/selection record be introduced? Explain how historical publication validation evidence remains traceable and how this interacts with the artifact uniqueness key and license evidence.

**Gate:** before artifact persistence and validation-upgrade workflows. Package bytes, source checksums, and published historical content remain immutable. Owner: problem/import and database owners.

## Q-006 — Mutation rejection and replay edge cases

**Engineering decision:** accepted request replay returns current task/job before current-state admission checks; a new requestId for the same submission is IDEMPOTENCY_CONFLICT; initial DRAFT withdrawal is PROBLEM_NOT_SUBMITTABLE; deterministic admission rejection reserves no remote task key; accepted asynchronous failures are persisted task/item facts. Management responses/errors are frozen and path-bound. [Q-006 semantics](v0.2/clarifications.md#q-006-duplicate-rejection-replay-and-recovery). Concurrent/malformed/replay/callback consumer fixtures remain required.

**Evidence:** API §5 forbids a second attempt for the same business Submission; database §10 enforces unique `submission_id`, but the API does not name the error for a different requestId targeting it. Database §2 requires WITHDRAWN problems to have a current version; API §7 does not state the response when withdrawing an initial DRAFT. Database §13 freezes successful management-operation responses but task replay semantics are not equally explicit.

**Question:** agree exact codes/statuses for a second requestId on one submission and initial-DRAFT withdrawal, including concurrent races. Confirm whether JudgeTask/import replay returns current task state while management replay returns the frozen operation result, and how replay headers/body request IDs are preserved. Define the boundary between POST import `422 PACKAGE_INVALID` (API §7) and validation/license failures on an already accepted asynchronous ImportJob; accepted jobs report their failures through item/task state rather than retroactive HTTP rejection.

**Gate:** before mutation/API contract fixtures. Never create a second task, fabricate a current version, or silently return a successful operation on another resource. Owner: API/backend and database owners.

## Q-007 — Shared manifest and conversion profile

**Engineering specification:** exact typed manifest and validation-results schemas, deterministic JCS/ustar archives, sorted file/program/adaptation/test arrays, source unit/default evidence, exact Kattis checker/input-validator protocol, and strict reference acceptance under frozen source limits are recorded in [package-protocol.md](v0.2/package-protocol.md). Synthetic schema/byte vectors are verified separately from real pinned checker/package/Linux qualification, which remains required.

**Evidence:** API §8 pins `ojlab-kattis-v0.2.1`; database §4 pins manifest `0.2.0` and describes its contents without a complete typed schema. Units must be converted explicitly, and checker semantics must match the source package, but missing wall/output defaults and conversion decisions are not enumerated.

**Question:** freeze the typed manifest and its checksum scope, file/test ordering, source-to-normalized paths, checker/validator protocol and allowed adaptations. Define reviewed bounded defaults when upstream wall/memory/output configuration is absent or ambiguous, and record each conversion/default in provenance.

**Gate:** before importer and runtime owners independently consume manifests. This is implementation design constrained by the contracts, not permission to alter limits silently or hide technical failures. Owner: package adapter and judge/runtime owners with security review.

## Q-008 — Bottom-level transport and binding reconciliation

**Engineering decision and implementation:** the owned finite role adapter preserves the pinned demo's compile/test/checker flow through the runtime's private REST interface at `127.0.0.1:5050`. The API uses a separate authenticated private scheduler socket; only the judger holds the low-level runtime credential. The concrete adapter and supervisor are implemented. See the [owner evidence gates](v0.2/clarifications.md#q-007-and-q-008-implementation-owner-evidence-gates), [REST mapping](../upstream/rest-transport.md), [runtime adapter](../development/runtime-adapter.md), [patch provenance](../upstream/patches.md), and Issues [#15](https://github.com/STAR-Ability/code-startrack-judge/issues/15), [#20](https://github.com/STAR-Ability/code-startrack-judge/issues/20), [#21](https://github.com/STAR-Ability/code-startrack-judge/issues/21). Portable tests do not establish final-image Linux qualification.

**Evidence:** API §8 requires supervised reuse of the demo's gRPC judge flow and states the bottom-level runtime listens only on `127.0.0.1:5050`. At the exact pins, [demo judger/main.go](https://github.com/criyle/go-judge-demo/blob/ed6cc756082ee9f7d792238185dc3e6a47c84b52/judger/main.go) creates a gRPC ExecutorClient with default `localhost:5051`; [runtime config](https://github.com/criyle/go-judge/blob/e9d70a0d9a3df0c62182a6e7090d7af650a1d5f8/cmd/go-judge/config/config.go) defines separate HTTP `5050` and optional gRPC `5051`; [runtime main.go](https://github.com/criyle/go-judge/blob/e9d70a0d9a3df0c62182a6e7090d7af650a1d5f8/cmd/go-judge/main.go) initializes HTTP plus optional gRPC listeners. These source facts were read during Phase 0; an unchanged demo cannot simply use its gRPC client against the default HTTP `5050` listener.

**Question:** agree a contract-conforming transport/binding configuration or an explicit reviewed transport adapter/clarification. Evaluate the pinned runtime's actual supported listener configuration. Do not add an extra listener, expose a raw submit API, or claim the unchanged upstream processes are already interoperable by assumption. Any required upstream patch needs provenance and review.

**Gate:** before enabling qualified execution or claiming the final single-container profile satisfies its isolation, listener, credential, cancellation and verdict requirements. Owner: judge/runtime, deployment and security owners; project contract owner approves any change to the binding constraint.

## Q-009 — Complete problem detail servability

**Owner-authorized engineering decision (2026-10-08):** under the owner's explicit delegation of engineering resolutions, the Judge implementation profile admits only versions whose complete `ApiResponse<PlatformProblemDetail>` fits the existing owned HTTP encoder's 32 MiB ceiling. This is an implementation eligibility policy, not a claim that the published API imposed a global problem-detail cap. [Policy, guard points and regression evidence](../development/problem-detail-servability.md). Recorded under [#2](https://github.com/STAR-Ability/code-startrack-judge/issues/2); actual Backend acceptance remains [#23](https://github.com/STAR-Ability/code-startrack-judge/issues/23).

**Evidence and distinction:** API §5's explicit 32 MiB wording concerns task results/callbacks; §3 requires complete Markdown and samples. The package protocol's 64 MiB per-file and 512 MiB aggregate safety limits permit a valid archive whose complete public detail exceeds the current HTTP encoder. The observed defect created a validated DRAFT with 32 MiB sample input plus 32 MiB answer, then its ordinary detail response failed with HTTP 500. Supplied historical/current contract copies and immutable package/version facts remain unchanged.

**Implementation boundary:** after retaining original/normalized archives and resolving the exact human license approval, import preparation retains an oversized approved candidate as `REJECTED` / `UNSUPPORTED` / `PACKAGE_UNSUPPORTED` before execution or registration. A shared complete escaped-JSON counter protects `CreateVersion` before writes and publication before catalog/current/first-publication changes, including no-op publication. Metadata overflow maps to the endpoint's existing 400 `INVALID_ARGUMENT`; publication uses its existing 422 `PACKAGE_UNSUPPORTED`. Complete content is never truncated. Failed operations retain structured request history without partial business writes.

**Gate and historical limitation:** encoder differential tests, actual PostgreSQL/HTTP regressions, independent review, final repository checks, and full-size capacity qualification are separate evidence. Existing immutable oversized details remain subject to the current encoder ceiling; no historical rows are rewritten. A larger transport/profile requires reviewed evolution and consumer evidence before release. This decision does not supply Backend sign-off or Linux execution qualification. Owner: Judge implementation lead under delegated project-owner authority; Backend integration owner retains consumer acceptance.

## Q-010 — Callback ACK envelope request correlation

**Status:** unresolved joint-owner acceptance. No contract amendment or consumer change is selected by this entry.

**Baseline and distinction:** [API §2](v0.2/api.md#2-http-与认证) defines `ApiResponse.requestId` as a UUID; [§6](v0.2/api.md#6-judge--backend-结果事件) fixes the callback event/header request identity and the HTTP 200 `ApiResponse<CallbackAck>` shape. Neither explicitly says that the ACK envelope's `requestId` must echo the callback `requestId` (the original `JudgeTaskRequest.requestId`); `eventId` is the distinct delivery-deduplication identity. Q-002's request header/body equality rule does not independently specify this response-envelope meaning. The current [Judge callback profile](../development/callbacks.md) requires a matching ACK request ID, enforced by [Client.Send](../../internal/callbacks/client.go#L88); that is an implemented engineering profile, not evidence of an explicit baseline echo requirement.

**Current consumer evidence:** at unchanged Backend commit `318b84170860b6e4ca6931712554474a531acfcb`, [RequestIdFilter](https://github.com/STAR-Ability/code-startrack-backend/blob/318b84170860b6e4ca6931712554474a531acfcb/src/main/java/com/startrack/backend/common/web/RequestIdFilter.java#L61) generates its own request trace UUID. [InternalEventController.judge](https://github.com/STAR-Ability/code-startrack-backend/blob/318b84170860b6e4ca6931712554474a531acfcb/src/main/java/com/startrack/backend/controller/InternalEventController.java#L76) returns [ApiResponse.of](https://github.com/STAR-Ability/code-startrack-backend/blob/318b84170860b6e4ca6931712554474a531acfcb/src/main/java/com/startrack/backend/common/web/ApiResponse.java#L29) using that trace. This does not establish the equality required by the current Judge client, even if the receiver applies the event. Static review is now supplemented by the finite R6 diagnostic: an independently seeded contract-valid mock task, using an explicitly recorded synthetic copy whose platform changed from `STARTRACK` to `startrack`, supplied a benign AC event to the real authenticated Backend callback handler. The first delivery returned HTTP 200 with `accepted:true, duplicate:false`; the identical duplicate returned HTTP 200 with `accepted:true, duplicate:true`. Backend recorded one APPLIED inbox event and one result projection, and the Submission became COMPLETED at revision 2. Both ACK response headers and envelopes contained receiver trace UUIDs different from the original event/header request ID. The genuine scheduled dispatch still returned 400 for header `-`; its captured body separately retained the uppercase platform `STARTRACK`. This separate synthetic fixture does not establish normal dispatch success, ACK acceptance by the current Judge client, real Judge execution or Backend-owner acceptance. See [qualification progress](../releases/v0.2-qualification-progress-2026-10-08.md) and the handoffs in [Backend #1](https://github.com/STAR-Ability/code-startrack-backend/issues/1) and [Judge #23](https://github.com/STAR-Ability/code-startrack-judge/issues/23).

**Question:** agree what the ACK envelope's `requestId` represents and which correlation rule both services accept: the original callback request ID, or a receiver trace with another agreed means of correlation. Record the authoritative clarification and shared consumer fixture before choosing a change to either implementation; this register does not choose that change.

**Gate:** joint Judge/Backend owner acceptance and real-service ACK evidence remain integrated release gates under [#23](https://github.com/STAR-Ability/code-startrack-judge/issues/23) and [#19](https://github.com/STAR-Ability/code-startrack-judge/issues/19). A successful projection alone does not prove delivery acknowledgement under the current Judge profile. Owner: Judge callback owner and Backend integration/contract owners. Preserve published contracts and existing immutable event facts while resolving the ambiguity.

## Separate owner/platform decisions

These do not reinterpret the V0.2 contract but must be recorded before the corresponding release gate:

- Project license: owner selected Apache-2.0 for project-owned source in the complete-implementation instruction. Third-party and problem-package license obligations remain independent; see the licensing documents.
- Actual Linux target, host/kernel/cgroup delegation, restricted capability/mount profile, resource budgets, and retained toolchain-image policy: deployment/security owners; require measured isolation evidence before production execution.
- Business-service language and exact toolchain version after upstream build review: bootstrap owner; record the decision and lock versions before mass implementation.

Issue resolutions must identify the decision owner, evidence, affected contract sections, tests, and any publication/version impact. A closed Issue without an agreed answer and evidence does not resolve a gate.
