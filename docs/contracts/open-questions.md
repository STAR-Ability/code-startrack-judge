# Contract resolution register

The supplied V0.2 API/database contracts remain unchanged. This register records missing evidence or genuine shared-interface ambiguity; it grants no alternative behavior. An unresolved question blocks the affected decision, not unrelated foundation work. Track resolutions in GitHub Issues, link agreed evidence here, and publish an approved clarification/erratum when required by the [contract policy](README.md).

GitHub resolution tracker: [#2](https://github.com/STAR-Ability/code-startrack-judge/issues/2).

Status at Phase 0: all questions below are **open**. IDs are stable so implementation Issues can depend on them. Judge/backend owners jointly approve cross-service answers; security/platform and database/compliance owners review their respective decisions.

## Q-001 — Missing whole-system architecture contract

**Evidence:** both supplied documents' introductions defer cross-service boundaries/full integration to `V0.2-整体架构与联调说明.md`. That file and the historical V0.1/V0.11/V0.12 references are not present in this repository.

**Question:** where is the exact authoritative whole-system architecture/integration document, which revision applies, and who owns it? Supply or link the original evidence and reconcile any conflicts with the two current contracts.

**Gate:** does not block service-local scaffolding. Blocks asserting a verified four-service topology, real-backend compatibility, or final end-to-end acceptance until the referenced integration contract is available and reviewed. Owner: project/backend integration lead.

## Q-002 — Canonical hashing and operation identity

**Evidence:** API §§2/6 use normalized request hashes and fixed-field canonical event JSON; database §§3/10/11/13 persist metadata/request/result/payload hashes. The exact canonicalization profile and cross-service test vectors are not supplied.

**Question:** specify field ordering, Unicode/UTF-8 treatment, numeric representation, missing versus null fields, array-order semantics, and each hash's included fields. For management operations keyed by `(operation, requestId)`, confirm how path `problemId` participates in request identity so reuse against another problem cannot replay the wrong result. Do not normalize source bytes before `sourceSha256` calculation.

**Gate:** settle before hash/idempotency/event implementations diverge across owners. Produce shared golden vectors for backend and judge, including malformed and conflict cases. Owner: API/backend integration owners with database review.

## Q-003 — License evidence intake and review workflow

**Evidence:** API §7 requires per-package license review; database §5 requires nonempty evidence/files plus `reviewed_by` and `reviewed_at` for VERIFIED. Imports become VALIDATED only when technical checks and license review both pass. The API lists no license-review mutation endpoint and its import request has no reviewer/evidence fields.

**Question:** what approved administrative workflow supplies reviewed evidence or the explicit import-policy identity, and how does an initially REJECTED package get reviewed and safely re-imported? Define authorization and append-only publication rules without assuming the repository's MIT license covers every problem. Also define where rejected/unsupported original packages, provenance and validation evidence are retained: unsupported packages must be preserved, but a failed import must not create a fictitious validated problem/version, and validation-run/artifact rows require a problem identity. DEFERRABLE foreign keys solve successful transaction insertion order; they do not define failed-package retention.

**Gate:** before imports can create publishable DRAFT versions or production packages can be published. Safe extraction and technical adapter work can proceed against fixtures. Owner: project/compliance lead and import owner; backend owner if a public administrative action is introduced.

## Q-004 — Recovery graph and retry budget

**Evidence:** API §5 draws the normal forward task path; database §10 explicitly permits visible nonterminal state rollback with a higher revision during recovery. API §9 and database §§8/10 describe up to three recovery executions and counters `0..3`. These requirements are compatible, but the exact recovery transitions and boundary fixtures still need a shared design.

**Question:** define the allowed nonterminal recovery transitions and associated lease/start timestamps/events. Make initial-versus-recovery counter semantics explicit in acceptance fixtures, including exhaustion, so owners implement the same bounded policy. Define the same semantics for import leases where applicable. Confirm fencing tests for every transition.

**Gate:** before persistent worker/scheduler recovery is implemented. Terminal states never revive, ordinary TLE is a completed user verdict, and expired lease owners cannot write under either interpretation. Owner: judge/runtime and database owners; backend owner reviews observed transitions.

## Q-005 — Immutable artifact versus validation pointer

**Evidence:** database §4 calls package artifacts immutable but contains `validation_run_id`; §§4/7 permit new validation runs for tool upgrades and preserve old runs. The permitted lifecycle of that pointer, especially after publication, is not explicit. More concretely, database §5 requires post-publication license re-review to append new evidence and a new artifact/version, while §4 uniquely identifies artifacts by `(repository_url, source_revision, package_path, adapter_version)`. Evidence-only re-review at unchanged source/adapter cannot create that required new artifact.

**Question:** reconcile evidence-only re-review with the unique artifact identity; do not mutate published evidence or invent an adapter bump. Publish an allowed-mutability matrix for artifact registration/validation linking and published artifacts. Can a validation-only upgrade change an old artifact's pointer, or must a new artifact/selection record be introduced? Explain how historical publication validation evidence remains traceable and how this interacts with the artifact uniqueness key and license evidence.

**Gate:** before artifact persistence and validation-upgrade workflows. Package bytes, source checksums, and published historical content remain immutable. Owner: problem/import and database owners.

## Q-006 — Mutation rejection and replay edge cases

**Evidence:** API §5 forbids a second attempt for the same business Submission; database §10 enforces unique `submission_id`, but the API does not name the error for a different requestId targeting it. Database §2 requires WITHDRAWN problems to have a current version; API §7 does not state the response when withdrawing an initial DRAFT. Database §13 freezes successful management-operation responses but task replay semantics are not equally explicit.

**Question:** agree exact codes/statuses for a second requestId on one submission and initial-DRAFT withdrawal, including concurrent races. Confirm whether JudgeTask/import replay returns current task state while management replay returns the frozen operation result, and how replay headers/body request IDs are preserved. Define the boundary between POST import `422 PACKAGE_INVALID` (API §7) and validation/license failures on an already accepted asynchronous ImportJob; accepted jobs report their failures through item/task state rather than retroactive HTTP rejection.

**Gate:** before mutation/API contract fixtures. Never create a second task, fabricate a current version, or silently return a successful operation on another resource. Owner: API/backend and database owners.

## Q-007 — Shared manifest and conversion profile

**Evidence:** API §8 pins `ojlab-kattis-v0.2.1`; database §4 pins manifest `0.2.0` and describes its contents without a complete typed schema. Units must be converted explicitly, and checker semantics must match the source package, but missing wall/output defaults and conversion decisions are not enumerated.

**Question:** freeze the typed manifest and its checksum scope, file/test ordering, source-to-normalized paths, checker/validator protocol and allowed adaptations. Define reviewed bounded defaults when upstream wall/memory/output configuration is absent or ambiguous, and record each conversion/default in provenance.

**Gate:** before importer and runtime owners independently consume manifests. This is implementation design constrained by the contracts, not permission to alter limits silently or hide technical failures. Owner: package adapter and judge/runtime owners with security review.

## Q-008 — Bottom-level transport and binding reconciliation

**Evidence:** API §8 requires supervised reuse of the demo's gRPC judge flow and states the bottom-level runtime listens only on `127.0.0.1:5050`. At the exact pins, [demo judger/main.go](https://github.com/criyle/go-judge-demo/blob/ed6cc756082ee9f7d792238185dc3e6a47c84b52/judger/main.go) creates a gRPC ExecutorClient with default `localhost:5051`; [runtime config](https://github.com/criyle/go-judge/blob/e9d70a0d9a3df0c62182a6e7090d7af650a1d5f8/cmd/go-judge/config/config.go) defines separate HTTP `5050` and optional gRPC `5051`; [runtime main.go](https://github.com/criyle/go-judge/blob/e9d70a0d9a3df0c62182a6e7090d7af650a1d5f8/cmd/go-judge/main.go) initializes HTTP plus optional gRPC listeners. These source facts were read during Phase 0; an unchanged demo cannot simply use its gRPC client against the default HTTP `5050` listener.

**Question:** agree a contract-conforming transport/binding configuration or an explicit reviewed transport adapter/clarification. Evaluate the pinned runtime's actual supported listener configuration. Do not add an extra listener, expose a raw submit API, or claim the unchanged upstream processes are already interoperable by assumption. Any required upstream patch needs provenance and review.

**Gate:** before supervising/wiring real runtime processes or claiming the single-container profile works. Owner: judge/runtime, deployment and security owners; project contract owner approves any change to the binding constraint.

## Separate owner/platform decisions

These do not reinterpret the V0.2 contract but must be recorded before the corresponding release gate:

- Project license selection (MIT versus Apache-2.0): repository owner; see the licensing documents. No project license is chosen by Phase 0.
- Actual Linux target, host/kernel/cgroup delegation, restricted capability/mount profile, resource budgets, and retained toolchain-image policy: deployment/security owners; require measured isolation evidence before production execution.
- Business-service language and exact toolchain version after upstream build review: bootstrap owner; record the decision and lock versions before mass implementation.

Issue resolutions must identify the decision owner, evidence, affected contract sections, tests, and any publication/version impact. A closed Issue without an agreed answer and evidence does not resolve a gate.
