# Code Startrack Judge & Problem Service — repository operating rules

These rules apply to humans and coding agents throughout this repository. Read this file, the current contracts, and the relevant accepted ADRs before changing behavior. The Phase 0 foundation is complete; V0.2 business implementation proceeds through scoped Issues.

## Identity and ownership

This service owns platform problems, immutable package/version artifacts, private tests and validation evidence, catalog snapshots, persistent JudgeTasks, and original judge results. It executes untrusted code through reviewed upstream sandbox components.

Backend owns users, authorization, business Submissions, long-term submitted source, training records, public result projections, and orchestration of analysis/recommendations. Frontend calls backend. Algorithm owns analysis computation. Judge neither accesses their business tables nor calls algorithm. Cross-service identifiers are logical references; platform and external problem identities must retain their complete namespace.

## Authority and conflict handling

1. The active versioned implementation contracts and subsequently published contract amendments.
2. Accepted [ADRs](docs/adr/README.md), within those contracts.
3. This operating manual.
4. Implementation/development documentation.
5. Existing code behavior.

A published historical contract governs its historical release. A draft future contract does not override the active contract. Conflicting code is a defect, not an undocumented amendment. Record ambiguities in [the contract register](docs/contracts/open-questions.md) and an Issue; resolve with the relevant service owners before implementing dependent semantics. Do not silently edit a contract or use an ADR to override it. Security isolation may never be weakened to make implementation or tests easier.

## Current release pointers

- Target: V0.2 / service release `0.2.0`; no production release recorded yet.
- Implementation baseline: [contracts v0.2](docs/contracts/README.md), contract publication identifier `0.2.0`, API generation `/internal/v2`.
- Repository migration level: `1` (initial schema candidate; applied database history is recorded separately).
- Release/deployment evidence belongs in [release records](docs/releases/process.md); [state.json](docs/releases/state.json) records the repository's current pointers, not live deployment health.

Update these small pointers when a release/contract becomes active; do not turn this file into a milestone checklist.

## Directory ownership

| Path | Purpose and change owner |
| --- | --- |
| `docs/contracts/` | Versioned API/database source of truth; joint service-owner review |
| `docs/adr/`, `docs/architecture/` | Intentional architecture and implementation work boundaries |
| `migrations/` | Judge-owned forward schema evolution; one migration allocator per concurrent wave |
| `scripts/`, `Makefile`, `compose.yaml` | Reproducible development and foundation verification |
| `.github/` | Portable CI and contributor templates |
| `upstream.lock.json`, `docs/upstream/`, `docs/licenses/` | Exact upstream provenance, compatibility and license evidence |
| `docs/development/`, `docs/security/`, `docs/deployment/`, `docs/releases/` | Operational instructions and evidence requirements |
| `.cache/`, `.local/`, `artifacts/` | Ignored fetched sources/local state/results; never original project source |

Future source layout is chosen in the service-bootstrap Issue. Keep API, persistence, orchestration and upstream adapters separate with small explicit interfaces; avoid speculative frameworks. Upstream source stays distinguishable from project-owned adapters. Root Chinese contracts remain byte-identical historical source copies.

## API and data evolution

Follow [contract versioning and API evolution](docs/contracts/README.md). Additions are compatible only when actual consumers tolerate them, including enum additions. Field removal, changed requiredness/meaning, identity, authentication, state machines, or idempotency require a reviewed migration; use a new API generation when necessary. Introduce → migrate consumers → verify → deprecate → remove, with an announced window and recorded consumer evidence. Release version, contract publication, API generation, and schema migration level are different identities.

Follow [database policy](docs/development/database.md): forward-only numbered migrations, never edit/reorder/delete migrations used in shared environments, never undocumented manual production SQL. Review lock duration, backfills, constraints, privilege boundaries, compatibility with the previous application, backup/restore and failure recovery. Database facts, migration ledger/checksums and shipped release manifests must make applied schema history visible.

Preserve problem/version IDs, original and normalized package checksums, license/validation evidence, frozen task inputs/runtime/toolchain identity, original results, and released contracts. New semantics produce new versions/evidence, not rewrites of historical facts. A retention exception such as transient-source cleanup must follow the active contract and must not delete backend-owned source or immutable problem history. Historical reproducibility means tracing the recorded environment and inputs; replay of submitted source requires backend's authorized source retention.

## Upstream and security invariants

- Use exact reviewed commits/releases and image digests; never silently track `latest`, a branch, or an unqualified tag.
- Do not copy upstream code without provenance/license texts. Patches require origin, base commit, diff, reason, license/compatibility impact and upgrade conditions.
- Sandbox execution/limits must reuse mature reviewed components. Replacing them or rewriting isolation requires explicit architectural and security review.
- Submitted code, compilers handling it, validators, checkers and reference solutions are untrusted. Portable development uses mocks; real execution qualification requires Linux evidence.
- Never accept arbitrary caller shell commands, execution templates, test data, callback URLs, filesystem paths or network fetch destinations.
- Hidden tests, answers, user stdout/stderr, raw tool logs, internal object addresses and credentials stay out of public DTOs and normal logs. Emit bounded redacted diagnostics and correlation IDs.
- No Docker socket, host-root mounts, backend database/source-bucket credentials, or production secrets in sandbox workers. Scope each process's credentials; shared-container environment/process boundaries need real verification.
- Production has no privileged default. Grant only a reviewed, empirically verified Linux capability/delegation/mount profile; loopback runtime interfaces stay private. Disable submission network, enforce CPU/wall/memory/output/filesystem/process isolation, and prove cleanup.
- Required isolation failure means readiness fails and new execution stops. Never fallback to unrestricted execution or substitute mocks for security acceptance.
- Commit no real credentials, private keys or `.env` files. Do not print rendered secret-bearing Compose configuration. Use [security guidance](docs/security/model.md) and [private reporting](SECURITY.md).

## Workflow and traceability

`dev` is integration: validated small-team work may be pushed directly. `main` is stable: normal changes arrive only through a `dev → main` release PR and final validation. Never force-push/delete `main`. Administrators have emergency bypass, used only for documented incidents, not ordinary delivery. Merge release PRs with a merge commit to preserve `dev` ancestry; do not delete `dev`. When the team grows, use `feature/* → PR → dev` without changing release flow. See [governance](docs/development/governance.md).

Meaningful work references an Issue or documented authorized task. Commits describe the resulting change; split unrelated work. Inspect status/diff before committing and preserve unknown user changes. Concurrent owners agree interfaces from contracts before implementation, reserve migration numbers centrally, and avoid editing each other's owned paths without coordination. Do not create a release PR, tag, image or deployment as a side effect of a scoped implementation task.

<!-- CODEGRAPH_START -->
## CodeGraph

When `.codegraph/` exists, use `codegraph_explore` (MCP, if available) or `codegraph explore "<question or symbol/file>"` **before grep/find or reading source to understand or locate code**. Inspect current source when the index is stale. If no relevant code is indexed, use `rg`/direct reads as fallback; never index without the owner's decision. If `.codegraph/` is absent, skip it.
<!-- CODEGRAPH_END -->

## Validation, documentation and done

Run `make check` for all work. Add the actual language formatter/linter/unit/contract checks when source exists, PostgreSQL integration tests for persistence, migration application/upgrade checks for DDL, consumer fixtures for API changes, and Linux runtime/adversarial tests for security-critical changes. Tests should exercise real invariants and failure behavior, not mirror implementation. Ordinary CI and privileged sandbox qualification remain separate. Record which environment ran each check and its limitations; never claim unrun tests passed.

Architecture/security/ownership/evolution changes update the relevant docs and an ADR when a durable choice changes. Keep instructions executable, link authoritative content instead of copying it, update compatibility/release records after actual qualification, and keep planned work distinct from delivered capabilities.

A task is done when its scoped acceptance criteria are satisfied, required checks actually pass, meaningful independent review findings are resolved, contracts/security/history remain intact, docs/provenance are updated, limitations and owner decisions are explicit, and reviewed commits reach the authorized branch. Files existing, a green unrelated check, or a plausible report alone are not completion evidence.
