# Phase 0 foundation validation

Date: 2026-10-07. Target: V0.2 (`0.2.0`); production release: none recorded. This record covers repository engineering foundation only. It is not judge acceptance, a sandbox certificate, or a production release. Final GitHub delivery/CI evidence is appended after push.

## Delivered foundation

| Requirement | Result / authoritative record |
| --- | --- |
| Governance | `main` default/stable; active ruleset `24657826` requires release PR, blocks deletion/force push, permits documented administrator emergency bypass; `dev` permits validated direct integration. Merge commits preserve release ancestry. [Governance](../development/governance.md) |
| Durable operating manual | [AGENTS.md](../../AGENTS.md) defines ownership, authority, directory seams, compatibility, migrations, historical invariants, security, upstream, workflow, checks and done |
| Historical contracts | Byte-identical supplied originals + `docs/contracts/v0.2/{api,database}.md`, manifest SHA-256 and local aliases; [versioning policy](../contracts/README.md) |
| Architecture | Owned service boundaries, shared-interface planning, five accepted contract-grounded ADRs, [implementation plan](../architecture/implementation-plan.md) |
| API evolution | Consumer-aware additions; deliberate new generation for breaks; introduce/migrate/verify/deprecate/remove; actual backend compatibility evidence required |
| Database evolution | Forward-only consecutive `.up.sql`; deployed history frozen; native runner selected for later implementation with locks/checksums, schema-scoped roles, upgrade/repair/backup requirements. Repository level 0, no SQL/runner/tracking table |
| Development | Standard-library Python tooling + Make + exact-digest PostgreSQL Compose; generated ignored local credentials; upstream bare Git source caches. No fake start/migration command |
| Linux security | Fail-closed host preflight and written adversarial qualification gates; [Linux guide](../development/linux-sandbox.md). Actual judge isolation remains implementation work |
| Upstream/compliance | Four contractual exact source pins, retained verbatim licenses/notices/hashes, additional selected security-critical evidence, [matrix](../upstream/compatibility-matrix.md), reviewed-upgrade policy. Not a complete image SBOM |
| Project license | MIT/Apache-2.0 comparison prepared; owner decision remains open. No project LICENSE selected |
| CI | Portable repository/link/hash/metadata/secret-pattern/shell checks, validator failure-fixture tests, YAML syntax and Compose parse. Read-only workflow, immutable checkout action, no privileged execution |
| Work tracking | Reusable 16 scoped labels; V0.2 milestone; independently bounded implementation/decision Issues with explicit dependencies. Exact links recorded in [plan](../architecture/implementation-plan.md) |
| Releases | Unreleased changelog, tag/version/contract/schema/upstream/digest/test traceability, evidence template, production upgrade/restore procedure. No final release PR/tag/image/deployment created |

## Checks actually performed locally

The development environment agent ran the actual commands on macOS with Python 3.13.2, Docker CLI 29.8.0, Compose 5.5.1, and Colima Docker Engine 29.5.2. PostgreSQL ran Linux/amd64 inside the local Docker VM; this is portable database verification, not real judge isolation.

- `make bootstrap`, repeated bootstrap: generated `.env` mode `0600`, retained existing settings; isolated negative checks rejected placeholder/insecure/symlink settings.
- `make infra-up`: exact PostgreSQL `17.10-bookworm` image became healthy. `make db-version` returned PostgreSQL 17.10 Debian. Inspection confirmed only `127.0.0.1:15432` published and registry index `sha256:9b18b78397054fce88a9552e9d5a3ad5bb7fd258c5b3cc1c5028e46373d6ea8f`.
- Database query confirmed no `judge` schema. `make migration-status` correctly reports repository level zero, no SQL/runner; it does not inspect or certify a deployed schema.
- `make infra-down`: containers stopped; named database volume retained.
- `make upstream-fetch` and offline `make upstream-verify`: all four pinned commits, Git object integrity and retained license evidence passed. No fetched source was built/executed.
- Python script compilation; validator's seven negative/positive fixture groups; shell syntax; Ruby/Psych YAML syntax; `docker compose ... config --quiet` with example placeholders.
- macOS `make sandbox-preflight` returned nonzero because Linux is required; it did not run untrusted programs or claim readiness.

Root reconciliation reran `make check`, all seven validator fixture tests, Ruby/Psych YAML parse, quiet Compose configuration, migration status and upstream verification successfully. It separately confirmed original/snapshot byte equality and all 14 source metadata/binary evidence hashes against fetched pinned Git objects. Independent review outcomes, GitHub check names/results and commit hashes are recorded below once finalized. Local/CI checks cover only their described scope; no schema/DTO business tests, production image, full transitive license audit, real backend compatibility or sandbox isolation was verified in Phase 0.

## Evidence and release blockers discovered

[Q-001..Q-008](../contracts/open-questions.md) preserve unresolved owner decisions: missing overall architecture contract; canonical hash vectors; license-review intake/rejected package retention; recovery graph/attempt budget; evidence-only artifact re-review conflicting with uniqueness; mutation/replay edge cases; typed manifest/default conversion profile; demo gRPC transport versus the prescribed bottom-level listener.

Exact source review also found demo/runtime protobuf version skew (compatibility untested), startup token logging requiring safe configuration or provenance-tracked redaction, default demo metrics/pprof and unauthenticated runtime diagnostics requiring listener/route review, and problemtools packaging that copies JARs containing nested MigLayout/Eclipse material whose redistributable attribution is not fully established. The VIVA code itself has MIT attribution evidence in upstream `debian/copyright`; that does not settle the nested components. These block affected implementation/redistribution gates, not the engineering foundation.

Owner decisions remaining: project license; applicable missing integration contract/clarifications; business language/exact patched toolchain; Linux host, privilege/delegation profile, budgets, secrets/backup/retention/support policies. Do not silently resolve them by relaxing contracts.

## Independent review and final delivery

Independent reviewers examined all nine requested perspectives. All nine final verdicts are resolved. Each reviewer read actual written files and distinguished source/portable evidence from future runtime qualification.

| Perspective | Review reconciliation |
| --- | --- |
| New human developer | Commands/navigation passed; Compose prerequisite made consistently >=2.20; final remote clone checked after push |
| Fresh coding-agent session | Permanently frozen root historical contracts clarified; P01 now explicitly owns language/toolchain/build/source-layout and native CI decisions |
| Database engineer | Migration docs and full foundation independently reviewed; ownership, deferred constraints, atomicity, acyclic Issue DAG and honest level-zero state pass |
| Backend integration owner | Corrected terminal-result nullability (including valid CANCELLED), retry deadline versus retained dead letters, public license.sourceUrl allowance, and deterministic 4xx qualifier; verified live Issue readbacks |
| Judge/runtime engineer | Same terminal/dead-letter fixes; added exact pinned diagnostic listener/route risks to runtime/image/qualification gates |
| Security reviewer | Read-only CI, source retrieval boundary, process/secret rules and diagnostic additions reviewed; no runtime certification claimed |
| Compliance reviewer | Exact retained bytes and tag/commit evidence independently verified; corrected upgrade policy to avoid requiring new artifacts for every validation-tool change |
| Production operator | Development commands, level-zero status, fail-closed Linux/production/release/backup procedures reviewed |
| Future maintainer | Q-005 now explicitly gates first schema Issue #6 and clarification #2; history/evolution/upgrade policy reviewed |

GitHub inventory readback confirmed [milestone 1](https://github.com/STAR-Ability/code-startrack-judge/milestone/1), 16 reusable scoped labels and 24 Issues: foundation [#1](https://github.com/STAR-Ability/code-startrack-judge/issues/1), contract register [#2](https://github.com/STAR-Ability/code-startrack-judge/issues/2), owner project license [#3](https://github.com/STAR-Ability/code-startrack-judge/issues/3), nested-binary audit [#4](https://github.com/STAR-Ability/code-startrack-judge/issues/4), and P01–P20 [#5–#24](https://github.com/STAR-Ability/code-startrack-judge/issues?q=is%3Aissue+milestone%3A%22V0.2+Judge+%26+Problem+Service%22). Milestone contains 22 items (#2/#4 plus 20 implementation Issues); no invented deadline. Source drafts/IDs and actual URLs are retained in the [Issue plan](../architecture/issue-plan.json).

Recommended first implementation Issue: [#5 / P01](https://github.com/STAR-Ability/code-startrack-judge/issues/5). Build configuration/strict shared HTTP fixtures first, then schema #6; problem/license/adapter and runtime/template/image tracks run in parallel. Primitive Linux qualification #21 precedes real package verification #10. Atomic task/result/outbox core #18 precedes admission #16 and scheduler #17. Complete callback delivery #19, mock acceptance #22, real-backend coordination #23, and final-image/four-service acceptance #24. Unresolved contract gates block their affected decisions only.

GitHub delivery/CI evidence remains pending until the final reviewed push; no final release PR is created.
