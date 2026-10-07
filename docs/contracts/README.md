# Versioned implementation contracts

Code Startrack Judge & Problem Service evolves independently of a single milestone. Contracts describe release-specific behavior; repository rules and architecture records describe how that behavior is maintained.

## Active contract

| Item | Current value |
|---|---|
| Target service release | V0.2, not yet implemented or released |
| Contract release | `0.2.0` |
| Internal API generation | `/internal/v2` |
| API contract | [v0.2/api.md](v0.2/api.md) |
| Database contract | [v0.2/database.md](v0.2/database.md) |
| Integration contract | [v0.2/integration.md](v0.2/integration.md) |
| Engineering clarifications/amendments | [v0.2/clarifications.md](v0.2/clarifications.md); implementation/release review gates recorded separately |
| Supplied source provenance | [v0.2/provenance.md](v0.2/provenance.md) |
| Immutable package/runtime protocol | [v0.2/package-protocol.md](v0.2/package-protocol.md), [manifest schema](v0.2/manifest-schema.json), [validation checkpoint schema](v0.2/validation-results-schema.json) |
| Open questions | [Resolution register](open-questions.md) |

The original supplied documents remain at [判题题库api文档.md](../../判题题库api文档.md) and [判题题库数据库文档.md](../../判题题库数据库文档.md). Those root originals and the `v0.2/` snapshots are frozen baseline evidence; never overwrite them to describe a later release. New publications/errata use new artifacts, and this index's active pointer changes deliberately. The `v0.2/` copies preserve the originals' bytes, with adjacent Chinese-name symlink aliases preserving their mutual relative links. Integrity is recorded in `v0.2/manifest.json` and checked by repository validation.

Both supplied contracts reference `V0.2-整体架构与联调说明.md`, which was absent when the foundation was created. The exact owner-supplied `0.2.0` integration contract has now been recovered, copied without changing its bytes, and recorded in the manifest. The historical links resolve through adjacent aliases; their former bounded missing-link exception is no longer needed. Six linked service documents are preserved as supplementary [reference evidence](v0.2/reference/README.md), with exact checksums and aliases. [Q-001](open-questions.md#q-001--missing-whole-system-architecture-contract) records the recovered evidence; real consumer/integration acceptance remains a separate gate.

## Authority and publication

Published versioned contracts take precedence over accepted ADRs, repository-wide [AGENTS.md](../../AGENTS.md), implementation guides, and code behavior, in that order. A higher-priority document does not make a contradiction safe: record the conflict, stop work that depends on an unresolved answer, and obtain a reviewed resolution from the relevant owners. Never repair a mismatch by silently changing tests, DTOs, or the contract.

The V0.2 source files are authoritative input, not evidence that the service has passed acceptance. A service release, a contract release, an API generation, a manifest schema version, a migration level, and an upstream version are separate identifiers. Record their relationship for each deployment rather than inferring it from the repository name.

Each contract publication must identify its release number, source/evidence, effective service releases, API generations, consumer compatibility, and changes from the previous publication. Preserve published text and its integrity record. Append a reviewed clarification/erratum with its scope, affected sections, owner approvals, and date when correcting historical ambiguity; do not erase the original evidence. Incompatible behavior belongs in a new version directory such as `v0.3/` or `v1.0/`. A contract publication does not automatically require an API-generation change.

## Compatibility review

Judge and backend owners review changes together. Compatibility includes request validation, response semantics, resource identity, units, authentication, idempotency, state transitions, events, error handling, and migration/rollout behavior, not merely matching JSON field names. Contract tests must cover both directions and exact request/response examples.

Potentially compatible changes include new endpoints, optional response fields, and optional query parameters with unchanged defaults. Enum additions are compatible only when deployed consumers tolerate unknown values safely. Strict request validation remains intentional: the V0.2 contract rejects unknown request fields, so new request fields require coordinated consumer/provider deployment even when optional.

Removing fields, making fields required, changing meanings or identity, changing authentication/idempotency, or altering terminal-state semantics can break consumers. Use a deliberate migration and, when needed, a new generation such as `/internal/v3`. Do not silently redefine `/internal/v2`.

The lifecycle is **introduce → migrate consumers → verify → deprecate → remove**. Document a supported overlap window, usage evidence, rollback behavior, and an agreed removal release. Deprecation is announced to named consumers and reflected in contracts/release notes. Remove a generation only after its consumers have migrated and historical records remain interpretable. Retain obsolete APIs only for a documented need with an owner and review date.

## Backend/judge compatibility evidence

Every release record must name the backend build/release, judge build/release, contract publication and API generation, tested callback/inbox and polling behavior, catalog-snapshot behavior, and test evidence. No backend build is claimed compatible during Phase 0; the mock and real-backend acceptance workstreams in the [implementation plan](../architecture/implementation-plan.md) must produce this evidence.

The upstream [compatibility matrix](../upstream/compatibility-matrix.md) separately tracks sandbox and package tooling. Passing an upstream check does not prove backend integration, and a green portable CI run does not prove real Linux isolation.
