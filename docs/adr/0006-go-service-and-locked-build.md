# ADR 0006: Go service with explicit module boundaries and locked builds

- Status: Accepted
- Date: 2026-10-08
- Accountable role: authorized V0.2 implementation owner
- Issues: [#5](https://github.com/STAR-Ability/code-startrack-judge/issues/5), [#6](https://github.com/STAR-Ability/code-startrack-judge/issues/6)
- Authority: [API](../contracts/v0.2/api.md), [database](../contracts/v0.2/database.md), owner-authorized V0.2 implementation task

## Decision

Implement one Go business service using the standard library HTTP server. Pin Go **1.26.8**, a compatible patched toolchain for both upstream repositories' minimum `go 1.26.0`. [toolchain.lock.json](../../toolchain.lock.json) records official archive hashes for supported macOS and Linux architectures. `make toolchain` downloads and verifies the archive; builds and checks set `GOTOOLCHAIN=local` and reject a different SDK version. No release build may resolve a floating toolchain.

Keep `cmd/` entrypoints small. `internal/contract` owns strict DTOs and scalar validation; `internal/config` owns deployment configuration; `internal/httpapi` owns authentication, envelopes and routing; `internal/canonical` owns RFC8785 hashing. Persistence lives under `internal/persistence`, domain workflows under their respective problem/task/catalog packages, and upstream adapters under separate runtime/package packages. No API module imports Backend business models or tables. Parallel owners coordinate these interfaces before implementing dependent behavior.

Use exact native dependencies in `go.mod` and `go.sum`. Reuse golang-migrate **v4.20.1** with its PostgreSQL driver and an owned forward-only checksum-verifying wrapper; use pgx **v5.11.0** for PostgreSQL access. Preserve the selected migration direction in [migration policy](../../migrations/README.md), including explicit SQL transactions and native dirty-state visibility. The wrapper must not offer down/drop/force or rewrite historical checksums.

Use the reviewed RFC8785 implementation at json-canonicalization commit `19d51d7fe467d4706a3ff08adf8a748f29fc21e0`, with additional strict invalid-input checks and independently checked golden vectors. Hash profiles are explicit contract clarifications, rather than a Go-specific serialization convention.

## Reasons and consequences

Go fits the pinned execution/protocol components and keeps portable API/database tests independent of a sandbox. Standard HTTP and explicit repositories keep the small-team system understandable. Native formatting, vet, race/unit/contract tests, and reproducible builds become required checks as source lands. Actual PostgreSQL tests and Linux sandbox qualification remain separate gates; a built service must stay unavailable for execution until its dependencies and isolation probes pass.

All upstream source remains distinguishable in the fetched source cache and reviewed patch series. The language selection does not authorize copying sandbox code or modifying published contracts. Toolchain/module upgrades require explicit lock changes, dependency/license review and affected regression checks. Compiler/toolchain capability for submitted C++17 is a separate runtime lock and cannot be inferred from the Go build SDK.
