# Changelog

Versions follow the [release policy](docs/releases/process.md). No production release has been recorded. A release entry is created only when a reviewed tag/release is made; Phase 0 does not issue `v0.2.0`.

## Unreleased

### Added

- Durable repository operating rules and versioned `0.2.0` API/database contract baseline.
- Architecture decisions, implementation dependency plan, forward-only migration policy, and security/release procedures.
- Portable PostgreSQL development environment, exact upstream source/license inventory, and foundation CI.
- Small-team `dev` integration / protected `main` release workflow and V0.2 work tracking.
- Byte-identical recovered integration contract, explicit V0.2 clarifications, typed package/validation schemas and canonical/archive golden vectors.
- Go 1.26.8 service, strict internal HTTP/DTO/hash boundaries, native dependency/license inventory and reproducible build checks.
- Initial forward PostgreSQL schema, checksum-aware migration runner and separately scoped provisioning/runtime roles.
- Provenance-tracked upstream hardening patches and private binary-safe sandbox REST transport.
- Immutable private-object storage and problem/artifact/version repositories with garbage collection that preserves historical owners.
- Asynchronous fixed-revision OJ-Lab imports, deterministic USTAR adaptation, retained rejection diagnostics and streamed private validation evidence.
- Append-only trusted ADMIN license receipts, immutable metadata versions, publication/withdrawal and consistent protected catalog snapshots.
- C++17 task admission, live capability checks, fenced scheduling with three counted recoveries, atomic results/case history and transactional callback snapshots.
- Fixed-target callback delivery, durable retry/dead letters and explicit audited manual redelivery.
- Five forward schema migrations and actual PostgreSQL integrity, concurrency, privilege and SQL-log redaction checks.

### Changed

- Adopted owner-approved Apache-2.0 for Code Startrack-owned source; retained independent third-party terms and problem license approval.

### Security

- Explicit separation of portable development from Linux sandbox qualification; isolation failures must stop execution.
- Final Linux entrypoints measure nondumpability after execution; exact upstream patches and vendor source inventories preserve reviewed provenance.

### Planned

- Final Linux image and isolated problemtools qualification, cross-service compatibility, protected release merge and official immutable artifact publication.
