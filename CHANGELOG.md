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

### Changed

- Adopted owner-approved Apache-2.0 for Code Startrack-owned source; retained independent third-party terms and problem license approval.

### Security

- Explicit separation of portable development from Linux sandbox qualification; isolation failures must stop execution.

### Planned

- V0.2 business workflows, package adapters, task/outbox execution and actual image/Linux deployment qualification.
