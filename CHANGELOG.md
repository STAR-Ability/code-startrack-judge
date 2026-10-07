# Changelog

Versions follow the [release policy](docs/releases/process.md). No production release has been recorded. A release entry is created only when a reviewed tag/release is made; Phase 0 does not issue `v0.2.0`.

## Unreleased

### Added

- Durable repository operating rules and versioned `0.2.0` API/database contract baseline.
- Architecture decisions, implementation dependency plan, forward-only migration policy, and security/release procedures.
- Portable PostgreSQL development environment, exact upstream source/license inventory, and foundation CI.
- Small-team `dev` integration / protected `main` release workflow and V0.2 work tracking.

### Security

- Explicit separation of portable development from Linux sandbox qualification; isolation failures must stop execution.

### Planned

- V0.2 service implementation, migration runner/schema, package adapters, task/outbox execution and deployment qualification.
- Owner selection of the project's own license. Third-party notices are independently retained.
