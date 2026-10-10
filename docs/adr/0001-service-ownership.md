# ADR 0001: Preserve service ownership boundaries

- Status: Accepted
- Date: 2026-10-07
- Accountable roles: repository lead; backend and algorithm integration owners
- Evidence: [API contract](../contracts/v0.2/api.md) §1; [database contract](../contracts/v0.2/database.md) §1

## Context

Platform judging is new infrastructure alongside existing backend-owned CF/user workflows and algorithm-owned analysis. A shared PostgreSQL host and similar numeric IDs could otherwise encourage cross-service table access or accidental identity conflation.

## Decision

Judge owns platform problems/packages/versions, private tests, validation/license provenance, catalog snapshots, JudgeTasks and raw judgment facts. Backend owns users, business Submission, long-term source, public projections, training and orchestration. Algorithm owns analysis facts. Frontend uses backend. Use complete `ProblemRef` identities, service-specific credentials, internal HTTP and fixed result events; do not introduce cross-schema foreign keys or direct backend/algorithm table access.

## Reasons

Ownership makes audit, failure handling and future upgrades explicit. Backend can preserve existing CF behavior and coordinate analysis without judge learning user identity or acquiring public authorization responsibilities.

## Consequences

Backend mocks and contract tests are required. Logical Submission references are intentional and need input/mapping verification. Catalog caches and result projections are derived, carry their source owner and cannot overwrite judge facts. The missing whole-system reference remains [Q-001](../contracts/open-questions.md#q-001--missing-whole-system-architecture-contract).

Current status (2026-10-08): the exact owner-supplied [whole-system integration contract](../contracts/v0.2/integration.md) has been recovered byte-identically. [Q-001](../contracts/open-questions.md#q-001--missing-whole-system-architecture-contract) records its provenance and resolution; real consumer and integration acceptance remain separate gates.

## Alternatives

Shared business tables or a combined user/judge service simplify some local queries but violate the supplied contracts and obscure fact ownership. They are not authorized alternatives for V0.2.

## Revisit / upgrade conditions

A deliberate service-boundary change requires joint owner review, a new contract publication and a migration that preserves historical identities/projections. Adding user-driven features does not by itself transfer user ownership to judge.
