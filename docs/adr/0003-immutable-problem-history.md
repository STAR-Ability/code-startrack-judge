# ADR 0003: Preserve immutable problem history and frozen judgment inputs

- Status: Accepted
- Date: 2026-10-07
- Accountable roles: repository lead; problem, database and judge/runtime owners
- Evidence: [API contract](../contracts/v0.2/api.md) §§3/5/7; [database contract](../contracts/v0.2/database.md) §§2–7/10–12

## Context

A problem can gain new tests, metadata or execution rules while old submissions remain auditable. A mutable current problem row or a floating compiler image would make past judgment facts misleading.

## Decision

Separate stable problem identity from UUID problem versions and checksum-addressed private package artifacts. New content/limits/tests/checker/metadata create new version records; metadata-only versions can share the same immutable artifact. Tasks freeze the accepted version, checker, limits, language-template version, sandbox version and actual worker image digest. Results/cases are immutable after terminal commit. Publishing changes the current pointer/catalog atomically; withdrawal keeps historical versions/artifacts/results.

## Reasons

The separation supports reproducible interpretation, safe upgrades and reliable backend cache invalidation without losing historical identity. License and technical validation evidence remain independently traceable.

## Consequences

Storage retention and image/toolchain retention need explicit operator policies. Source remains backend-owned: judge clears its transient copy after the contract's terminal retention window, so reproducibility metadata is not a promise of autonomous later re-execution. `first_published_at` has a one-time allowed transition; selection-pointer mutability and evidence-only re-review need resolution in [Q-005](../contracts/open-questions.md#q-005--immutable-artifact-versus-validation-pointer).

## Alternatives

Editing published rows in place or deleting withdrawn packages reduces short-term storage but destroys the required historical explanation. Copying metadata and tests without artifact identity/provenance also obscures what actually ran.

## Revisit / upgrade conditions

Future retention/privacy or storage requirements need reviewed archival policies that retain required checksums, provenance and interpretability. API rejudge support requires a separate contract and task identity model; it must not be inferred from historical-data retention.
