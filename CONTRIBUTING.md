# Contributing

Read [AGENTS.md](AGENTS.md), the [active contracts](docs/contracts/README.md), and the relevant [ADRs](docs/adr/README.md). Work should make a scoped Issue's acceptance criteria concrete. Implementation priorities and dependencies are in the [implementation plan](docs/architecture/implementation-plan.md).

## Small-team workflow

Use `dev` for validated integration work. Direct pushes to `dev` are allowed for the current team; use a short-lived `feature/*` branch and PR when review/concurrent work benefits. Preserve other contributors' changes. Coordinate shared interfaces and migration number allocation before parallel edits.

`main` receives stable releases through a `dev → main` PR. Use a merge commit for that PR so integration ancestry is retained. Do not delete `dev`, create a final release PR during Phase 0, or push ordinary work directly to `main`. Emergency administrator bypass requires an incident reason and retrospective review; see [governance](docs/development/governance.md).

## Issues and commits

State the problem, boundaries, contract references, acceptance criteria and dependencies. Reference the Issue in meaningful commits (`Refs #123`, `Fixes #123` only when finished). A documented authorized task is sufficient for small maintenance; no micro-Issue is required for every typo. Use clear conventional-style subjects such as `docs: explain migration recovery` or `feat: persist task acceptance`.

Do not resolve contract ambiguity by inventing behavior. Register it and consult the affected service owner; independent work may continue. Public Issues must not contain hidden tests, submitted source, credentials, or vulnerability exploit details.

## Validation and review

Every change runs `make check`. Business implementation adds the appropriate language checks and focused tests; persistence changes need real PostgreSQL transaction/constraint/concurrency coverage. API changes need backend consumer fixtures for validation, idempotency, statuses and error projection. Run failure/recovery tests for asynchronous work. Security-sensitive execution changes require independent runtime/security review and real Linux isolation evidence, not portable mocks.

PRs state the resulting behavior, Issue link, relevant contract/ADR, checks and environments actually run, operational consequences, and remaining risks. Use the repository PR template. A small team may use one competent reviewer rather than mandatory review bureaucracy; the author still owns verification. Future team growth can require review on `dev` after actual checks and owners exist.

## Data, dependencies and docs

- Reserve migration numbers with the database owner; add forward-only `.up.sql` files. Never rewrite shared/deployed migrations. Include fresh application and upgrade validation, lock/backfill/compatibility analysis and recovery instructions. See [database policy](docs/development/database.md).
- Dependency changes require an Issue, exact pin/diff, license/security review and relevant compatibility regression evidence. Update the lock, notices and [compatibility matrix](docs/upstream/compatibility-matrix.md); follow the [upgrade policy](docs/upstream/upgrade-policy.md). Preserve patch provenance. Do not automatically chase new versions.
- Document durable architecture decisions in ADRs and update executable development/deployment guidance. Released contracts and immutable artifact facts are historical records; changes require the appropriate new contract/evidence/version.
- Keep credentials ignored and out of logs. Report vulnerabilities privately through [SECURITY.md](SECURITY.md). Do not run imported code outside the reviewed sandbox or add Docker socket/host-root mounts.

Work is complete only when scoped acceptance, real validation, review, documentation/provenance and the authorized branch delivery are all satisfied. Clearly label unimplemented or unverified capabilities.
