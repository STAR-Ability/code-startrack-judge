# Code Startrack Judge & Problem Service

Platform problem packages, immutable problem versions, asynchronous judging, and original judge results for Code Startrack. Backend owns user authorization, Submissions and source retention, public projections, training, and analysis orchestration. Frontend calls backend; this service exposes internal APIs to backend and sends events to its fixed receiver.

**Status:** V0.2 (`0.2.0`) implementation in progress after the completed Phase 0 foundation. Service/strict HTTP/hash and schema foundations are being implemented through the existing Issues. No production release or qualified execution capability is recorded. The service intentionally reports unavailable until its real dependency and sandbox checks pass.

The active implementation baseline is [V0.2 contracts](docs/contracts/README.md). These are versioned historical contracts, not permanent assumptions for later releases. [Open contract questions](docs/contracts/open-questions.md) must be resolved before dependent behavior is implemented.

## Start development

Use macOS or Linux with Python 3.11+, Git, Make, and Docker Engine/Desktop or Colima with Compose 2.20+. Clone `dev`, because `main` is the stable release branch:

```sh
git clone --branch dev https://github.com/STAR-Ability/code-startrack-judge.git
cd code-startrack-judge
make bootstrap
make toolchain
make contract-test-setup
make check
make build
make upstream-fetch
make upstream-verify
make infra-up
make db-version
make migration-status
make infra-down
```

Bootstrap generates ignored local infrastructure credentials; never commit `.env`. PostgreSQL is localhost-only. `make toolchain` installs the exact checksum-verified Go SDK; `make check` runs foundation checks and native formatting, vet, race tests and build checks. `make build` produces service and forward migration binaries. [Service development](docs/development/service.md) describes `make run`, configuration and current capability limits. Database-backed migration acceptance is tracked in [#6](https://github.com/STAR-Ability/code-startrack-judge/issues/6); repository migration files are distinct from applied database history. See [getting started](docs/development/getting-started.md) for infrastructure commands.

Portable development supports future API, database, metadata/import parsing and mock integration work. **It does not establish sandbox security.** User programs, validators, reference solutions and checkers require a separately qualified [Linux environment](docs/development/linux-sandbox.md). Failed isolation must stop execution; ordinary Docker or macOS must never silently use unrestricted execution.

## Project map

| Start here | What it answers |
| --- | --- |
| [AGENTS.md](AGENTS.md) / [CONTRIBUTING.md](CONTRIBUTING.md) | Durable operating rules, completion expectations and contributions |
| [Architecture](docs/architecture/overview.md) / [ADRs](docs/adr/README.md) | Service boundaries and intentional engineering decisions |
| [Contracts](docs/contracts/README.md) / [implementation plan](docs/architecture/implementation-plan.md) | Shared interfaces, evolution and scoped delivery order |
| [Database evolution](docs/development/database.md) | Schema ownership, immutable migrations and upgrade safety |
| [Security](SECURITY.md) / [security model](docs/security/model.md) | Private reporting and execution/data/credential boundaries |
| [Upstream dependencies](docs/upstream/dependencies.md) / [compatibility](docs/upstream/compatibility-matrix.md) | Exact versions, provenance and what has actually been validated |
| [Third-party notices](THIRD_PARTY_NOTICES.md) / [project license decision](docs/licenses/project-license-decision.md) | Attribution and accepted Apache-2.0 licensing for owned source |
| [Production deployment](docs/deployment/production.md) / [release process](docs/releases/process.md) | Qualification gates, release evidence and operational handover |
| [Governance](docs/development/governance.md) / [changelog](CHANGELOG.md) | Branch protections and release history |

Code Startrack-owned source uses [Apache-2.0](LICENSE), following the repository owner's explicit decision. Upstream software and imported problem content retain their independent licenses, notices and review requirements.
