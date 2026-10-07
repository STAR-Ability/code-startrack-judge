# Code Startrack Judge & Problem Service

Platform problem packages, immutable problem versions, asynchronous judging, and original judge results for Code Startrack. Backend owns user authorization, Submissions and source retention, public projections, training, and analysis orchestration. Frontend calls backend; this service exposes internal APIs to backend and sends events to its fixed receiver.

**Status:** Phase 0 engineering foundation, targeting V0.2 (`0.2.0`). No production service release is recorded. Business APIs, migrations, import/scheduler adapters and the production sandbox are planned implementation work; this repository does not currently run a judge service.

The active implementation baseline is [V0.2 contracts](docs/contracts/README.md). These are versioned historical contracts, not permanent assumptions for later releases. [Open contract questions](docs/contracts/open-questions.md) must be resolved before dependent behavior is implemented.

## Start development

Use macOS or Linux with Python 3.11+, Git, Make, and Docker Engine/Desktop or Colima with Compose 2.20+. Clone `dev`, because `main` is the stable release branch and currently only has the empty repository baseline:

```sh
git clone --branch dev https://github.com/STAR-Ability/code-startrack-judge.git
cd code-startrack-judge
make bootstrap
make check
make upstream-fetch
make upstream-verify
make infra-up
make db-version
make migration-status
make infra-down
```

Bootstrap generates ignored local credentials; never commit `.env`. PostgreSQL is localhost-only. The first schema Issue will add the real forward migration runner; migration level is currently zero. There is no service start command until bootstrap implementation lands. See [getting started](docs/development/getting-started.md) for prerequisites, environment variables, commands and troubleshooting.

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
| [Third-party notices](THIRD_PARTY_NOTICES.md) / [project license decision](docs/licenses/project-license-decision.md) | Attribution and pending owner license choice |
| [Production deployment](docs/deployment/production.md) / [release process](docs/releases/process.md) | Qualification gates, release evidence and operational handover |
| [Governance](docs/development/governance.md) / [changelog](CHANGELOG.md) | Branch protections and release history |

Code Startrack's own project license is awaiting owner selection. Retained upstream license texts apply to their respective materials; they do not grant permission for every imported problem package. No root project LICENSE is inferred.
