# Third-party attribution inventory

Source/license inspection date: 2026-10-07. Exact revisions and SHA-256 evidence are in [upstream.lock.json](upstream.lock.json); [compatibility](docs/upstream/compatibility-matrix.md) is tracked separately. This is a curated source inventory, not a complete released-image SBOM. No production image has been released by Phase 0.

| Component | Copyright / declared terms | Evidence retained |
|---|---|---|
| criyle/go-judge-demo, contract commit | Copyright (c) 2019 Yang Gao; MIT | [LICENSE](docs/licenses/go-judge-demo-LICENSE) |
| criyle/go-judge, v1.13.0 | Copyright (c) 2019 Yang Gao; MIT; vendored seccomp profile is Apache-2.0 | [LICENSE](docs/licenses/go-judge-LICENSE), [seccomp NOTICE](docs/licenses/go-judge-seccomp-NOTICE), [Moby Apache license](docs/licenses/moby-profiles-Apache-2.0-LICENSE) |
| oj-lab/problem-packages, contract commit | Copyright (c) 2024 oj-lab; root MIT declaration | [LICENSE](docs/licenses/problem-packages-LICENSE); per-package content review pending |
| Kattis/problemtools, v1.20260907 | Copyright (c) Kattis and all respective contributors; MIT | [LICENSE](docs/licenses/problemtools-LICENSE), [Debian copyright declarations](docs/licenses/problemtools-debian-copyright) |
| criyle/go-sandbox, v0.14.0 (runtime direct dependency) | Copyright (c) 2019 criyle; MIT | [LICENSE](docs/licenses/go-sandbox-LICENSE) |
| elastic/go-seccomp-bpf, v1.6.0 (runtime direct dependency) | Copyright 2022 Elasticsearch B.V.; Apache-2.0 | [LICENSE](docs/licenses/go-seccomp-bpf-Apache-2.0-LICENSE), [NOTICE](docs/licenses/go-seccomp-bpf-NOTICE) |
| VIVA shipped by pinned problemtools | Debian metadata declares MIT, Copyright 2010–2018 David van Brackle | [declared evidence](docs/licenses/problemtools-debian-copyright); nested MigLayout jar and Eclipse loader attribution unresolved |

MIT requires the copyright and permission notice in copies or substantial portions. Apache-2.0 requires a license copy, relevant retained notices, prominent change notices on modified files, and applicable NOTICE attribution when included. These summaries do not replace the original terms. [NOTICE](NOTICE) carries the verified Moby/Elastic notice text. Preserve upstream's original files and source attribution if adapting or redistributing them.

Moby's original seccomp snapshot revision is not specified by the go-judge NOTICE. The snapshot is fixed by the contracted go-judge source/hashes. The supplemental Moby revision in the lock identifies the Apache license text inspected, and does not assert origin of that snapshot.

Before image redistribution, resolve the [known dependency gates](docs/upstream/dependencies.md), including nested VIVA artifacts, actual resolved Go/Python/OS dependencies and the artifact SBOM. Do not assign a guessed SPDX identifier to unknown nested terms. Imported problem statements, images, tests, answers, reference solutions and validators require independent, retained package evidence; root MIT is not automatic publication approval.

Code Startrack-owned source uses [Apache-2.0](LICENSE), following the [owner decision](docs/licenses/project-license-decision.md). This does not relicense any component or imported problem content listed here.
