# Service development

The owned service uses [Go 1.26.8](../../toolchain.lock.json), following [ADR 0006](../adr/0006-go-service-and-locked-build.md). Install and verify the SDK with `make toolchain`; this requires Python 3.11.8+ with safe tar extraction filtering and does not change the system Go installation. Every native command sets `GOTOOLCHAIN=local`, so a global automatic resolver cannot downgrade or replace the locked compiler. `make check` checks formatting, runs vet and race tests, and compiles the complete module. `make build` writes ignored binaries under `build/`.

Native checks also verify the exact command dependency/license closure and the canonical golden vectors with independent Node.js serialization. Install Node.js 18+ for this test-only verifier; no frontend packages are required. Changes to the runtime command dependency closure require refreshed reviewed license evidence, rather than silently accepting a new module.

`make contract-test-setup` installs the exact hash-locked schema test dependencies in an ignored local virtual environment. `make check` then validates the manifest/validation-record schemas and synthetic negative/archive fixtures using that interpreter. This test engine is excluded from the service's runtime image; schema fixture checks do not establish package execution or sandbox safety.

Start with `make run` after supplying deployment-owned settings through the environment or a trusted secret facility. The program does not source `.env`; the portable infrastructure file and application credentials are separate. Configuration errors and startup logs redact credentials and private paths. SIGINT/SIGTERM drain HTTP connections with a bounded graceful shutdown.

| Setting | Purpose |
|---|---|
| `JUDGE_DATABASE_URL` | PostgreSQL runtime-role URL with explicit TLS policy. `sslmode=disable` is limited to loopback development. Production across a network requires certificate verification. Never log the URL or use migration/admin credentials for the service. |
| `JUDGE_PRIVATE_STORAGE_DIR` | Absolute clean path to Judge-owned private storage; no caller-selected paths or public artifact links. |
| `BACKEND_JUDGE_TOKEN` | Independent incoming Bearer token, at least 32 printable nonwhitespace bytes. |
| `JUDGE_BACKEND_TOKEN` | Independent outgoing Bearer token, at least 32 printable nonwhitespace bytes. |
| `JUDGE_LISTEN_ADDR` | IP literal and port; default `0.0.0.0:8082` on the private service network. Local smoke tests use loopback. |
| `JUDGE_MIGRATION_DATABASE_URL` | Separately scoped migration-role connection consumed only by `judge-migrate`, never the sandbox process. |

The callback target is fixed at `http://backend:8081/internal/v2/events/judge`; requests cannot supply a callback URL. Language templates, toolchains, tests, validators and checker commands are controlled by later versioned service configuration and immutable package manifests.

`GET /health` returns the exact raw V0.2 health DTO. Unimplemented dependency probes and workflows stay false. The current foundation does not advertise usable Judge/import/catalog workflows: a database ping alone cannot establish readiness. Later Issues wire measured storage/schema/toolchain/isolation probes and actual handlers. Native tests use explicit mocks and never execute submitted code or imported programs on the host. [Linux qualification](linux-sandbox.md) remains required for execution.
