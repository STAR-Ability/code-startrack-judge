# Offline ADMIN license review

The V0.2 final human review follows [Q-003](../contracts/v0.2/clarifications.md#q-003-final-human-approval-and-rejected-package-retention). Import requests, automatic suggestions and repository-root MIT discovery cannot approve a package. Backend still owns user ADMIN authorization and problem publication. This trusted local operation records license approval; it does not publish a problem.

An operator with root authority performs the human review through `judge-admin license-review`. The command accepts no reviewer argument or environment credential. Both the approval receipt and operator configuration must be regular root-owned files with mode0600 or stricter. Their ancestors must be root-owned, without group/world write permission or symlinks. The configured private-storage directory remains owned by the storage service account with mode0700; its ancestors must be root-owned and cannot redirect it. Give this command only to named ADMIN operators through the host's existing audited privilege mechanism; do not expose it through the service, worker, HTTP API, or submission sandbox. On macOS use physical paths such as `/private/etc`, because `/etc` is a symlink.

Provision a separate `judge_license_reviewer` login with [grant-license-reviewer.sql](../../scripts/grant-license-reviewer.sql). Supply `JUDGE_LICENSE_REVIEW_PASSWORD`, `JUDGE_RUNTIME_PASSWORD` and `JUDGE_MIGRATION_PASSWORD` through the operator's protected environment; the script requires an independent reviewer credential of at least32 characters and retains an existing role's password. It may read retained evidence/object metadata and insert immutable license evidence. It cannot publish, mutate tasks or catalog, change schema/migration history, or modify existing evidence. The runtime login's column-level evidence INSERT grant excludes `reviewed_by` and `reviewed_at`; the VERIFIED constraint therefore blocks approval by an automatic import worker. Protect the reviewer credential separately from runtime credentials. The command refuses privileged database roles and requires the exact reviewer login. Before private reads and writes it also checks the effective session policy that suppresses statements, parameters, duration and transaction samples, error details and optional pgAudit session/object auditing. An external SQL proxy needs the deployment's separately reviewed redaction policy.

The root-owned configuration fixes the accountable ADMIN identity:

```json
{
  "databaseUrl": "postgres://judge_license_reviewer:REPLACE_WITH_SECRET@localhost:5432/startrack_judge?sslmode=disable",
  "privateStorageRoot": "/var/lib/code-startrack/private",
  "reviewerId": "ADMIN:accountable-operator-identity",
  "authority": "ADMIN"
}
```

Use TLS `verify-full` for a remote database. Keep real configuration and receipts out of Git. The identity must name the actual reviewing administrator; a shared service/import-policy label is insufficient. Operator handover creates a new root-owned configuration with the next accountable identity and retains the former audit record.

Review the original package and all third-party material at the exact retained commit. Record the license's actual coverage, attribution obligations, source notices and third-party examination. If a repository-root license is inherited, explain why it covers this package and which content has separate rights. Missing files or unresolved rights remain unapproved. A valid non-SPDX license may use null `spdxId` only with complete notice and review evidence.

The private approval receipt uses a new `evidenceId` and the rejected package's retained `rejectedEvidenceId`; it binds the exact repository, sourceRevision, packagePath, sourceSha256 and nullable normalizedSha256. `previousEvidenceId` may name a same-source predecessor, or null to use the retained automatic observation. Include `scope` (`PACKAGE` or `REPOSITORY_INHERITED`), nullable `spdxId`, `notice`, the fixed source URL `https://github.com/oj-lab/problem-packages/tree/<commit>/<packagePath>`, and nonempty `coverage`, `thirdPartyReview`, and `approvalEvidence` explanations. `licenseFiles` is a nonempty list of `{path,sha256,spdxId}`. Names are canonical relative paths, checksums are lowercase SHA-256, and license contents must be nonempty UTF-8.

For package license files, the command reads and checks the exact bytes in the retained original TAR. A parent repository license need not be a package archive member: include its exact fixed-commit text in `repositoryLicenseTexts`, a map from its listed relative path to text. This is allowed only for `REPOSITORY_INHERITED`. The human reviewer attests the fixed-commit origin and applicability, while the command verifies the supplied text's listed checksum and retains the full text in immutable private evidence. No source execution or extraction occurs during review. The command also verifies original and available normalized archive object checksums.

```sh
sudo judge-admin license-review \
  -config /etc/code-startrack/license-review/operator.json \
  -review /etc/code-startrack/license-review/approved-package.json
```

A successful command prints only the evidence ID and VERIFIED status. Approval is append-only, records database review time, and preserves the automatic predecessor. Repeating the same evidence ID and receipt is harmless; changed receipt content under that ID conflicts. Keep the approved receipt with the operator audit records. Re-import with a new requestId to create a validated DRAFT bound to the new evidence. Publish it separately through Backend's ADMIN management operation. A later rights change requires new evidence, artifact and version; never rewrite a historical license or reuse a prior approval for another source tuple.

Run `scripts/test-license-review-grants.py --context <docker-context> --image sha256:<exact-local-image-id>` for the disposable PostgreSQL qualification. It applies the exact current forward SQL and operator scripts, proves fresh/repeated grants and permission denials, refuses five unsafe existing-role profiles, and checks credentials, runtime evidence and successful/failed receipt canaries in SQL logs while server statement, duration and transaction sampling are enabled. It owns and removes its own container and never resets a supplied database. This harness does not load pgAudit; deployments using it need separate extension qualification. Local unit/PostgreSQL workflow tests and this Linux database check remain separate from Linux sandbox qualification. License review itself does not establish that validators/reference solutions passed or that sandbox execution is qualified.
