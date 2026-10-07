# Problem detail servability profile

Refs [contract register Q-009](../contracts/open-questions.md#q-009--complete-problem-detail-servability),
[engineering resolution #2](https://github.com/STAR-Ability/code-startrack-judge/issues/2),
and [Backend consumer acceptance #23](https://github.com/STAR-Ability/code-startrack-judge/issues/23).
The owner delegated engineering resolutions on 2026-10-08; this records the
resulting Judge implementation policy and its acceptance evidence.

The owned HTTP encoder currently bounds every complete response to 32 MiB.
The published API's explicit 32 MiB wording applies to task results and callbacks;
it does not publish a separate ceiling for `PlatformProblemDetail`. The detail
contract requires complete Markdown and public samples, and package archive
safety permits files larger than this response ceiling. Archive safety alone
therefore cannot establish public detail servability. This implementation
profile accepts only versions whose complete detail can be encoded under the
existing HTTP ceiling. It does not amend the published contract or change its
limits, truncate content, or qualify consumer compatibility.

`internal/responsebudget/problem_detail.go` counts the complete
`ApiResponse<PlatformProblemDetail>` using the HTTP encoder's default JSON
escaping. It includes the statement's content/input/output, every sample,
title/tags/difficulty/limits/languages, and the selected immutable approval's
public SPDX ID, notice and source URL. It reserves the response request UUID,
19-digit problem and catalog IDs, the longest current status representation,
and the longest valid UTC RFC3339Nano timestamp. Later publication, withdrawal
or catalog growth cannot exhaust a budget accepted only against a shorter
current representation. The counter stops when the ceiling is exceeded and
does not allocate another content-sized serialized buffer. Encoder parity
tests must change with the DTO or encoding profile.

Import preparation stages the exact original and normalized archives first,
resolves the exact source-bound human approval, and applies the existing
structure and license gates. An approved package whose public detail exceeds
the profile is retained as `REJECTED`, failure stage `UNSUPPORTED`, diagnostic
`PACKAGE_UNSUPPORTED`, license status `VERIFIED`, and validation status `FAILED`.
It creates no problem/version, stages no normalized execution files and invokes
no technical validator. The accepted import job still polls with HTTP 200 and
preserves its structured history. An unapproved package first retains the
ordinary `LICENSE_REVIEW` outcome; this size policy does not bypass human review.

`CreateVersion` checks the same complete projection with the artifact's actual
immutable approval before version insertion or latest-pointer changes.
Metadata requests that would exceed the profile return the endpoint's existing
HTTP 400 `INVALID_ARGUMENT`, frozen under the management request identity.
Publication independently checks older immutable versions, including the
already-current no-op branch, before first-publication, catalog or current
pointer changes. It returns the existing HTTP 422 `PACKAGE_UNSUPPORTED`.
These checks run before writes because management operations commit bounded
deterministic failures; checking only the final response could commit partial
business state alongside a frozen failure.

Historical oversized facts are preserved unchanged. Their existing detail
response remains subject to the encoder ceiling; this guard prevents new
unservable versions and publication transitions, not a historical rewrite.
A future larger detail transport or profile requires reviewed contract/profile
evolution and actual Backend consumer acceptance before release. Issue #23
remains that consumer gate; these Judge tests do not close it.

`internal/responsebudget/problem_detail_test.go` compares the counter with the
actual Go JSON encoder across null/array and mixed escape vectors, the exact
ceiling, one-byte overflow, and future scalar growth. The real PostgreSQL
fixtures in `internal/imports/detail_budget_postgres_test.go` and
`internal/problems/detail_budget_postgres_test.go` use moderate raw inputs whose
escaped JSON crosses the real ceiling. They verify retained rights/unsupported
history and archive hashes after GC, no validation/registration on rejection,
complete supported HTTP detail through publication and withdrawal, rejected
metadata and historical publication with unchanged facts, and frozen failure
replay/conflicts. All schema guards remain enabled. These are synthetic
eligibility fixtures, not Linux execution or human rights qualification.

```sh
JUDGE_TEST_ADMIN_DSN_FILE="$PWD/.local/v02-postgres-admin.dsn" \
GOTOOLCHAIN=local .local/toolchains/go1.26.8/go/bin/go test -race \
  ./internal/responsebudget ./internal/imports ./internal/problems \
  -run 'TestProblemDetail|TestPostgresDetailBudget|TestPostgresOversizedEscapedDetail' \
  -count=1 -v
```

The full capacity runner separately retains its authored 32 MiB input plus
32 MiB answer case as an expected unsupported rejection and uses a separate
15 MiB input plus 15 MiB answer case for supported real validation. See
[full-size qualification gate #21](https://github.com/STAR-Ability/code-startrack-judge/issues/21). Full-size Linux evidence
and the repository's final `make check` remain separate acceptance records.

On 2026-10-08 the actual PostgreSQL/HTTP regression passed with Go 1.26.8
`-race` on macOS x86_64 against isolated PostgreSQL 17.10 (test 43.81 seconds,
package 45.691 seconds). The import retention regression passed without skips
(test 5.92 seconds, package 7.746 seconds). The encoder differential and
boundary tests passed with `-race` (package 6.470 seconds); the zero-allocation
check separately passed (package 2.322 seconds). Independent read-only review
found no blockers after correcting the contract-section citation. Its fresh
Go 1.26.8 `-race` replay passed all counter checks (package 5.229 seconds),
retained import rejection (test 5.19 seconds, package 6.977 seconds), and actual
PostgreSQL/HTTP management regression (test 40.25 seconds, package 42.757 seconds).
Scoped `go vet` and whitespace checks also passed. Final integrated checks are
recorded separately after they run.
