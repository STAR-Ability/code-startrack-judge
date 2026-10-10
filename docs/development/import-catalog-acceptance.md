# Import and catalog acceptance fixtures

Refs [#11](https://github.com/STAR-Ability/code-startrack-judge/issues/11),
[#12](https://github.com/STAR-Ability/code-startrack-judge/issues/12), and
[#13](https://github.com/STAR-Ability/code-startrack-judge/issues/13). The
[published API](../contracts/v0.2/api.md),
[database contract](../contracts/v0.2/database.md), and
[accepted clarifications](../contracts/v0.2/clarifications.md) govern these
fixtures. They supplement the [service acceptance suite](acceptance.md).

`internal/imports/partial_registration_postgres_test.go` uses actual PostgreSQL
and private storage to complete one approved synthetic package, expire its
worker lease, and resume only the remaining unapproved package. The old fence
cannot commit. The final job is `PARTIAL`, retains the first immutable `DRAFT`
and both outcomes, replays during readiness loss, and leaves the public catalog
unchanged. Garbage collection preserves the validated and rejected objects.
Source acquisition and validation reports are inert test substitutes; their
synthetic approval and qualification belong only to the disposable database.

`internal/problems/public_list_acceptance_postgres_test.go` exercises real SQL
with two published immutable versions. Fifteen cases cover trimmed title and
number search, literal percent/underscore characters, exact tags, inclusive
rating boundaries, exclusion and explicit JSON null of unrated difficulty,
combined filters, numeric ID ordering when timestamps tie, and first/final/
out-of-range pages. A separate timestamp check proves timestamp precedence;
withdrawal retains its last published metadata. Each query verifies its total,
page metadata and catalog identity. The repository uses the same filter SQL for
count and rows within one read-only `REPEATABLE READ` transaction.

`internal/contract/catalog_consumer_fixture_test.go` and its three authored JSON
vectors document the independent Backend consumption contract. Actual contract
DTO decoding rejects invalid pages. The reference consumer stages all pages,
checks snapshot/catalog identity, passes each opaque cursor unchanged with the
fixed limit, and publishes one complete immutable map. Readers retain the old
cache while collection is incomplete; transport/schema/status failures, mixed
snapshots, duplicate identities, repeated cursors and expiration cannot replace
it. A 410 starts a fresh cursor-free whole fetch. Returned metadata is detached
from stored data, withdrawn summaries remain tombstones, and a complete empty
snapshot clears the Judge catalog. Shared identity vectors preserve
`sourceOwner=judge-problem-service`, source, platform and problem number; equal
PLATFORM and EXTERNAL numbers remain distinct. Judge page vectors contain only
PLATFORM/startrack entries. This test-only reference owns no Backend product
cache and performs no network or execution qualification.

Run the PostgreSQL cases with a private administrator DSN filename; without it,
these tests skip and provide no actual database acceptance evidence:

```sh
JUDGE_TEST_ADMIN_DSN_FILE="$PWD/.local/v02-postgres-admin.dsn" \
GOTOOLCHAIN=local .local/toolchains/go1.26.8/go/bin/go test -race \
  ./internal/imports ./internal/problems \
  -run 'TestPostgresMixedImportRecoversValidatedDraftAndFinishesPartial|TestPostgresPublicListFiltersSortPaginationAndNullDifficulty' \
  -count=1 -v

GOTOOLCHAIN=local .local/toolchains/go1.26.8/go/bin/go test -race \
  ./internal/contract -run TestCatalogConsumerFixture -count=1 -v
```

On 2026-10-08 both tests passed with Go 1.26.8 `-race`, driven from macOS x86_64
against the isolated PostgreSQL 17.10 development environment. The mixed
import took 3.28 seconds and the query test took 1.98 seconds. These tests prove
workflow and query behavior, not human rights coverage or Linux execution.
Runtime enabling still requires [Linux qualification](linux-sandbox.md), actual
validation evidence and final image acceptance.

The six consumer tests, including eleven failed-refresh cases, also passed
Go 1.26.8 `-race` on that host (package 1.671 seconds). An independent HTTP
reviewer found no blocking findings in the three fixture sets and separately
replayed the mixed import, fifteen query cases, and six consumer tests with the
private PostgreSQL DSN file where needed.
