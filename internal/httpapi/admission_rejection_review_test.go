// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/STAR-Ability/code-startrack-judge/internal/admission"
	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	persistencetasks "github.com/STAR-Ability/code-startrack-judge/internal/persistence/tasks"
	"github.com/STAR-Ability/code-startrack-judge/internal/storage"
	"github.com/STAR-Ability/code-startrack-judge/internal/testutil/judgetask"
	"github.com/STAR-Ability/code-startrack-judge/internal/testutil/postgres"
	"github.com/jackc/pgx/v5/pgconn"
)

const rejectionBetaVersion = "00000000-0000-0000-0000-000000000111"

// These fixtures prove HTTP/admission/database rejection, not Linux execution.
// All schema and immutable-evidence guards remain enabled.
func TestReviewPostgresAdmissionRejectionsLeaveNoTaskOrEvent(t *testing.T) {
	tests := []struct {
		name   string
		status int
		code   string
		setup  func(*testing.T, *sql.DB, *contract.JudgeTaskRequest)
		wire   func([]byte) []byte
	}{
		{"missing problem", 404, "PROBLEM_NOT_FOUND", func(_ *testing.T, _ *sql.DB, r *contract.JudgeTaskRequest) {
			r.ProblemRef.ProblemID = "999"
		}, nil},
		{"withdrawn", 409, "PROBLEM_NOT_SUBMITTABLE", func(t *testing.T, db *sql.DB, _ *contract.JudgeTaskRequest) {
			rejectionExec(t, db, `BEGIN; UPDATE judge.platform_problems SET status='WITHDRAWN',withdrawn_at=now(),withdrawal_reason='synthetic review',public_updated_at=clock_timestamp() WHERE id=1; UPDATE judge.catalog_state SET catalog_version=catalog_version+1; COMMIT`)
		}, nil},
		{"not current", 409, "PROBLEM_VERSION_CONFLICT", func(t *testing.T, db *sql.DB, r *contract.JudgeTaskRequest) {
			rejectionExec(t, db, `INSERT INTO judge.problem_versions SELECT (jsonb_populate_record(NULL::judge.problem_versions,to_jsonb(v)||jsonb_build_object('id',$1::text,'version_number',2,'first_published_at',NULL))).* FROM judge.problem_versions v WHERE problem_id=1`, rejectionBetaVersion)
			v := contract.UUID(rejectionBetaVersion)
			r.ProblemRef.ProblemVersionID = &v
		}, nil},
		{"cross problem published version", 409, "PROBLEM_VERSION_CONFLICT", func(t *testing.T, db *sql.DB, r *contract.JudgeTaskRequest) {
			rejectionBetaGraph(t, db, "VERIFIED", true, false, true, false)
			v := contract.UUID(rejectionBetaVersion)
			r.ProblemRef.ProblemVersionID = &v
		}, nil},
		{"unlicensed registration denied and draft rejected", 409, "PROBLEM_NOT_SUBMITTABLE", func(t *testing.T, db *sql.DB, r *contract.JudgeTaskRequest) {
			before := rejectionGraph(t, db)
			rejectionBetaGraph(t, db, "MISSING", true, false, true, true)
			if rejectionGraph(t, db) != before {
				t.Fatal("denied unlicensed registration changed original evidence")
			}
			r.ProblemRef.ProblemID = "2"
		}, nil},
		{"unvalidated draft cannot publish or admit", 409, "PROBLEM_NOT_SUBMITTABLE", func(t *testing.T, db *sql.DB, r *contract.JudgeTaskRequest) {
			rejectionBetaGraph(t, db, "VERIFIED", false, false, false, false)
			before := rejectionGraph(t, db)
			tx, err := db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal("cannot start synthetic publication")
			}
			defer tx.Rollback()
			_, err = tx.Exec(`UPDATE judge.problem_versions SET first_published_at=now() WHERE id=$1`, rejectionBetaVersion)
			if err == nil {
				_, err = tx.Exec(`UPDATE judge.platform_problems SET status='PUBLISHED',current_version_id=$1,public_updated_at=now() WHERE id=2`, rejectionBetaVersion)
			}
			if err == nil {
				err = tx.Commit()
			}
			rejectionConstraint(t, err)
			if rejectionGraph(t, db) != before {
				t.Fatal("denied publication changed draft evidence")
			}
			v := contract.UUID(rejectionBetaVersion)
			r.ProblemRef.ProblemID, r.ProblemRef.ProblemVersionID = "2", &v
		}, nil},
		{"qualified artifact unsupported checker", 503, "JUDGE_UNAVAILABLE", func(t *testing.T, db *sql.DB, r *contract.JudgeTaskRequest) {
			rejectionBetaGraph(t, db, "VERIFIED", true, true, true, false)
			v := contract.UUID(rejectionBetaVersion)
			r.ProblemRef.ProblemID, r.ProblemRef.ProblemVersionID = "2", &v
		}, nil},
		{"unsupported language", 409, "LANGUAGE_NOT_SUPPORTED", func(_ *testing.T, _ *sql.DB, r *contract.JudgeTaskRequest) {
			r.LanguageID = "python3"
		}, nil},
		{"source checksum", 400, "INVALID_ARGUMENT", func(_ *testing.T, _ *sql.DB, r *contract.JudgeTaskRequest) {
			r.SourceSHA256 = strings.Repeat("0", 64)
		}, nil},
		{"source byte limit", 413, "SOURCE_TOO_LARGE", func(t *testing.T, _ *sql.DB, r *contract.JudgeTaskRequest) {
			r.SourceCode = strings.Repeat("x", contract.MaxSourceBytes+1)
			var err error
			r.SourceSHA256, err = canonical.HashSource(r.SourceCode)
			if err != nil {
				t.Fatal("synthetic source checksum unavailable")
			}
		}, nil},
		{"invalid source Unicode", 400, "INVALID_ARGUMENT", nil, func(b []byte) []byte {
			return []byte(strings.Replace(string(b), `"sourceCode":"int main(){}\r\n"`, `"sourceCode":"\ud800"`, 1))
		}},
		{"source request byte limit", 413, "INPUT_TOO_LARGE", nil, func(b []byte) []byte {
			return append([]byte(strings.Repeat(" ", int(contract.MaxJudgeRequestBytes)+1)), b...)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			database := postgres.New(t)
			judgetask.Seed(t, database.Admin, 1)
			store, err := storage.New(filepath.Join(t.TempDir(), "private"))
			if err != nil {
				t.Fatal("private fixture store unavailable")
			}
			t.Cleanup(func() { store.Close() })
			registry, err := storage.NewRegistry(database.Runtime, store)
			if err != nil {
				t.Fatal("private fixture registry unavailable")
			}
			repository, err := persistencetasks.New(database.Runtime, registry)
			if err != nil {
				t.Fatal("task fixture repository unavailable")
			}
			service, err := admission.New(admission.Options{Repository: repository, Sources: registry, Runtime: func(context.Context) (admission.RuntimeIdentity, bool, error) {
				return judgetask.Identity(), true, nil
			}})
			if err != nil {
				t.Fatal("admission fixture unavailable")
			}
			v := contract.UUID("00000000-0000-0000-0000-000000000011")
			source := "int main(){}\r\n"
			sha, _ := canonical.HashSource(source)
			r := contract.JudgeTaskRequest{RequestID: contract.UUID(testRequestID), SubmissionID: "100", ProblemRef: contract.ProblemRef{Source: contract.SourcePlatform, Platform: contract.PlatformStartrack, ProblemID: "1", ProblemVersionID: &v}, LanguageID: "cpp17", SourceCode: source, SourceSHA256: sha}
			if test.setup != nil {
				test.setup(t, database.Admin, &r)
			}
			before := rejectionGraph(t, database.Admin)
			raw, err := json.Marshal(r)
			if err != nil {
				t.Fatal("request fixture unavailable")
			}
			if test.wire != nil {
				raw = test.wire(raw)
			}
			response := httptest.NewRecorder()
			judgeRoutes(t, service).ServeHTTP(response, businessRequest(http.MethodPost, "/internal/v2/judge-tasks", string(raw)))
			if response.Code != test.status || responseCode(t, response) != test.code {
				t.Fatalf("rejection status/code = %d/%s, want %d/%s", response.Code, responseCode(t, response), test.status, test.code)
			}
			var count int
			if err := database.Admin.QueryRow(`SELECT (SELECT count(*) FROM judge.judge_tasks)+(SELECT count(*) FROM judge.judge_results)+(SELECT count(*) FROM judge.judge_case_results)+(SELECT count(*) FROM judge.callback_outbox)+(SELECT count(*) FROM judge.private_object_references WHERE owner_type='TASK')+(SELECT count(*) FROM judge.private_object_stages WHERE task_id IS NOT NULL)`).Scan(&count); err != nil || count != 0 {
				t.Fatal("rejection created task/result/event or retained a task source pin")
			}
			if _, found, err := repository.FindByRequest(context.Background(), r.RequestID); err != nil || found {
				t.Fatal("rejection reserved request identity")
			}
			if _, found, err := repository.FindBySubmission(context.Background(), r.SubmissionID); err != nil || found {
				t.Fatal("rejection reserved submission identity")
			}
			if rejectionGraph(t, database.Admin) != before {
				t.Fatal("admission rejection mutated original problem/package/license facts")
			}
			for _, private := range []string{source, "private/", "sourceSha256", "sourceCode", "SQL", "sha256:"} {
				if strings.Contains(response.Body.String(), private) {
					t.Fatal("rejection disclosed private execution input")
				}
			}
		})
	}
}

func rejectionExec(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatal("synthetic rejection setup failed")
	}
}

func rejectionConstraint(t *testing.T, err error) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Fatal("unqualified evidence was not rejected by its schema constraint")
	}
}

func rejectionGraph(t *testing.T, db *sql.DB) string {
	t.Helper()
	var graph string
	err := db.QueryRow(`SELECT jsonb_build_object(
 'problems',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM judge.platform_problems x),
 'versions',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM judge.problem_versions x),
 'artifacts',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM judge.package_artifacts x),
 'licenses',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM judge.license_evidence x),
 'sources',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM judge.package_source_identities x),
 'contents',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM judge.package_content_identities x),
 'validation',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM judge.package_validation_runs x),
 'tests',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM judge.problem_test_cases x),
 'references',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM judge.reference_solutions x),
 'languages',(SELECT jsonb_agg(to_jsonb(x) ORDER BY language_id,config_version) FROM judge.judge_language_configs x),
 'catalog',(SELECT jsonb_agg(to_jsonb(x) ORDER BY singleton_id) FROM judge.catalog_state x))::text`).Scan(&graph)
	if err != nil {
		t.Fatal("original graph inspection failed")
	}
	return graph
}

// Clone a complete synthetic beta graph before any admission. This preserves the
// alpha graph and lets the actual constraints reject unlicensed/unvalidated data.
func rejectionBetaGraph(t *testing.T, db *sql.DB, license string, qualified, badChecker, publish, denied bool) {
	t.Helper()
	if license != "VERIFIED" && license != "MISSING" {
		t.Fatal("unexpected fixed synthetic license status")
	}
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal("cannot start beta graph fixture")
	}
	defer tx.Rollback()
	query := `
 INSERT INTO judge.license_evidence SELECT (jsonb_populate_record(NULL::judge.license_evidence,to_jsonb(x)||jsonb_build_object('id','00000000-0000-0000-0000-000000000101','package_path','problems/beta','status',$1::text))).* FROM judge.license_evidence x WHERE id='00000000-0000-0000-0000-000000000001';
 INSERT INTO judge.package_source_identities SELECT (jsonb_populate_record(NULL::judge.package_source_identities,to_jsonb(x)||jsonb_build_object('id','00000000-0000-0000-0000-000000000102','package_path','problems/beta'))).* FROM judge.package_source_identities x WHERE id='00000000-0000-0000-0000-000000000002';
 INSERT INTO judge.package_content_identities SELECT (jsonb_populate_record(NULL::judge.package_content_identities,to_jsonb(x)||jsonb_build_object('id','00000000-0000-0000-0000-000000000103','source_identity_id','00000000-0000-0000-0000-000000000102'))).* FROM judge.package_content_identities x WHERE id='00000000-0000-0000-0000-000000000003';
 INSERT INTO judge.package_artifacts SELECT (jsonb_populate_record(NULL::judge.package_artifacts,to_jsonb(x)||jsonb_build_object('id','00000000-0000-0000-0000-000000000110','problem_id',2,'content_identity_id','00000000-0000-0000-0000-000000000103','package_path','problems/beta','license_evidence_id','00000000-0000-0000-0000-000000000101','validation_run_id',CASE WHEN $2 THEN '00000000-0000-0000-0000-000000000104' ELSE NULL END))).* FROM judge.package_artifacts x WHERE id='00000000-0000-0000-0000-000000000010';
 INSERT INTO judge.package_validation_runs SELECT (jsonb_populate_record(NULL::judge.package_validation_runs,to_jsonb(x)||jsonb_build_object('id','00000000-0000-0000-0000-000000000104','package_artifact_id','00000000-0000-0000-0000-000000000110'))).* FROM judge.package_validation_runs x WHERE id='00000000-0000-0000-0000-000000000004' AND $2;
 INSERT INTO judge.problem_test_cases SELECT (jsonb_populate_record(NULL::judge.problem_test_cases,to_jsonb(x)||jsonb_build_object('id','00000000-0000-0000-0000-000000000120','package_artifact_id','00000000-0000-0000-0000-000000000110'))).* FROM judge.problem_test_cases x WHERE package_artifact_id='00000000-0000-0000-0000-000000000010';
 INSERT INTO judge.reference_solutions SELECT (jsonb_populate_record(NULL::judge.reference_solutions,to_jsonb(x)||jsonb_build_object('id','00000000-0000-0000-0000-000000000121','package_artifact_id','00000000-0000-0000-0000-000000000110'))).* FROM judge.reference_solutions x WHERE package_artifact_id='00000000-0000-0000-0000-000000000010';
 INSERT INTO judge.problem_versions SELECT (jsonb_populate_record(NULL::judge.problem_versions,to_jsonb(x)||jsonb_build_object('id','00000000-0000-0000-0000-000000000111','problem_id',2,'package_artifact_id','00000000-0000-0000-0000-000000000110','first_published_at',CASE WHEN $4 THEN now() ELSE NULL END,'checker_config',CASE WHEN $3 THEN jsonb_set(x.checker_config,'{profile}','"unsupported-review-profile"') ELSE x.checker_config END))).* FROM judge.problem_versions x WHERE id='00000000-0000-0000-0000-000000000011';
 UPDATE judge.platform_problems SET latest_version_id='00000000-0000-0000-0000-000000000111',status=CASE WHEN $4 THEN 'PUBLISHED' ELSE 'DRAFT' END,current_version_id=CASE WHEN $4 THEN '00000000-0000-0000-0000-000000000111'::uuid ELSE NULL END,public_updated_at=CASE WHEN $4 THEN now() ELSE NULL END WHERE id=2;
 UPDATE judge.catalog_state SET catalog_version=catalog_version+1 WHERE $4;
 `
	// No caller-controlled values enter this SQL. Fixed enum/bool replacements
	// permit one simple-protocol batch while the explicit transaction owns commit.
	query = strings.NewReplacer("$1::text", "'"+license+"'::text", "$2", strconv.FormatBool(qualified), "$3", strconv.FormatBool(badChecker), "$4", strconv.FormatBool(publish)).Replace(query)
	_, err = tx.Exec(query)
	if err == nil {
		err = tx.Commit()
	}
	if denied {
		rejectionConstraint(t, err)
		return
	}
	if err != nil {
		t.Fatal("complete synthetic beta graph failed to register")
	}
}
