// SPDX-License-Identifier: Apache-2.0

package problems

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/httpapi"
	persistence "github.com/STAR-Ability/code-startrack-judge/internal/persistence/problems"
)

// This is actual PostgreSQL and the production HTTP encoder with synthetic
// immutable eligibility evidence. It provides no execution or human review proof.
func TestPostgresDetailBudgetPreventsUnservableVersionAndPublication(t *testing.T) {
	db := isolatedDB(t)
	ctx := context.Background()
	repo := persistence.New(db, nil)
	ready := true
	service := New(repo, Options{FreshReady: func(context.Context) bool { return ready }})
	handler, err := httpapi.New(httpapi.Options{BackendJudgeToken: strings.Repeat("e", 64), Register: func(mux *http.ServeMux) {
		httpapi.RegisterRoutes(mux, httpapi.Routes{CurrentProblem: service.Current, ProblemVersion: service.Version, MetadataVersion: service.Metadata, Publish: service.Publish, Withdraw: service.Withdraw})
	}})
	if err != nil {
		t.Fatal(err)
	}
	base := contract.UUID("00000000-0000-0000-0000-000000000011")
	detail, err := service.Version(ctx, "1", base)
	if err != nil {
		t.Fatal(err)
	}
	input, output := "Input <>& \"\\\n\u2028中", "Output <>& \"\\\n\u2029🙂"
	detail.Statement = contract.Statement{Format: "MARKDOWN", Input: &input, Output: &output}
	detail.Samples = []contract.Sample{{Input: input, Output: output}}
	// Derive a near-boundary moderate raw payload from the actual encoder,
	// reserving the profile's longest future scalar representations independently.
	prospective := detail
	prospective.ProblemRef.ProblemID, prospective.CatalogVersion = "9223372036854775807", "9223372036854775807"
	prospective.Status, prospective.UpdatedAt = contract.ProblemWithdrawn, "9999-12-31T23:59:59.999999999Z"
	baseline, err := json.Marshal(contract.ApiResponse[contract.PlatformProblemDetail]{Data: prospective, RequestID: uuid(t)})
	if err != nil {
		t.Fatal(err)
	}
	remaining := int(contract.MaxResultBytes) - len(baseline) - 1024
	content := strings.Repeat("<", remaining/6) + strings.Repeat("a", remaining%6)
	var supported persistence.Version
	var spec persistence.VersionSpec
	err = repo.WithTx(ctx, nil, func(tx *persistence.Tx) error {
		original, err := tx.LoadVersion("1", base)
		if err != nil {
			return err
		}
		spec = original.Spec
		spec.StatementContent, spec.StatementInput, spec.StatementOutput, spec.Samples = content, &input, &output, detail.Samples
		supported, err = tx.CreateVersion(spec)
		return err
	})
	if err != nil {
		t.Fatal("supported complete projection could not be registered", err)
	}
	assertDetail := func(response *httptest.ResponseRecorder, wantStatus contract.PlatformProblemStatus) {
		t.Helper()
		if response.Code != http.StatusOK || int64(response.Body.Len()) > contract.MaxResultBytes {
			t.Fatalf("complete supported detail returned %d, %d bytes", response.Code, response.Body.Len())
		}
		var envelope contract.ApiResponse[contract.PlatformProblemDetail]
		if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
			t.Fatal("supported detail could not be decoded")
		}
		if envelope.Data.Status != wantStatus || envelope.Data.Statement.Content != content || envelope.Data.Statement.Input == nil || *envelope.Data.Statement.Input != input || envelope.Data.Statement.Output == nil || *envelope.Data.Statement.Output != output || !reflect.DeepEqual(envelope.Data.Samples, detail.Samples) || !reflect.DeepEqual(envelope.Data.License, detail.License) {
			t.Fatal("servability changed or omitted complete public content")
		}
	}
	versionPath := "/internal/v2/problems/1/versions/" + string(supported.ID)
	assertDetail(budgetHTTP(t, handler, http.MethodGet, versionPath, nil), contract.ProblemDraft)

	before := budgetFacts(t, db)
	oversized := spec
	oversized.StatementContent = strings.Repeat("<", 6<<20) // 6 MiB raw, 36 MiB JSON.
	err = repo.WithTx(ctx, nil, func(tx *persistence.Tx) error { _, err := tx.CreateVersion(oversized); return err })
	if !errors.Is(err, persistence.ErrDetailTooLarge) || budgetFacts(t, db) != before {
		t.Fatal("CreateVersion accepted overflow or changed immutable/latest state")
	}

	rating := contract.SafeInt(2000)
	metadata := contract.MetadataVersionRequest{RequestID: uuid(t), BaseProblemVersionID: supported.ID, Difficulty: &rating, DifficultyScale: contract.DifficultyPlatform}
	for i := range 32 {
		metadata.Tags = append(metadata.Tags, fmt.Sprintf("%02d", i)+strings.Repeat("<", 126))
	}
	if metadata.Validate() != nil {
		t.Fatal("metadata regression must be a valid request")
	}
	for attempt := 0; attempt < 2; attempt++ {
		if attempt == 1 {
			ready = false
		}
		response := budgetHTTP(t, handler, http.MethodPost, "/internal/v2/problems/1/metadata-versions", metadata)
		budgetError(t, response, http.StatusBadRequest, "INVALID_ARGUMENT")
		if budgetFacts(t, db) != before {
			t.Fatal("metadata overflow changed version, pointers, catalog or timestamps")
		}
	}
	metadata.Tags[0] = "changed"
	budgetError(t, budgetHTTP(t, handler, http.MethodPost, "/internal/v2/problems/1/metadata-versions", metadata), http.StatusConflict, "IDEMPOTENCY_CONFLICT")
	ready = true
	var frozen int
	if db.QueryRow(`SELECT count(*) FROM judge.operation_requests WHERE operation='METADATA_VERSION' AND request_id=$1 AND status='FAILED' AND result IS NULL AND error->>'code'='INVALID_ARGUMENT'`, metadata.RequestID).Scan(&frozen) != nil || frozen != 1 {
		t.Fatal("metadata overflow did not freeze one safe failure")
	}

	assertDetail(budgetHTTP(t, handler, http.MethodPost, "/internal/v2/problems/1/publish", contract.PublishRequest{RequestID: uuid(t), ProblemVersionID: supported.ID}), contract.ProblemPublished)
	withdraw := budgetHTTP(t, handler, http.MethodPost, "/internal/v2/problems/1/withdraw", contract.WithdrawRequest{RequestID: uuid(t), Reason: "Synthetic retained history"})
	if withdraw.Code != http.StatusOK {
		t.Fatal("supported publication could not be withdrawn")
	}
	assertDetail(budgetHTTP(t, handler, http.MethodGet, versionPath, nil), contract.ProblemWithdrawn)

	// Seed a historical oversized row directly in the disposable admin fixture;
	// all schema guards stay enabled and ordinary workflow never rewrites it.
	legacy := uuid(t)
	if _, err := db.Exec(`INSERT INTO judge.problem_versions SELECT
 (jsonb_populate_record(NULL::judge.problem_versions,to_jsonb(v)||jsonb_build_object('id',$1::text,'version_number',3,'statement_content',$2::text,'first_published_at',NULL))).*
 FROM judge.problem_versions v WHERE id=$3`, legacy, oversized.StatementContent, supported.ID); err != nil {
		t.Fatal("cannot seed immutable historical overflow")
	}
	publication := contract.PublishRequest{RequestID: uuid(t), ProblemVersionID: legacy}
	before = budgetFacts(t, db)
	for attempt := 0; attempt < 2; attempt++ {
		if attempt == 1 {
			ready = false
		}
		budgetError(t, budgetHTTP(t, handler, http.MethodPost, "/internal/v2/problems/1/publish", publication), http.StatusUnprocessableEntity, "PACKAGE_UNSUPPORTED")
		if budgetFacts(t, db) != before {
			t.Fatal("historical overflow advanced catalog, publication or pointers")
		}
	}
	ready = true
	publication.ProblemVersionID = supported.ID
	budgetError(t, budgetHTTP(t, handler, http.MethodPost, "/internal/v2/problems/1/publish", publication), http.StatusConflict, "IDEMPOTENCY_CONFLICT")
	// Simulate an already published historical overflow, then exercise the
	// no-op branch with a new request. The guard must still precede any writes.
	if _, err := db.Exec(`BEGIN;
 UPDATE judge.problem_versions SET first_published_at=now() WHERE id='` + string(legacy) + `';
 UPDATE judge.platform_problems SET status='PUBLISHED',current_version_id='` + string(legacy) + `',public_updated_at=clock_timestamp(),withdrawn_at=NULL,withdrawal_reason=NULL WHERE id=1;
 UPDATE judge.catalog_state SET catalog_version=catalog_version+1;
 COMMIT`); err != nil {
		t.Fatal("cannot seed published historical overflow with guards enabled")
	}
	before = budgetFacts(t, db)
	budgetError(t, budgetHTTP(t, handler, http.MethodPost, "/internal/v2/problems/1/publish", contract.PublishRequest{RequestID: uuid(t), ProblemVersionID: legacy}), http.StatusUnprocessableEntity, "PACKAGE_UNSUPPORTED")
	if budgetFacts(t, db) != before {
		t.Fatal("no-op overflow rewrote historical publication facts")
	}
}

func budgetHTTP(t *testing.T, handler http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	requestID := uuid(t)
	if request, ok := body.(interface{ BodyRequestID() contract.UUID }); ok {
		requestID = request.BodyRequestID()
	}
	var raw []byte
	var err error
	if body != nil {
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatal("budget request cannot be encoded")
		}
	}
	request := httptest.NewRequest(method, path, strings.NewReader(string(raw)))
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("e", 64))
	request.Header.Set("X-Request-Id", string(requestID))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func budgetError(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	var envelope contract.ApiError
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil || response.Code != status || envelope.Error.Code != code || len(envelope.Error.Details) != 0 {
		t.Fatalf("budget rejection returned %d, want %d/%s", response.Code, status, code)
	}
}

func budgetFacts(t *testing.T, db *sql.DB) string {
	t.Helper()
	var snapshot string
	err := db.QueryRow(`SELECT jsonb_build_object(
 'problems',(SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM judge.platform_problems p),
 'versions',(SELECT jsonb_agg(jsonb_build_object('id',id,'digest',md5(to_jsonb(v)::text)) ORDER BY id) FROM judge.problem_versions v),
 'artifacts',(SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM judge.package_artifacts a),
 'licenses',(SELECT jsonb_agg(to_jsonb(l) ORDER BY id) FROM judge.license_evidence l),
 'catalog',(SELECT to_jsonb(c) FROM judge.catalog_state c))::text`).Scan(&snapshot)
	if err != nil {
		t.Fatal("cannot inspect complete immutable/publication facts")
	}
	return snapshot
}
