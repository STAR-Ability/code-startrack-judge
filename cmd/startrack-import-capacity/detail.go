// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/httpapi"
	problemstore "github.com/STAR-Ability/code-startrack-judge/internal/persistence/problems"
	"github.com/STAR-Ability/code-startrack-judge/internal/problems"
	"github.com/STAR-Ability/code-startrack-judge/internal/testutil/importcapacity"
)

// This read-only probe uses the actual Version service and authenticated HTTP
// route/encoder in process. Its generated synthetic token is never an external
// Backend credential. No listener, publication route or network request exists.
func measureDetail(ctx context.Context, repository *problemstore.Repository, current *caseReport) error {
	service := problems.New(repository, problems.Options{})
	detail, err := service.Version(ctx, contract.ID(current.ProblemID), contract.UUID(current.ProblemVersionID))
	if err != nil {
		return errQualification
	}
	for _, sample := range detail.Samples {
		current.StoredSampleBytes += int64(len(sample.Input) + len(sample.Output))
	}
	if current.Name != importcapacity.MemberPayload && current.Name != importcapacity.SampleSupported || current.Name == importcapacity.SampleSupported && (len(detail.Samples) != 2 || current.StoredSampleBytes != 2*importcapacity.SupportedSampleBytes+6) || current.Name == importcapacity.MemberPayload && (len(detail.Samples) != 1 || current.StoredSampleBytes != 6) {
		return errQualification
	}
	id, err := contract.NewUUID()
	if err != nil {
		return errQualification
	}
	encoded, err := json.Marshal(contract.ApiResponse[contract.PlatformProblemDetail]{Data: detail, RequestID: id})
	if err != nil || contract.ValidateValue(detail) != nil {
		return errQualification
	}
	current.DetailEnvelopeBytes = int64(len(encoded))
	// Retain no second DTO byte buffer while the real handler loads the same view.
	encoded = nil
	detail = contract.PlatformProblemDetail{}
	token := string(id) + strings.Repeat("Q", 32)
	handler, err := httpapi.New(httpapi.Options{BackendJudgeToken: token, Register: func(mux *http.ServeMux) {
		httpapi.RegisterRoutes(mux, httpapi.Routes{ProblemVersion: service.Version})
	}})
	if err != nil {
		return errQualification
	}
	request := httptest.NewRequestWithContext(ctx, http.MethodGet, "http://capacity.invalid/internal/v2/problems/"+current.ProblemID+"/versions/"+current.ProblemVersionID, nil)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Request-Id", string(id))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	current.DetailHTTPStatus, current.DetailResponseBytes = response.Code, response.Body.Len()
	if current.DetailEnvelopeBytes > contract.MaxResultBytes || response.Code != http.StatusOK || int64(response.Body.Len()) != current.DetailEnvelopeBytes {
		return errQualification
	}
	current.DetailResponseCode = "DETAIL_RESPONSE_ACCEPTED"
	return nil
}
