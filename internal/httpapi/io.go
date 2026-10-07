package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
)

// DecodeBody bounds bytes before parsing and validates request identity after
// strict DTO validation. maxBytes is a server-owned limit, never caller input.
func DecodeBody(r *http.Request, dst any, maxBytes int64) error {
	if maxBytes < 1 || maxBytes > contract.MaxResultBytes {
		return contract.Invalid("body")
	}
	values := r.Header.Values("Content-Type")
	if len(values) != 1 {
		return contract.Invalid("contentType")
	}
	media, params, e := mime.ParseMediaType(values[0])
	if e != nil || media != "application/json" {
		return contract.Invalid("contentType")
	}
	for k, v := range params {
		if k != "charset" || !strings.EqualFold(v, "utf-8") {
			return contract.Invalid("contentType")
		}
	}
	if r.Header.Get("Content-Encoding") != "" && r.Header.Get("Content-Encoding") != "identity" {
		return contract.Invalid("contentEncoding")
	}
	if r.ContentLength > maxBytes {
		return &contract.ValidationError{Code: "INPUT_TOO_LARGE", Field: "body"}
	}
	if r.Body == nil {
		return contract.Invalid("body")
	}
	data, e := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	if e != nil {
		return contract.Invalid("body")
	}
	if int64(len(data)) > maxBytes {
		return &contract.ValidationError{Code: "INPUT_TOO_LARGE", Field: "body"}
	}
	if e := contract.DecodeJSON(data, dst); e != nil {
		return e
	}
	if body, ok := dst.(interface{ BodyRequestID() contract.UUID }); ok {
		if body.BodyRequestID() != RequestID(r.Context()) {
			return contract.Invalid("requestId")
		}
	}
	return nil
}

func ErrorCode(err error) string {
	var validation *contract.ValidationError
	if errors.As(err, &validation) {
		return validation.Code
	}
	return "INTERNAL_ERROR"
}

// WriteError deliberately accepts a code only. Messages are static and details
// are empty; raw errors, SQL, source, paths and secrets cannot enter the envelope.
func WriteError(w http.ResponseWriter, r *http.Request, code string) {
	status, message := errorDefinition(code)
	if status == 0 {
		code = "INTERNAL_ERROR"
		status, message = errorDefinition(code)
	}
	if code == "REQUEST_IN_PROGRESS" {
		w.Header().Set("Retry-After", "2")
	}
	payload := contract.ApiError{Error: contract.ErrorDetail{Code: code, Message: message, Details: map[string]any{}}, RequestID: RequestID(r.Context())}
	writeJSON(w, r, status, payload, contract.MaxResultBytes)
}
func WriteResponse[T any](w http.ResponseWriter, r *http.Request, status int, data T) {
	writeJSON(w, r, status, contract.ApiResponse[T]{Data: data, RequestID: RequestID(r.Context())}, contract.MaxResultBytes)
}
func WritePage[T any](w http.ResponseWriter, r *http.Request, data contract.Array[T], meta contract.PageMeta) {
	writeJSON(w, r, http.StatusOK, contract.PageResponse[T]{Data: data, Meta: meta, RequestID: RequestID(r.Context())}, contract.MaxResultBytes)
}
func writeJSON(w http.ResponseWriter, r *http.Request, status int, value any, maxBytes int64) {
	if e := contract.ValidateValue(value); e != nil {
		writeInternalError(w, r)
		return
	}
	encoded, e := json.Marshal(value)
	if e != nil || (maxBytes > 0 && int64(len(encoded)) > maxBytes) {
		writeInternalError(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(encoded)
}
func writeInternalError(w http.ResponseWriter, r *http.Request) {
	// Request identity is generated before handlers run and is always valid here.
	encoded, e := json.Marshal(contract.ApiError{Error: contract.ErrorDetail{Code: "INTERNAL_ERROR", Message: "Internal service error", Details: map[string]any{}}, RequestID: RequestID(r.Context())})
	if e != nil {
		http.Error(w, "internal service error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write(encoded)
}
func errorDefinition(code string) (int, string) {
	switch code {
	case "INVALID_ARGUMENT":
		return 400, "Invalid request"
	case "INVALID_PROBLEM_REF":
		return 400, "Invalid problem reference"
	case "SERVICE_UNAUTHORIZED":
		return 401, "Service authentication required"
	case "PROBLEM_NOT_FOUND":
		return 404, "Problem not found"
	case "TASK_NOT_FOUND":
		return 404, "Task not found"
	case "IDEMPOTENCY_CONFLICT":
		return 409, "Request identity conflicts with existing input"
	case "REQUEST_IN_PROGRESS":
		return 409, "Request is in progress"
	case "PROBLEM_VERSION_CONFLICT":
		return 409, "Problem version conflict"
	case "PROBLEM_NOT_SUBMITTABLE":
		return 409, "Problem is unavailable for new submissions"
	case "LANGUAGE_NOT_SUPPORTED":
		return 409, "Language is unavailable"
	case "EVENT_CONFLICT":
		return 409, "Event revision conflict"
	case "SNAPSHOT_EXPIRED":
		return 410, "Catalog snapshot expired"
	case "SOURCE_TOO_LARGE":
		return 413, "Source exceeds the byte limit"
	case "INPUT_TOO_LARGE":
		return 413, "Request exceeds the byte limit"
	case "PACKAGE_INVALID":
		return 422, "Problem package is invalid"
	case "PACKAGE_LICENSE_MISSING":
		return 422, "Problem package license approval is required"
	case "PACKAGE_UNSUPPORTED":
		return 422, "Problem package format is unsupported"
	case "RATE_LIMITED":
		return 429, "Request rate exceeded"
	case "JUDGE_UNAVAILABLE":
		return 503, "Judge capability unavailable"
	case "INTERNAL_ERROR":
		return 500, "Internal service error"
	}
	return 0, ""
}
