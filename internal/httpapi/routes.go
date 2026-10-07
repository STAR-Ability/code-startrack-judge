package httpapi

import (
	"context"
	"net/http"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
)

type JudgeService interface {
	Submit(context.Context, contract.JudgeTaskRequest) (contract.JudgeTask, bool, error)
	Get(context.Context, contract.UUID) (contract.JudgeTask, error)
	ByRequest(context.Context, contract.ByRequestRequest) (contract.ByRequestResponse, error)
}
type ImportService interface {
	Submit(context.Context, contract.ImportRequest) (contract.ImportJob, bool, error)
	Get(context.Context, contract.UUID) (contract.ImportJob, error)
}

// Routes supplies small domain seams without granting handlers SQL or private
// storage access. Missing services are not registered or advertised as available.
type Routes struct {
	Judge           JudgeService
	Imports         ImportService
	ListProblems    func(context.Context, ProblemListQuery) (contract.Array[contract.PlatformProblemSummary], contract.PageMeta, error)
	CurrentProblem  func(context.Context, contract.ID) (contract.PlatformProblemDetail, error)
	ProblemVersion  func(context.Context, contract.ID, contract.UUID) (contract.PlatformProblemDetail, error)
	MetadataVersion func(context.Context, contract.ID, contract.MetadataVersionRequest) (contract.PlatformProblemDetail, bool, error)
	Publish         func(context.Context, contract.ID, contract.PublishRequest) (contract.PlatformProblemDetail, error)
	Withdraw        func(context.Context, contract.ID, contract.WithdrawRequest) (contract.WithdrawResponse, error)
	CatalogPage     func(context.Context, *string, contract.SafeInt) (contract.CatalogSnapshotPage, error)
	Languages       func(context.Context) (contract.LanguageCapabilities, error)
}

func RegisterRoutes(mux *http.ServeMux, routes Routes) {
	if routes.Judge != nil {
		mux.HandleFunc("POST /internal/v2/judge-tasks", func(w http.ResponseWriter, r *http.Request) {
			if !noQuery(w, r) {
				return
			}
			var request contract.JudgeTaskRequest
			if err := DecodeBody(r, &request, contract.MaxJudgeRequestBytes); err != nil {
				WriteError(w, r, ErrorCode(err))
				return
			}
			task, created, err := routes.Judge.Submit(r.Context(), request)
			if err != nil {
				WriteError(w, r, ErrorCode(err))
				return
			}
			status := http.StatusOK
			if created {
				status = http.StatusAccepted
			}
			WriteResponse(w, r, status, task)
		})
		mux.HandleFunc("GET /internal/v2/judge-tasks/{judgeTaskId}", func(w http.ResponseWriter, r *http.Request) {
			if !noQueryOrBody(w, r) {
				return
			}
			id := contract.UUID(r.PathValue("judgeTaskId"))
			if err := id.Validate(); err != nil {
				WriteError(w, r, "INVALID_ARGUMENT")
				return
			}
			task, err := routes.Judge.Get(r.Context(), id)
			if err != nil {
				WriteError(w, r, ErrorCode(err))
				return
			}
			WriteResponse(w, r, http.StatusOK, task)
		})
		mux.HandleFunc("POST /internal/v2/judge-tasks/by-request", func(w http.ResponseWriter, r *http.Request) {
			if !noQuery(w, r) {
				return
			}
			var request contract.ByRequestRequest
			if err := DecodeBody(r, &request, contract.MaxJudgeRequestBytes); err != nil {
				WriteError(w, r, ErrorCode(err))
				return
			}
			result, err := routes.Judge.ByRequest(r.Context(), request)
			if err != nil {
				WriteError(w, r, ErrorCode(err))
				return
			}
			WriteResponse(w, r, http.StatusOK, result)
		})
	}
	if routes.Imports != nil {
		mux.HandleFunc("POST /internal/v2/problem-imports", func(w http.ResponseWriter, r *http.Request) {
			if !noQuery(w, r) {
				return
			}
			var request contract.ImportRequest
			if err := DecodeBody(r, &request, contract.MaxJudgeRequestBytes); err != nil {
				WriteError(w, r, ErrorCode(err))
				return
			}
			job, created, err := routes.Imports.Submit(r.Context(), request)
			if err != nil {
				WriteError(w, r, ErrorCode(err))
				return
			}
			status := http.StatusOK
			if created {
				status = http.StatusAccepted
			}
			WriteResponse(w, r, status, job)
		})
		mux.HandleFunc("GET /internal/v2/problem-imports/{importJobId}", func(w http.ResponseWriter, r *http.Request) {
			if !noQueryOrBody(w, r) {
				return
			}
			id := contract.UUID(r.PathValue("importJobId"))
			if err := id.Validate(); err != nil {
				WriteError(w, r, "INVALID_ARGUMENT")
				return
			}
			job, err := routes.Imports.Get(r.Context(), id)
			if err != nil {
				WriteError(w, r, ErrorCode(err))
				return
			}
			WriteResponse(w, r, http.StatusOK, job)
		})
	}
	if routes.ListProblems != nil {
		mux.HandleFunc("GET /internal/v2/problems", func(w http.ResponseWriter, r *http.Request) {
			if !noBody(w, r) {
				return
			}
			query, err := ParseProblemListQuery(r.URL.RawQuery)
			if err != nil {
				WriteError(w, r, ErrorCode(err))
				return
			}
			rows, meta, err := routes.ListProblems(r.Context(), query)
			if err != nil {
				WriteError(w, r, ErrorCode(err))
				return
			}
			WritePage(w, r, rows, meta)
		})
	}
	if routes.CurrentProblem != nil {
		mux.HandleFunc("GET /internal/v2/problems/{problemId}", func(w http.ResponseWriter, r *http.Request) {
			if !noQueryOrBody(w, r) {
				return
			}
			id, valid := problemID(w, r)
			if !valid {
				return
			}
			detail, err := routes.CurrentProblem(r.Context(), id)
			if err != nil {
				WriteError(w, r, ErrorCode(err))
				return
			}
			WriteResponse(w, r, http.StatusOK, detail)
		})
	}
	if routes.ProblemVersion != nil {
		mux.HandleFunc("GET /internal/v2/problems/{problemId}/versions/{problemVersionId}", func(w http.ResponseWriter, r *http.Request) {
			if !noQueryOrBody(w, r) {
				return
			}
			id, valid := problemID(w, r)
			if !valid {
				return
			}
			version := contract.UUID(r.PathValue("problemVersionId"))
			if err := version.Validate(); err != nil {
				WriteError(w, r, "INVALID_ARGUMENT")
				return
			}
			detail, err := routes.ProblemVersion(r.Context(), id, version)
			if err != nil {
				WriteError(w, r, ErrorCode(err))
				return
			}
			WriteResponse(w, r, http.StatusOK, detail)
		})
	}
	if routes.MetadataVersion != nil {
		mux.HandleFunc("POST /internal/v2/problems/{problemId}/metadata-versions", func(w http.ResponseWriter, r *http.Request) {
			if !noQuery(w, r) {
				return
			}
			id, valid := problemID(w, r)
			if !valid {
				return
			}
			var request contract.MetadataVersionRequest
			if err := DecodeBody(r, &request, contract.MaxJudgeRequestBytes); err != nil {
				WriteError(w, r, ErrorCode(err))
				return
			}
			// Domain normalization and canonical hashing occur after raw body/header
			// identity checks and before durable management idempotency lookup.
			detail, replay, err := routes.MetadataVersion(r.Context(), id, request.Normalize())
			if err != nil {
				WriteError(w, r, ErrorCode(err))
				return
			}
			status := http.StatusCreated
			if replay {
				status = http.StatusOK
			}
			WriteResponse(w, r, status, detail)
		})
	}
	if routes.Publish != nil {
		mux.HandleFunc("POST /internal/v2/problems/{problemId}/publish", func(w http.ResponseWriter, r *http.Request) {
			if !noQuery(w, r) {
				return
			}
			id, valid := problemID(w, r)
			if !valid {
				return
			}
			var request contract.PublishRequest
			if err := DecodeBody(r, &request, contract.MaxJudgeRequestBytes); err != nil {
				WriteError(w, r, ErrorCode(err))
				return
			}
			detail, err := routes.Publish(r.Context(), id, request)
			if err != nil {
				WriteError(w, r, ErrorCode(err))
				return
			}
			WriteResponse(w, r, http.StatusOK, detail)
		})
	}
	if routes.Withdraw != nil {
		mux.HandleFunc("POST /internal/v2/problems/{problemId}/withdraw", func(w http.ResponseWriter, r *http.Request) {
			if !noQuery(w, r) {
				return
			}
			id, valid := problemID(w, r)
			if !valid {
				return
			}
			var request contract.WithdrawRequest
			if err := DecodeBody(r, &request, contract.MaxJudgeRequestBytes); err != nil {
				WriteError(w, r, ErrorCode(err))
				return
			}
			result, err := routes.Withdraw(r.Context(), id, request)
			if err != nil {
				WriteError(w, r, ErrorCode(err))
				return
			}
			WriteResponse(w, r, http.StatusOK, result)
		})
	}
	if routes.CatalogPage != nil {
		mux.HandleFunc("GET /internal/v2/catalog-snapshots", func(w http.ResponseWriter, r *http.Request) {
			if !noBody(w, r) {
				return
			}
			query, err := ParseSnapshotQuery(r.URL.RawQuery)
			if err != nil {
				WriteError(w, r, ErrorCode(err))
				return
			}
			page, err := routes.CatalogPage(r.Context(), query.Cursor, query.Limit)
			if err != nil {
				WriteError(w, r, ErrorCode(err))
				return
			}
			WriteResponse(w, r, http.StatusOK, page)
		})
	}
	if routes.Languages != nil {
		mux.HandleFunc("GET /internal/v2/languages", func(w http.ResponseWriter, r *http.Request) {
			if !noQueryOrBody(w, r) {
				return
			}
			languages, err := routes.Languages(r.Context())
			if err != nil {
				WriteError(w, r, ErrorCode(err))
				return
			}
			WriteResponse(w, r, http.StatusOK, languages)
		})
	}
}

func noQuery(w http.ResponseWriter, r *http.Request) bool {
	if _, err := ParseQuery(r.URL.RawQuery); err != nil {
		WriteError(w, r, "INVALID_ARGUMENT")
		return false
	}
	return true
}
func noBody(w http.ResponseWriter, r *http.Request) bool {
	if r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
		WriteError(w, r, "INVALID_ARGUMENT")
		return false
	}
	return true
}
func noQueryOrBody(w http.ResponseWriter, r *http.Request) bool { return noQuery(w, r) && noBody(w, r) }
func problemID(w http.ResponseWriter, r *http.Request) (contract.ID, bool) {
	id := contract.ID(r.PathValue("problemId"))
	if err := id.Validate(); err != nil {
		WriteError(w, r, "INVALID_ARGUMENT")
		return "", false
	}
	return id, true
}
