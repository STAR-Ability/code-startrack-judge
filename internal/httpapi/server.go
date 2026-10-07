// Package httpapi provides the shared authenticated v0.2 HTTP boundary. Business
// handlers register through Options.Register; no unfinished route is advertised.
package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/config"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
)

type Capability string

const (
	Catalog Capability = "catalog"
	Judge   Capability = "judge"
	Imports Capability = "imports"
)

// DependencyState is measured by real dependency adapters. Capability flags
// require implemented services in addition to successful checks; zero values
// therefore fail closed. Catalog can remain available during sandbox failure.
type DependencyState struct {
	Database       bool
	PrivateStorage bool
	Sandbox        bool
	Toolchain      bool
	Catalog        bool
	Judge          bool
	Imports        bool
}
type ReadinessFunc func(context.Context) DependencyState
type Options struct {
	BackendJudgeToken string
	Readiness         ReadinessFunc
	Register          func(*http.ServeMux)
}
type requestIDKey struct{}

func RequestID(ctx context.Context) contract.UUID {
	id, _ := ctx.Value(requestIDKey{}).(contract.UUID)
	return id
}

func New(opts Options) (http.Handler, error) {
	if !config.ValidServiceToken(opts.BackendJudgeToken) {
		return nil, configError()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", healthHandler(opts.Readiness))
	if opts.Register != nil {
		opts.Register(mux)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { WriteError(w, r, "TASK_NOT_FOUND") })
	want := sha256.Sum256([]byte(opts.BackendJudgeToken))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tracked := &commitWriter{ResponseWriter: w}
		w = tracked
		id, e := contract.NewUUID()
		if e != nil {
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}
		values := r.Header.Values("X-Request-Id")
		validID := len(values) == 1 && contract.UUID(values[0]).Validate() == nil
		if validID {
			id = contract.UUID(values[0])
		}
		r = r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id))
		w.Header().Set("X-Request-Id", strings.ToLower(string(id)))
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		defer func() {
			if recover() != nil {
				if tracked.committed {
					panic(http.ErrAbortHandler)
				}
				WriteError(w, r, "INTERNAL_ERROR")
			}
		}()
		if r.URL.Path == "/health" {
			mux.ServeHTTP(w, r)
			return
		}
		if r.URL.Path != "/internal/v2" && !strings.HasPrefix(r.URL.Path, "/internal/v2/") {
			WriteError(w, r, "TASK_NOT_FOUND")
			return
		}
		if r.URL.Path == "/internal/v2" || strings.HasPrefix(r.URL.Path, "/internal/v2/") {
			auth := r.Header.Values("Authorization")
			provided := ""
			if len(auth) == 1 && strings.HasPrefix(auth[0], "Bearer ") {
				provided = strings.TrimPrefix(auth[0], "Bearer ")
			}
			got := sha256.Sum256([]byte(provided))
			if provided == "" || subtle.ConstantTimeCompare(want[:], got[:]) != 1 {
				w.Header().Set("WWW-Authenticate", "Bearer")
				WriteError(w, r, "SERVICE_UNAUTHORIZED")
				return
			}
			if !validID {
				WriteError(w, r, "INVALID_ARGUMENT")
				return
			}
			r = r.Clone(r.Context())
			r.Header.Del("Cookie")
		}
		mux.ServeHTTP(w, r)
	}), nil
}

type commitWriter struct {
	http.ResponseWriter
	committed bool
}

func (w *commitWriter) WriteHeader(status int) {
	if !w.committed {
		w.committed = true
		w.ResponseWriter.WriteHeader(status)
	}
}
func (w *commitWriter) Write(data []byte) (int, error) {
	if !w.committed {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(data)
}
func (w *commitWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

type setupError struct{}

func (setupError) Error() string { return "invalid incoming service credential" }
func configError() error         { return setupError{} }

func capabilities(state DependencyState) contract.HealthCapabilities {
	storage := state.Database && state.PrivateStorage
	execution := storage && state.Sandbox && state.Toolchain
	return contract.HealthCapabilities{Catalog: storage && state.Catalog, Judge: execution && state.Judge, Imports: execution && state.Imports}
}
func inspect(ctx context.Context, readiness ReadinessFunc) DependencyState {
	if readiness == nil {
		return DependencyState{}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	state := readiness(ctx)
	if ctx.Err() != nil {
		return DependencyState{}
	}
	return state
}
func healthHandler(readiness ReadinessFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" || r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
			WriteError(w, r, "INVALID_ARGUMENT")
			return
		}
		state := inspect(r.Context(), readiness)
		caps := capabilities(state)
		health := contract.Health{Status: "unavailable", Service: "judge-problem-service", ContractVersion: contract.Version, Capabilities: caps}
		status := http.StatusServiceUnavailable
		if state.Database && state.PrivateStorage && state.Sandbox && state.Toolchain && caps.Catalog && caps.Judge && caps.Imports {
			health.Status = "ok"
			status = http.StatusOK
		}
		writeJSON(w, r, status, health, 0)
	}
}

// RequireCapability guards fresh admission without disabling historical reads.
// An idempotent POST handler must validate and look up an accepted replay BEFORE
// invoking this guard: Q-006 replays remain available during readiness loss.
// Do not wrap an entire idempotent business route with this helper.
func RequireCapability(readiness ReadinessFunc, capability Capability, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := capabilities(inspect(r.Context(), readiness))
		ready := false
		switch capability {
		case Catalog:
			ready = c.Catalog
		case Judge:
			ready = c.Judge
		case Imports:
			ready = c.Imports
		}
		if !ready {
			WriteError(w, r, "JUDGE_UNAVAILABLE")
			return
		}
		next.ServeHTTP(w, r)
	})
}
