package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/config"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/httpapi"
	"github.com/STAR-Ability/code-startrack-judge/internal/packages"
	"github.com/STAR-Ability/code-startrack-judge/internal/persistence/migrate"
	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
	"github.com/STAR-Ability/code-startrack-judge/internal/testutil/judgetask"
	"github.com/STAR-Ability/code-startrack-judge/internal/testutil/postgres"
	"github.com/STAR-Ability/code-startrack-judge/migrations"
	"github.com/jackc/pgx/v5"
)

func TestDependencyReadinessTracksFailuresAndDrain(t *testing.T) {
	process, cancel := context.WithCancel(context.Background())
	defer cancel()
	var database, privateStorage, qualified, importSource atomic.Bool
	for _, flag := range []*atomic.Bool{&database, &privateStorage, &qualified, &importSource} {
		flag.Store(true)
	}
	probes := &dependencyProbes{process: process, database: func(context.Context) bool { return database.Load() }, storage: func(context.Context) error {
		if !privateStorage.Load() {
			return errors.New("private diagnostic must not escape readiness")
		}
		return nil
	}, runtime: func(context.Context) judgeruntime.Snapshot {
		return judgeruntime.Snapshot{Qualified: qualified.Load(), SandboxReady: qualified.Load(), ToolchainReady: qualified.Load()}
	}, catalog: true, importProbe: func(context.Context) bool { return importSource.Load() }}
	probes.judge.Store(true)
	probes.imports.Store(true)
	handler, err := httpapi.New(httpapi.Options{BackendJudgeToken: strings.Repeat("a", 32), Readiness: probes.readiness})
	if err != nil {
		t.Fatal(err)
	}
	health := func(status int, want contract.HealthCapabilities) {
		t.Helper()
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest("GET", "/health", nil))
		var actual contract.Health
		if response.Code != status || contract.DecodeJSON(response.Body.Bytes(), &actual) != nil || actual.Capabilities != want {
			t.Fatalf("unexpected readiness status %d", response.Code)
		}
	}
	health(http.StatusOK, contract.HealthCapabilities{Catalog: true, Judge: true, Imports: true})
	qualified.Store(false)
	health(http.StatusServiceUnavailable, contract.HealthCapabilities{Catalog: true})
	qualified.Store(true)
	importSource.Store(false)
	health(http.StatusServiceUnavailable, contract.HealthCapabilities{Catalog: true, Judge: true})
	importSource.Store(true)
	probes.judge.Store(false)
	health(http.StatusServiceUnavailable, contract.HealthCapabilities{Catalog: true, Imports: true})
	probes.judge.Store(true)
	privateStorage.Store(false)
	health(http.StatusServiceUnavailable, contract.HealthCapabilities{})
	privateStorage.Store(true)
	database.Store(false)
	health(http.StatusServiceUnavailable, contract.HealthCapabilities{})
	database.Store(true)
	cancel()
	health(http.StatusServiceUnavailable, contract.HealthCapabilities{})
}

func TestWorkerLivenessAndBoundedFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var live atomic.Bool
	started := make(chan struct{})
	app := application{workers: []workerSpec{{code: "FIXED_WORKER_FAILURE", live: &live, run: func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}}}}
	failures, wait := app.startWorkers(ctx)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("worker did not initialize")
	}
	if !live.Load() {
		t.Fatal("running worker was not visible")
	}
	cancel()
	wait()
	if live.Load() || len(failures) != 0 {
		t.Fatal("shutdown worker retained liveness or reported cancellation as failure")
	}
	app.workers[0].run = func(context.Context) error { return errors.New("private raw tool path and credential") }
	failures, wait = app.startWorkers(context.Background())
	wait()
	if live.Load() || (<-failures).Error() != "FIXED_WORKER_FAILURE" {
		t.Fatal("worker exposed a private failure or remained live")
	}
	app.workers[0].run = func(context.Context) error { panic("private source and tool diagnostic") }
	failures, wait = app.startWorkers(context.Background())
	wait()
	if live.Load() || (<-failures).Error() != "FIXED_WORKER_FAILURE" {
		t.Fatal("worker exposed a private panic or remained live")
	}
}

func TestWorkerFailureSurvivesOperatorCancellation(t *testing.T) {
	for _, mode := range []string{"error", "panic", "mixed_cancellation", "nil", "cancellation"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			started := make(chan struct{})
			var live atomic.Bool
			app := application{workers: []workerSpec{{code: "FIXED_WORKER_FAILURE", live: &live, run: func(ctx context.Context) error {
				close(started)
				<-ctx.Done()
				switch mode {
				case "error":
					return errors.New("private concurrent worker failure")
				case "panic":
					panic("private concurrent worker panic")
				case "mixed_cancellation":
					return errors.Join(ctx.Err(), errors.New("private concurrent failure"))
				case "cancellation":
					return ctx.Err()
				default:
					return nil
				}
			}}}}
			failures, wait := app.startWorkers(ctx)
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("worker did not start")
			}
			cancel()
			err := wait()
			if live.Load() {
				t.Fatal("stopped worker retained liveness")
			}
			if mode == "nil" || mode == "cancellation" {
				if err != nil || len(failures) != 0 {
					t.Fatal("healthy cancellation became a worker fault")
				}
				return
			}
			if err == nil || err.Error() != "FIXED_WORKER_FAILURE" || len(failures) != 1 || (<-failures).Error() != "FIXED_WORKER_FAILURE" {
				t.Fatal("operator cancellation erased a true fault or exposed a private diagnostic")
			}
			// The final error survives consumption of the notification by an earlier
			// select branch; the service closes resources only after this wait.
			if retained := wait(); retained == nil || retained.Error() != "FIXED_WORKER_FAILURE" {
				t.Fatal("consumed worker notification erased the final failure")
			}
		})
	}
}

func TestStalledJudgerPreservesCatalogReadiness(t *testing.T) {
	probes := &dependencyProbes{process: context.Background(), database: func(context.Context) bool { return true }, storage: func(context.Context) error { return nil }, runtime: func(ctx context.Context) judgeruntime.Snapshot {
		<-ctx.Done()
		return judgeruntime.Snapshot{Qualified: true, SandboxReady: true, ToolchainReady: true}
	}, catalog: true}
	probes.judge.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	state := probes.readiness(ctx)
	if ctx.Err() != nil || !catalogReady(state) || !state.Catalog || executionReady(state) {
		t.Fatal("stalled runtime erased independent catalog readiness or escaped its deadline")
	}
}

func TestStalledImportDependencyPreservesOtherReadiness(t *testing.T) {
	probes := &dependencyProbes{process: context.Background(), database: func(context.Context) bool { return true }, storage: func(context.Context) error { return nil }, runtime: func(context.Context) judgeruntime.Snapshot {
		return judgeruntime.Snapshot{Qualified: true, SandboxReady: true, ToolchainReady: true}
	}, catalog: true, importProbe: func(ctx context.Context) bool { <-ctx.Done(); return true }}
	probes.judge.Store(true)
	probes.imports.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	state := probes.readiness(ctx)
	if ctx.Err() != nil || !catalogReady(state) || !state.Catalog || !executionReady(state) || !state.Judge || state.Imports {
		t.Fatal("stalled import dependency erased independent readiness or escaped its deadline")
	}
}

// Actual migrated PostgreSQL and storage are exercised here; no sandbox exists
// in this test and execution/import readiness must remain false.
func TestPostgresApplicationCatalogAndPrivilegeBoundary(t *testing.T) {
	database := postgres.New(t)
	judgetask.Seed(t, database.Admin, 1)
	chain, err := migrate.Load(migrations.Files)
	if err != nil {
		t.Fatal(err)
	}
	var role, databaseName string
	if database.Runtime.QueryRow("SELECT current_user,current_database()").Scan(&role, &databaseName) != nil {
		t.Fatal("cannot inspect isolated application authority")
	}
	quotedRole, quotedDatabase := pgx.Identifier{role}.Sanitize(), pgx.Identifier{databaseName}.Sanitize()
	for _, setting := range []struct{ key, value string }{{"log_statement", "none"}, {"log_min_error_statement", "panic"}, {"log_min_duration_statement", "-1"}, {"log_min_duration_sample", "-1"}, {"log_duration", "off"}, {"log_parameter_max_length", "0"}, {"log_parameter_max_length_on_error", "0"}, {"log_transaction_sample_rate", "0"}, {"log_error_verbosity", "terse"}, {"log_min_messages", "panic"}} {
		if _, err := database.Admin.Exec("ALTER ROLE " + quotedRole + " IN DATABASE " + quotedDatabase + " SET " + setting.key + "='" + setting.value + "'"); err != nil {
			t.Fatal("cannot apply isolated operator-owned session logging policy")
		}
	}
	resetSessions := func() { database.Runtime.SetMaxIdleConns(0); database.Runtime.SetMaxIdleConns(4) }
	resetSessions()
	if !databaseReady(context.Background(), database.Runtime, chain) || databaseReady(context.Background(), database.Admin, chain) {
		t.Fatal("application database privilege boundary was not enforced")
	}
	if _, err := database.Admin.Exec("CREATE SCHEMA backend_probe;CREATE TABLE backend_probe.submissions(source text);REVOKE ALL ON SCHEMA backend_probe FROM PUBLIC"); err != nil {
		t.Fatal("cannot allocate private cross-service authority fixture")
	}
	for _, profile := range []struct{ grant, restore string }{
		{"ALTER ROLE " + quotedRole + " INHERIT", "ALTER ROLE " + quotedRole + " NOINHERIT"},
		{"GRANT pg_read_all_data TO " + quotedRole, "REVOKE pg_read_all_data FROM " + quotedRole},
		{"GRANT TEMPORARY ON DATABASE " + quotedDatabase + " TO " + quotedRole, "REVOKE TEMPORARY ON DATABASE " + quotedDatabase + " FROM " + quotedRole},
		{"GRANT USAGE ON SCHEMA backend_probe TO " + quotedRole + ";GRANT SELECT(source) ON backend_probe.submissions TO " + quotedRole, "REVOKE ALL ON backend_probe.submissions FROM " + quotedRole + ";REVOKE SELECT(source) ON backend_probe.submissions FROM " + quotedRole + ";REVOKE ALL ON SCHEMA backend_probe FROM " + quotedRole},
	} {
		if _, err := database.Admin.Exec(profile.grant); err != nil {
			t.Fatal("cannot apply isolated unsafe authority fixture")
		}
		unsafeAccepted := databaseReady(context.Background(), database.Runtime, chain)
		if _, err := database.Admin.Exec(profile.restore); err != nil {
			t.Fatal("cannot restore isolated application authority")
		}
		if unsafeAccepted || !databaseReady(context.Background(), database.Runtime, chain) {
			t.Fatal("unsafe application authority passed readiness or safe authority failed recovery")
		}
	}
	if _, err := database.Admin.Exec("ALTER ROLE " + quotedRole + " IN DATABASE " + quotedDatabase + " SET log_transaction_sample_rate='1'"); err != nil {
		t.Fatal("cannot apply unsafe isolated SQL logging fixture")
	}
	resetSessions()
	unsafeLoggingAccepted := databaseReady(context.Background(), database.Runtime, chain)
	if _, err := database.Admin.Exec("ALTER ROLE " + quotedRole + " IN DATABASE " + quotedDatabase + " SET log_transaction_sample_rate='0'"); err != nil {
		t.Fatal("cannot restore isolated SQL logging policy")
	}
	resetSessions()
	if unsafeLoggingAccepted || !databaseReady(context.Background(), database.Runtime, chain) {
		t.Fatal("unsafe private SQL logging passed readiness or safe logging failed recovery")
	}
	settings := map[string]string{"JUDGE_DATABASE_URL": database.RuntimeURL, "JUDGE_PRIVATE_STORAGE_DIR": filepath.Join(t.TempDir(), "private"), "BACKEND_JUDGE_TOKEN": strings.Repeat("a", 32), "JUDGE_BACKEND_TOKEN": strings.Repeat("b", 32), "JUDGE_CATALOG_CURSOR_KEY": strings.Repeat("d", 32)}
	cfg, err := config.Load(func(key string) string { return settings[key] })
	if err != nil {
		t.Fatal("synthetic application settings invalid")
	}
	process, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	app, err := newApplication(process, cfg, database.Runtime, logger)
	if err != nil {
		t.Fatal("actual application dependencies failed to initialize")
	}
	defer app.close()
	request := func(path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		r.Header.Set("Authorization", "Bearer "+cfg.BackendJudgeToken())
		r.Header.Set("X-Request-Id", "00000000-0000-0000-0000-000000000077")
		response := httptest.NewRecorder()
		app.handler.ServeHTTP(response, r)
		return response
	}
	response := request("/health")
	var health contract.Health
	if response.Code != http.StatusServiceUnavailable || contract.DecodeJSON(response.Body.Bytes(), &health) != nil || health.Capabilities != (contract.HealthCapabilities{Catalog: true}) {
		t.Fatal("unqualified application overstated its capabilities")
	}
	response = request("/internal/v2/problems?page=1&pageSize=20")
	var page contract.PageResponse[contract.PlatformProblemSummary]
	if response.Code != http.StatusOK || contract.DecodeJSON(response.Body.Bytes(), &page) != nil || len(page.Data) != 1 || len(page.Data[0].LanguageIDs) != 0 {
		t.Fatal("historical problem list unavailable without sandbox")
	}
	response = request("/internal/v2/catalog-snapshots")
	var snapshot contract.ApiResponse[contract.CatalogSnapshotPage]
	if response.Code != http.StatusOK || contract.DecodeJSON(response.Body.Bytes(), &snapshot) != nil || len(snapshot.Data.Items) != 1 {
		t.Fatal("real catalog snapshot unavailable without sandbox")
	}
	response = request("/internal/v2/languages")
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "JUDGE_UNAVAILABLE") {
		t.Fatal("missing scheduler advertised a language")
	}
	cancel()
	response = request("/health")
	if response.Code != http.StatusServiceUnavailable || contract.DecodeJSON(response.Body.Bytes(), &health) != nil || health.Capabilities != (contract.HealthCapabilities{}) {
		t.Fatal("draining application retained capability readiness")
	}
	t.Run("configured import graph remains unqualified", func(t *testing.T) {
		settings["JUDGE_SCHEDULER_TOKEN"] = strings.Repeat("c", 32)
		configured, err := config.Load(func(key string) string { return settings[key] })
		if err != nil {
			t.Fatal("synthetic scheduler configuration invalid")
		}
		process, stop := context.WithCancel(context.Background())
		defer stop()
		connected, err := newApplication(process, configured, database.Runtime, logger)
		if err != nil {
			t.Fatal("configured domain graph failed to initialize")
		}
		defer connected.close()
		failures, wait := connected.startWorkers(process)
		defer func() { stop(); wait() }()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		deadline := time.NewTimer(time.Second)
		defer deadline.Stop()
		for !connected.probes.judge.Load() || !connected.probes.imports.Load() {
			select {
			case <-ticker.C:
			case <-deadline.C:
				t.Fatal("validated execution loops failed to start")
			}
		}
		requestID := contract.UUID("00000000-0000-0000-0000-000000000088")
		body, err := json.Marshal(contract.ImportRequest{RequestID: requestID, Source: "OJ_LAB", RepositoryURL: contract.PackageRepository, Revision: packages.PinnedRevision, PackagePaths: contract.Array[string]{"problems/synthetic"}})
		if err != nil {
			t.Fatal("cannot encode valid synthetic import request")
		}
		r := httptest.NewRequest("POST", "/internal/v2/problem-imports", strings.NewReader(string(body)))
		r.Header.Set("Authorization", "Bearer "+configured.BackendJudgeToken())
		r.Header.Set("X-Request-Id", string(requestID))
		r.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		connected.handler.ServeHTTP(response, r)
		if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "JUDGE_UNAVAILABLE") {
			t.Fatal("unqualified mature validation admitted an import")
		}
		var jobs int
		if database.Admin.QueryRow("SELECT count(*) FROM judge.import_jobs").Scan(&jobs) != nil || jobs != 0 {
			t.Fatal("unqualified import created durable admission")
		}
		acquisition := filepath.Join(configured.PrivateStorageDir, "acquisition")
		info, err := os.Stat(acquisition)
		entries, readErr := os.ReadDir(acquisition)
		if err != nil || readErr != nil || info.Mode().Perm() != 0700 || len(entries) != 0 {
			t.Fatal("readiness fetched source or lost private acquisition permissions")
		}
		stop()
		wait()
		if len(failures) != 0 || connected.probes.judge.Load() || connected.probes.imports.Load() {
			t.Fatal("configured execution lifecycle failed to drain")
		}
	})
}
