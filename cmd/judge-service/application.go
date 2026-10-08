package main

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/admission"
	"github.com/STAR-Ability/code-startrack-judge/internal/callbacks"
	"github.com/STAR-Ability/code-startrack-judge/internal/catalog"
	"github.com/STAR-Ability/code-startrack-judge/internal/config"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/httpapi"
	"github.com/STAR-Ability/code-startrack-judge/internal/imports"
	persistenceimports "github.com/STAR-Ability/code-startrack-judge/internal/persistence/imports"
	"github.com/STAR-Ability/code-startrack-judge/internal/persistence/migrate"
	persistenceoutbox "github.com/STAR-Ability/code-startrack-judge/internal/persistence/outbox"
	persistenceproblems "github.com/STAR-Ability/code-startrack-judge/internal/persistence/problems"
	persistencetasks "github.com/STAR-Ability/code-startrack-judge/internal/persistence/tasks"
	"github.com/STAR-Ability/code-startrack-judge/internal/problems"
	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
	"github.com/STAR-Ability/code-startrack-judge/internal/storage"
	"github.com/STAR-Ability/code-startrack-judge/internal/tasks"
	"github.com/STAR-Ability/code-startrack-judge/internal/validation"
	"github.com/STAR-Ability/code-startrack-judge/migrations"
)

type workerSpec struct {
	code string
	live *atomic.Bool
	run  func(context.Context) error
}

type application struct {
	handler   http.Handler
	probes    *dependencyProbes
	workers   []workerSpec
	close     func()
	fatalStop chan struct{}
	fatalOnce sync.Once
}

// Each probe measures a real dependency. Worker liveness means its validated
// constructor succeeded and its process loop is running; qualification remains
// a separate measured condition and is never inferred from goroutine existence.
type dependencyProbes struct {
	process     context.Context
	database    func(context.Context) bool
	storage     func(context.Context) error
	runtime     func(context.Context) judgeruntime.Snapshot
	catalog     bool
	judge       atomic.Bool
	imports     atomic.Bool
	importProbe func(context.Context) bool
}

func (p *dependencyProbes) inspect(ctx context.Context) (httpapi.DependencyState, judgeruntime.Snapshot) {
	if p.process.Err() != nil || ctx.Err() != nil {
		return httpapi.DependencyState{}, judgeruntime.Snapshot{}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var database, privateStorage bool
	var importReady bool
	var snapshot judgeruntime.Snapshot
	var group sync.WaitGroup
	group.Add(4)
	go func() { defer group.Done(); database = p.database(ctx) }()
	go func() { defer group.Done(); privateStorage = p.storage(ctx) == nil }()
	go func() {
		defer group.Done()
		if p.runtime != nil {
			// A stalled private judger must not consume the whole deployment probe
			// deadline and erase a successfully measured catalog dependency state.
			runtimeCtx, stop := context.WithTimeout(ctx, 750*time.Millisecond)
			defer stop()
			snapshot = p.runtime(runtimeCtx)
			if runtimeCtx.Err() != nil {
				snapshot = judgeruntime.Snapshot{}
			}
		}
	}()
	go func() {
		defer group.Done()
		if p.imports.Load() && p.importProbe != nil {
			importCtx, stop := context.WithTimeout(ctx, 750*time.Millisecond)
			defer stop()
			importReady = p.importProbe(importCtx) && importCtx.Err() == nil
		}
	}()
	group.Wait()
	if p.process.Err() != nil || ctx.Err() != nil {
		return httpapi.DependencyState{}, judgeruntime.Snapshot{}
	}
	return httpapi.DependencyState{Database: database, PrivateStorage: privateStorage, Sandbox: snapshot.Qualified && snapshot.SandboxReady, Toolchain: snapshot.Qualified && snapshot.ToolchainReady, Catalog: p.catalog, Judge: p.judge.Load(), Imports: importReady}, snapshot
}

func (p *dependencyProbes) readiness(ctx context.Context) httpapi.DependencyState {
	state, _ := p.inspect(ctx)
	return state
}
func catalogReady(state httpapi.DependencyState) bool {
	return state.Database && state.PrivateStorage
}
func executionReady(state httpapi.DependencyState) bool {
	return catalogReady(state) && state.Sandbox && state.Toolchain
}
func runtimeIdentity(identity judgeruntime.FrozenIdentity) admission.RuntimeIdentity {
	return admission.RuntimeIdentity{LanguageID: judgeruntime.LanguageID, LanguageConfigVersion: identity.LanguageConfigVersion, CompilerVersion: identity.CompilerVersion, ToolchainDigest: identity.ToolchainDigest, WorkerImageDigest: identity.WorkerImageDigest, SandboxVersion: identity.SandboxVersion, CheckerDigest: identity.CheckerDigest}
}

// databaseReady is read-only and rejects a schema-owner or administrative
// application credential before advertising any business capability.
func databaseReady(ctx context.Context, db *sql.DB, chain []migrate.Migration) bool {
	var allowed bool
	err := db.QueryRowContext(ctx, `SELECT r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolcreatedb AND NOT r.rolcreaterole
 AND NOT r.rolreplication AND NOT r.rolbypassrls AND NOT r.rolinherit
 AND NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=r.oid OR roleid=r.oid)
 AND NOT has_database_privilege(r.oid,current_database(),'CREATE,TEMPORARY')
 AND NOT EXISTS(SELECT 1 FROM pg_database WHERE datdba=r.oid)
 AND NOT EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspowner=r.oid OR
  (n.nspname !~ '^pg_' AND n.nspname<>'information_schema' AND has_schema_privilege(r.oid,n.oid,'CREATE')))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relowner=r.oid OR
  (n.nspname !~ '^pg_' AND n.nspname<>'information_schema' AND n.nspname<>'judge' AND c.relkind IN('r','p','v','m','f') AND
   (has_table_privilege(r.oid,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
    OR has_any_column_privilege(r.oid,c.oid,'SELECT,INSERT,UPDATE,REFERENCES'))))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE
  CASE WHEN c.relkind='S' AND n.nspname !~ '^pg_' AND n.nspname<>'information_schema' AND n.nspname<>'judge'
   THEN has_sequence_privilege(r.oid,c.oid,'SELECT,USAGE,UPDATE') ELSE false END)
 AND NOT EXISTS(SELECT 1 FROM pg_proc f JOIN pg_namespace n ON n.oid=f.pronamespace WHERE f.proowner=r.oid OR
  (n.nspname !~ '^pg_' AND n.nspname<>'information_schema' AND n.nspname<>'judge' AND has_function_privilege(r.oid,f.oid,'EXECUTE')))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='judge' AND c.relname IN('schema_migrations','migration_checksums') AND
  (has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
   OR has_any_column_privilege(r.oid,c.oid,'INSERT,UPDATE,REFERENCES')))
 AND EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='judge')
 FROM pg_roles r WHERE r.rolname=current_user`).Scan(&allowed)
	if err != nil || !allowed {
		return false
	}
	// Operator-owned role-in-database defaults suppress statement parameters,
	// failing-row DETAILs, duration/transaction samples and optional audit logs.
	// The application only measures its effective session; it changes no policy.
	err = db.QueryRowContext(ctx, `SELECT current_setting('log_statement')='none'
 AND current_setting('log_min_error_statement')='panic'
 AND current_setting('log_min_duration_statement')='-1'
 AND current_setting('log_min_duration_sample')='-1'
 AND current_setting('log_duration')='off'
 AND current_setting('log_parameter_max_length')='0'
 AND current_setting('log_parameter_max_length_on_error')='0'
 AND current_setting('log_transaction_sample_rate')='0'
 AND current_setting('log_error_verbosity')='terse'
 AND current_setting('log_min_messages')='panic'
 AND (current_setting('pgaudit.log',true) IS NULL OR current_setting('pgaudit.log',true)='none')
 AND (current_setting('pgaudit.role',true) IS NULL OR current_setting('pgaudit.role',true)='')`).Scan(&allowed)
	if err != nil || !allowed {
		return false
	}
	status, err := migrate.Inspect(ctx, db, chain)
	return err == nil && status.Initialized && !status.Dirty && status.Applied == status.Available && status.Available > 0
}

func newApplication(ctx context.Context, cfg config.Config, db *sql.DB, logger *slog.Logger) (_ *application, err error) {
	chain, err := migrate.Load(migrations.Files)
	if err != nil {
		return nil, err
	}
	startup, cancel := context.WithTimeout(ctx, 10*time.Second)
	ready := databaseReady(startup, db, chain)
	cancel()
	if !ready {
		return nil, errors.New("service requires its nonadministrative application role and complete migrated schema")
	}
	store, err := storage.New(cfg.PrivateStorageDir)
	if err != nil {
		return nil, err
	}
	complete := false
	defer func() {
		if !complete {
			store.Close()
		}
	}()
	registry, err := storage.NewRegistry(db, store)
	if err != nil {
		return nil, err
	}
	taskRepository, err := persistencetasks.New(db, registry)
	if err != nil {
		return nil, err
	}
	problemRepository := persistenceproblems.New(db, registry)
	importRepository := persistenceimports.New(db)
	probes := &dependencyProbes{process: ctx, database: func(probe context.Context) bool { return databaseReady(probe, db, chain) }, storage: store.Check}
	app := &application{probes: probes, fatalStop: make(chan struct{})}
	closers := []func(){func() { store.Close() }}
	defer func() {
		if !complete {
			for i := len(closers) - 1; i > 0; i-- {
				closers[i]()
			}
		}
	}()

	var controlled *controlledRuntime
	if cfg.SchedulerToken() != "" {
		client, err := judgeruntime.NewSchedulerClient(cfg.SchedulerToken(), store)
		if err != nil {
			return nil, err
		}
		closers = append(closers, client.Close)
		controlled = &controlledRuntime{process: ctx, client: client, repository: taskRepository, database: probes.database, storage: store.Check}
		probes.runtime = controlled.Snapshot
		app.workers = append(app.workers, workerSpec{code: "RUNTIME_INITIALIZER_STOPPED", run: controlled.Run})
		worker, err := tasks.NewWorker(tasks.WorkerOptions{Repository: taskRepository, Executor: controlled, Source: func(readCtx context.Context, lease *tasks.Lease) ([]byte, error) {
			return store.Read(readCtx, storage.Object{Key: lease.SourceKey, SHA256: lease.SourceSHA256, SizeBytes: lease.Frozen.SourceSizeBytes}, contract.MaxSourceBytes)
		}, Concurrency: 2, PollInterval: time.Second, ShutdownGrace: 15 * time.Second, FatalStop: app.fatalStop, Report: func(error) { logger.Error("task worker retained work", "code", "TASK_WORKER_FAILURE") }})
		if err != nil {
			return nil, err
		}
		app.workers = append(app.workers, workerSpec{code: "TASK_WORKER_STOPPED", live: &probes.judge, run: worker.Run})
		// Acquisition keeps a fixed executable/repository/commit and an explicit
		// subprocess environment. Health never fetches a repository. The mature
		// verifier is available only when its real isolated hook is qualified.
		source, err := imports.NewGitSource(filepath.Join(cfg.PrivateStorageDir, "acquisition"), "/usr/bin/git", cfg.AcquisitionProxyURL())
		if err != nil {
			return nil, err
		}
		closers = append(closers, func() { source.Close() })
		mature, err := validation.NewMatureClient(controlled)
		if err != nil {
			return nil, err
		}
		validator, err := validation.New(validation.Options{Engine: controlled, Mature: mature})
		if err != nil {
			return nil, err
		}
		pipeline, err := imports.NewPipeline(imports.PipelineOptions{DB: db, Source: source, Registry: registry, Problems: problemRepository, Validation: validator})
		if err != nil {
			return nil, err
		}
		probes.importProbe = pipeline.Ready
		importWorker := &imports.Worker{Repository: importRepository, Pipeline: pipeline, Ready: pipeline.Ready, PollInterval: time.Second}
		app.workers = append(app.workers, workerSpec{code: "IMPORT_WORKER_STOPPED", live: &probes.imports, run: importWorker.Run})
	}
	judgeService, err := admission.New(admission.Options{Repository: taskRepository, Sources: registry, Runtime: func(requestCtx context.Context) (admission.RuntimeIdentity, bool, error) {
		state, snapshot := probes.inspect(requestCtx)
		return runtimeIdentity(snapshot.Identity), executionReady(state) && state.Judge, nil
	}})
	if err != nil {
		return nil, err
	}
	problemService := problems.New(problemRepository, problems.Options{FreshReady: func(requestCtx context.Context) bool { return catalogReady(probes.readiness(requestCtx)) }, LanguageCapabilities: func(requestCtx context.Context) contract.Array[string] {
		languages := contract.Array[string]{}
		if controlled == nil || !probes.judge.Load() {
			return languages
		}
		snapshot := controlled.Snapshot(requestCtx)
		if !measured(snapshot) {
			return languages
		}
		for _, language := range snapshot.Languages.Languages {
			languages = append(languages, language.LanguageID)
		}
		return languages
	}})
	importService := imports.New(importRepository, func(requestCtx context.Context) bool {
		state := probes.readiness(requestCtx)
		return executionReady(state) && state.Imports
	})
	routes := httpapi.Routes{Judge: judgeService, Imports: importService, ListProblems: func(requestCtx context.Context, query httpapi.ProblemListQuery) (contract.Array[contract.PlatformProblemSummary], contract.PageMeta, error) {
		return problemService.List(requestCtx, problems.ListQuery{Pagination: problems.Pagination{Page: query.Page, PageSize: query.PageSize}, Q: query.Q, Tag: query.Tag, MinDifficulty: query.MinDifficulty, MaxDifficulty: query.MaxDifficulty, Status: query.Status})
	}, CurrentProblem: problemService.Current, ProblemVersion: problemService.Version, MetadataVersion: problemService.Metadata, Publish: problemService.Publish, Withdraw: problemService.Withdraw, Languages: func(requestCtx context.Context) (contract.LanguageCapabilities, error) {
		state, snapshot := probes.inspect(requestCtx)
		if !executionReady(state) || !state.Judge || snapshot.Languages.Validate() != nil || len(snapshot.Languages.Languages) == 0 {
			return contract.LanguageCapabilities{}, imports.ErrUnavailable
		}
		return snapshot.Languages, nil
	}}
	var catalogService *catalog.Service
	if len(cfg.CatalogCursorKey()) > 0 {
		catalogService, err = catalog.New(problemRepository, cfg.CatalogCursorKey())
		if err != nil {
			return nil, err
		}
		probes.catalog = true
		routes.CatalogPage = catalogService.Page
	} else {
		routes.CatalogPage = func(context.Context, *string, contract.SafeInt) (contract.CatalogSnapshotPage, error) {
			return contract.CatalogSnapshotPage{}, imports.ErrUnavailable
		}
	}
	callbackClient, err := callbacks.NewClient(cfg.JudgeBackendToken())
	if err != nil {
		return nil, err
	}
	closers = append(closers, callbackClient.Close)
	outbox, err := persistenceoutbox.New(db)
	if err != nil {
		return nil, err
	}
	callbackWorker, err := callbacks.NewWorker(outbox, callbackClient, logger)
	if err != nil {
		return nil, err
	}
	app.workers = append(app.workers, workerSpec{code: "CALLBACK_WORKER_STOPPED", run: callbackWorker.Run})
	app.workers = append(app.workers, workerSpec{code: "PRIVATE_MAINTENANCE_STOPPED", run: maintenance(registry, catalogService, logger)})
	app.handler, err = httpapi.New(httpapi.Options{BackendJudgeToken: cfg.BackendJudgeToken(), Readiness: probes.readiness, Register: func(mux *http.ServeMux) { httpapi.RegisterRoutes(mux, routes) }})
	if err != nil {
		return nil, err
	}
	app.close = func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}
	complete = true
	return app, nil
}

func (app *application) startWorkers(ctx context.Context) (<-chan error, func() error) {
	workerErrors := make(chan error, len(app.workers))
	var group sync.WaitGroup
	var failureOnce sync.Once
	var firstFailure error
	report := func(code string) {
		failure := errors.New(code)
		failureOnce.Do(func() {
			firstFailure = failure
			app.fatalOnce.Do(func() {
				if app.fatalStop != nil {
					close(app.fatalStop)
				}
			})
		})
		workerErrors <- failure
	}
	for _, worker := range app.workers {
		group.Add(1)
		go func() {
			defer group.Done()
			defer func() {
				if recover() != nil {
					report(worker.code)
				}
			}()
			if worker.live != nil {
				worker.live.Store(true)
				defer worker.live.Store(false)
			}
			err := worker.run(ctx)
			if stopped := ctx.Err(); stopped == nil || err != nil && err != stopped {
				// Do not forward unknown driver/tool failures to normal diagnostics.
				// Only the worker's direct cancellation result is an expected stop;
				// a mixed or wrapped failure must not erase a concurrent fault.
				report(worker.code)
			}
		}()
	}
	return workerErrors, func() error {
		group.Wait()
		// Wait synchronizes with every reporter, including one that loses a select
		// race with operator cancellation in the HTTP coordinator.
		return firstFailure
	}
}

func maintenance(registry *storage.Registry, catalogService *catalog.Service, logger *slog.Logger) func(context.Context) error {
	return func(ctx context.Context) error {
		timer := time.NewTimer(time.Minute)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
			}
			probe, cancel := context.WithTimeout(ctx, 30*time.Second)
			_, sourceErr := registry.CleanSources(probe, 100)
			_, collectErr := registry.Collect(probe, time.Now().Add(-24*time.Hour), 100)
			_, orphanErr := registry.CollectUnregistered(probe, time.Now().Add(-24*time.Hour), 100)
			var snapshotErr error
			if catalogService != nil {
				_, snapshotErr = catalogService.Cleanup(probe, 100)
			}
			cancel()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if sourceErr != nil || collectErr != nil || orphanErr != nil || snapshotErr != nil {
				logger.Error("private maintenance retained objects", "code", "PRIVATE_MAINTENANCE_FAILURE")
			}
			timer.Reset(time.Minute)
		}
	}
}
