package tasks

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/admission"
	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
	taskdomain "github.com/STAR-Ability/code-startrack-judge/internal/tasks"
)

func runtimeProfile() (compile, run, limits []byte) {
	compile, _ = json.Marshal(struct {
		Args []string `json:"argv"`
	}{judgeruntime.CompileTemplate()})
	run = []byte(`{"argv":["/w/main"]}`)
	limits, _ = json.Marshal(judgeruntime.Limits{CPUTimeNS: uint64(60 * time.Second), WallTimeNS: uint64(120 * time.Second), MemoryBytes: 1 << 30, OutputBytes: 8 << 20, Processes: 128})
	return
}

// RegisterRuntime is initialization from the currently qualified server
// runtime. A same-version conflict rejects configuration instead of rewriting
// history. Callers must obtain the identity/capability from genuine readiness.
func (r *Repository) RegisterRuntime(ctx context.Context, identity admission.RuntimeIdentity, analysisSupported bool) error {
	frozen := judgeruntime.FrozenIdentity{LanguageConfigVersion: identity.LanguageConfigVersion, CompilerVersion: identity.CompilerVersion, ToolchainDigest: identity.ToolchainDigest, WorkerImageDigest: identity.WorkerImageDigest, SandboxVersion: identity.SandboxVersion, CheckerDigest: identity.CheckerDigest}
	if identity.LanguageID != judgeruntime.LanguageID || frozen.Validate() != nil {
		return taskdomain.ErrInvalid
	}
	compile, run, limits := runtimeProfile()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return taskdomain.ErrPersistence
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('judge-language:'||$1,0))`, identity.LanguageID); err != nil {
		return taskdomain.ErrPersistence
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO judge.judge_language_configs(language_id,config_version,display_name,language_family,compiler_version,source_filename,compile_template,run_template,compile_limits,toolchain_digest,analysis_supported,is_active)
 VALUES($1,$2,'C++17','CPP',$3,'main.cpp',$4,$5,$6,$7,$8,false) ON CONFLICT(language_id,config_version) DO NOTHING`, identity.LanguageID, identity.LanguageConfigVersion, identity.CompilerVersion, string(compile), string(run), string(limits), identity.ToolchainDigest, analysisSupported)
	if err != nil {
		return taskdomain.ErrPersistence
	}
	var display, family, compiler, filename, storedCompile, storedRun, storedLimits, toolchain string
	var analysis bool
	err = tx.QueryRowContext(ctx, `SELECT display_name,language_family,compiler_version,source_filename,compile_template::text,run_template::text,compile_limits::text,toolchain_digest,analysis_supported
 FROM judge.judge_language_configs WHERE language_id=$1 AND config_version=$2 FOR UPDATE`, identity.LanguageID, identity.LanguageConfigVersion).Scan(&display, &family, &compiler, &filename, &storedCompile, &storedRun, &storedLimits, &toolchain, &analysis)
	if err != nil {
		return taskdomain.ErrPersistence
	}
	if display != "C++17" || family != "CPP" || compiler != identity.CompilerVersion || filename != "main.cpp" || toolchain != identity.ToolchainDigest || analysis != analysisSupported || !sameJSON([]byte(storedCompile), compile) || !sameJSON([]byte(storedRun), run) || !sameJSON([]byte(storedLimits), limits) {
		return taskdomain.ErrInvalid
	}
	if _, err = tx.ExecContext(ctx, `UPDATE judge.judge_language_configs SET is_active=false WHERE language_id=$1 AND config_version<>$2 AND is_active`, identity.LanguageID, identity.LanguageConfigVersion); err != nil {
		return taskdomain.ErrPersistence
	}
	if _, err = tx.ExecContext(ctx, `UPDATE judge.judge_language_configs SET is_active=true WHERE language_id=$1 AND config_version=$2 AND NOT is_active`, identity.LanguageID, identity.LanguageConfigVersion); err != nil {
		return taskdomain.ErrPersistence
	}
	if tx.Commit() != nil {
		return taskdomain.ErrPersistence
	}
	return nil
}

// RuntimeReady is read-only; health probes never activate configurations.
func (r *Repository) RuntimeReady(ctx context.Context, identity admission.RuntimeIdentity, analysisSupported bool) (bool, error) {
	frozen := judgeruntime.FrozenIdentity{LanguageConfigVersion: identity.LanguageConfigVersion, CompilerVersion: identity.CompilerVersion, ToolchainDigest: identity.ToolchainDigest, WorkerImageDigest: identity.WorkerImageDigest, SandboxVersion: identity.SandboxVersion, CheckerDigest: identity.CheckerDigest}
	if identity.LanguageID != judgeruntime.LanguageID || frozen.Validate() != nil {
		return false, nil
	}
	var display, family, compiler, filename, compile, run, limits, toolchain string
	var analysis, active bool
	err := r.db.QueryRowContext(ctx, `SELECT display_name,language_family,compiler_version,source_filename,compile_template::text,run_template::text,compile_limits::text,toolchain_digest,analysis_supported,is_active
 FROM judge.judge_language_configs WHERE language_id=$1 AND config_version=$2`, identity.LanguageID, identity.LanguageConfigVersion).Scan(&display, &family, &compiler, &filename, &compile, &run, &limits, &toolchain, &analysis, &active)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, taskdomain.ErrPersistence
	}
	expectedCompile, expectedRun, expectedLimits := runtimeProfile()
	return active && display == "C++17" && family == "CPP" && compiler == identity.CompilerVersion && filename == "main.cpp" && toolchain == identity.ToolchainDigest && analysis == analysisSupported && sameJSON([]byte(compile), expectedCompile) && sameJSON([]byte(run), expectedRun) && sameJSON([]byte(limits), expectedLimits), nil
}
