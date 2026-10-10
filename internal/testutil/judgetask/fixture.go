// Package judgetask supplies explicitly synthetic qualified package fixtures.
// These are repository transaction evidence, never Linux validation evidence.
package judgetask

import (
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/admission"
	"github.com/STAR-Ability/code-startrack-judge/internal/packages"
	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
)

//go:embed testdata/seed.sql
var seed string

func Identity() admission.RuntimeIdentity {
	return admission.RuntimeIdentity{LanguageID: judgeruntime.LanguageID, LanguageConfigVersion: judgeruntime.CompilerConfigVersion, CompilerVersion: judgeruntime.CompilerVersion, ToolchainDigest: judgeruntime.CPP17ToolchainDigest, WorkerImageDigest: "sha256:" + strings.Repeat("b", 64), SandboxVersion: judgeruntime.SandboxVersion, CheckerDigest: strings.Repeat("c", 64)}
}
func Seed(t *testing.T, db *sql.DB, count int) {
	t.Helper()
	if count < 1 || count > 65536 {
		t.Fatal("invalid synthetic fixture test count")
	}
	sqlText := strings.ReplaceAll(seed, `{"testCount":1}`, fmt.Sprintf(`{"testCount":%d}`, count))
	checker, _ := json.Marshal(packages.DefaultChecker())
	sqlText = strings.Replace(sqlText, `'BATCH_PASS_FAIL','{}',repeat('a',64)`, `'BATCH_PASS_FAIL','`+string(checker)+`',repeat('a',64)`, 1)
	sqlText = strings.Replace(sqlText, `'fixture-1'`, `'`+judgeruntime.CompilerConfigVersion+`'`, 1)
	sqlText = strings.Replace(sqlText, `false,false);`, `false,true);`, 1)
	sqlText = strings.Replace(sqlText, `'C++','gcc-fixture','main.cpp'`, `'CPP','`+judgeruntime.CompilerVersion+`','main.cpp'`, 1)
	sqlText = strings.Replace(sqlText, `,'sha256:'||repeat('a',64),false,true);`, `,'`+judgeruntime.CPP17ToolchainDigest+`',false,true);`, 1)
	compile, _ := json.Marshal(struct {
		Args []string `json:"argv"`
	}{judgeruntime.CompileTemplate()})
	compileLimits, _ := json.Marshal(judgeruntime.Limits{CPUTimeNS: uint64(60 * time.Second), WallTimeNS: uint64(120 * time.Second), MemoryBytes: 1 << 30, OutputBytes: 8 << 20, Processes: 128})
	sqlText = strings.Replace(sqlText, `'main.cpp','{}','{}','{}'`, `'main.cpp','`+string(compile)+`','{"argv":["/w/main"]}','`+string(compileLimits)+`'`, 1)
	first := strings.Index(sqlText, "INSERT INTO judge.problem_test_cases(")
	end := strings.Index(sqlText[first:], ";\n") + first + 2
	sqlText = sqlText[:first] + fmt.Sprintf(`INSERT INTO judge.problem_test_cases(id,package_artifact_id,ordinal,visibility,input_object_key,answer_object_key,input_sha256,answer_sha256,input_size_bytes,answer_size_bytes)
 SELECT md5('synthetic-case-'||n)::uuid,'00000000-0000-0000-0000-000000000010',n,'SECRET','private/input/'||n,'private/answer/'||n,repeat('a',64),repeat('a',64),1,1 FROM generate_series(1,%d) n;
`, count) + sqlText[end:]
	sqlText = strings.Replace(sqlText, "COMMIT;", `UPDATE judge.problem_versions SET first_published_at=now() WHERE id='00000000-0000-0000-0000-000000000011';
 UPDATE judge.platform_problems SET status='PUBLISHED',current_version_id='00000000-0000-0000-0000-000000000011',public_updated_at=now() WHERE id=1;
 UPDATE judge.catalog_state SET catalog_version=catalog_version+1,updated_at=now() WHERE singleton_id=1;
 COMMIT;`, 1)
	if _, err := db.Exec(sqlText); err != nil {
		t.Fatal("cannot seed complete synthetic qualified task fixture")
	}
}
