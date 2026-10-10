// SPDX-License-Identifier: Apache-2.0
package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestReviewStatementArtifactExactSchemaBoundsAndRedaction(t *testing.T) {
	digest := strings.Repeat("a", 64)
	valid := `{"ok":true,"errors":0,"warnings":1000000,"parentProcessDenied":true,"artifacts":{"kind":"HTML","manifestSha256":"` + digest + `","fileCount":4096,"fileBytes":268435456,"primarySha256":"` + digest + `","primaryBytes":67108864,"mathElements":1000000}}`
	if _, err := statementArtifactReport([]byte(valid), "HTML"); err != nil {
		t.Fatal("maximum bounded structural evidence rejected")
	}
	for _, fields := range [][]string{
		{"ok", "errors", "warnings", "parentProcessDenied", "artifacts"},
		{"kind", "manifestSha256", "fileCount", "fileBytes", "primarySha256", "primaryBytes", "mathElements"},
	} {
		for _, field := range fields {
			for _, variant := range []string{"missing", "null"} {
				t.Run(field+"/"+variant, func(t *testing.T) {
					var top map[string]any
					if json.Unmarshal([]byte(valid), &top) != nil {
						t.Fatal("invalid review fixture")
					}
					target := top
					if fields[0] == "kind" {
						target = top["artifacts"].(map[string]any)
					}
					if variant == "missing" {
						delete(target, field)
					} else {
						target[field] = nil
					}
					raw, _ := json.Marshal(top)
					if _, err := statementArtifactReport(raw, "HTML"); err == nil {
						t.Fatal("omitted/null required evidence accepted")
					}
				})
			}
		}
	}
	for _, raw := range []string{
		valid + `{}`,
		strings.Replace(valid, `"mathElements":1000000`, `"mathElements":1000000,"mathElements":0`, 1),
		strings.Replace(valid, `"warnings":1000000`, `"warnings":1000001`, 1),
		strings.Replace(valid, `"warnings":1000000`, `"warnings":-1`, 1),
		strings.Replace(valid, `"fileCount":4096`, `"fileCount":0`, 1),
		strings.Replace(valid, `"primaryBytes":67108864`, `"primaryBytes":67108865`, 1),
		strings.Replace(valid, `"primaryBytes":67108864`, `"primaryBytes":1.0`, 1),
		strings.Replace(valid, `"mathElements":1000000`, `"mathElements":1000001`, 1),
		strings.Replace(valid, `"manifestSha256":"`+digest+`"`, `"manifestSha256":"PRIVATE_FILENAME_CANARY"`, 1),
		strings.Replace(valid, `"ok":true`, `"ok":true,"privateLog":"PRIVATE_LOG_CANARY"`, 1),
		strings.Replace(valid, `"kind":"HTML"`, `"kind":"HTML","privatePath":"PRIVATE_PATH_CANARY"`, 1),
	} {
		if _, err := statementArtifactReport([]byte(raw), "HTML"); err == nil {
			t.Fatal("ambiguous, excessive or private report fields accepted")
		} else if strings.Contains(err.Error(), "PRIVATE_") {
			t.Fatal("private report bytes entered ordinary error")
		}
	}
	qualification := StatementQualification{RawLog: []byte("PRIVATE_STATEMENT_LOG_CANARY")}
	raw, err := json.Marshal(qualification)
	if err != nil || strings.Contains(string(raw), "PRIVATE_STATEMENT_LOG_CANARY") || strings.Contains(fmt.Sprintf("%+v %#v", qualification, qualification), "PRIVATE_STATEMENT_LOG_CANARY") {
		t.Fatal("private statement log entered structural DTO or formatting")
	}
}

func TestReviewStatementQualificationReadinessStopsBeforeSessionDispatch(t *testing.T) {
	a, factory, verifier, blobs := testAdapter(t)
	input := matureFixture(t, a, blobs)
	before := len(factory.requests)
	verifier.mu.Lock()
	verifier.fail = true
	verifier.mu.Unlock()
	if _, err := a.QualifyStatement(context.Background(), input.Manifest); err == nil || len(factory.requests) != before {
		t.Fatal("statement qualification dispatched after required isolation evidence failed")
	}
}
