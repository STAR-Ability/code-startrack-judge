// SPDX-License-Identifier: Apache-2.0

package restclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestOutputSizeFactsBindToFrozenRequestedTargets(t *testing.T) {
	for _, tc := range []struct {
		name, target, kind, outer, message string
		pipe, requested, size, fixed       bool
	}{
		{"finite stdout", "stdout", "CollectSizeExceeded", "Output Limit Exceeded", "Output Limit Exceeded", true, true, true, true},
		{"finite stderr", "stderr", "CollectSizeExceeded", "Output Limit Exceeded", "Output Limit Exceeded", true, true, true, true},
		{"drained collector", "stdout", "CollectSizeExceeded", "", "Output Limit Exceeded", true, true, true, false},
		{"unrelated outer error", "stdout", "CollectSizeExceeded", "private-error-canary", "Output Limit Exceeded", true, true, true, false},
		{"unrelated collector message", "stdout", "CollectSizeExceeded", "Output Limit Exceeded", "private-error-canary", true, true, true, false},
		{"nonpipe collector", "stdout", "CollectSizeExceeded", "Output Limit Exceeded", "Output Limit Exceeded", false, true, false, false},
		{"unrequested collector", "private/output-canary", "CollectSizeExceeded", "Output Limit Exceeded", "Output Limit Exceeded", true, false, false, false},
		{"requested copyout cap", "main", "CopyOutSizeExceeded", "", "private-error-canary", true, true, true, false},
		{"dynamic copyout error", "main", "CopyOutSizeExceeded", "private-error-canary", "private-error-canary", true, true, true, false},
		{"unrequested copyout", "private/output-canary", "CopyOutSizeExceeded", "", "private-error-canary", true, false, false, false},
		{"ordinary file error", "stdout", "CopyOutOpen", "", "private-error-canary", true, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := fixtureRequest()
			request.Commands[0].Files[1].CollectPipe, request.Commands[0].Files[2].CollectPipe = tc.pipe, tc.pipe
			if tc.target == "main" && tc.requested {
				request.Commands[0].CopyOutCached = append(request.Commands[0].CopyOutCached, Output{Name: "main", Optional: true})
			}
			client := mockClient(t, Limits{}, func(w http.ResponseWriter, _ *http.Request) {
				_, _ = fmt.Fprintf(w, `[{"status":"Output Limit Exceeded","exitStatus":9,"time":123,"memory":456,"runTime":789,"error":%q,"fileError":[{"name":%q,"type":%q,"message":%q}]}]`, tc.outer, tc.target, tc.kind, tc.message)
			})
			results, err := client.Run(context.Background(), request)
			if err != nil || len(results) != 1 {
				t.Fatal("bounded structural response failed", err)
			}
			r := results[0]
			if r.RequestedOutputSizeExceeded != tc.size || r.CollectorOutputLimitError != tc.fixed || r.HasError != (tc.outer != "") || r.FileErrorCount != 1 || r.ExitStatus != 9 || r.CPUTimeNS != 123 || r.MemoryBytes != 456 || r.WallTimeNS != 789 {
				t.Fatal("output facts or original observations changed")
			}
			encoded, err := json.Marshal(r)
			if err != nil || strings.Contains(string(encoded), "private-") || strings.Contains(fmt.Sprintf("%#v", r), "private-") || strings.Contains(string(encoded), "message") || strings.Contains(string(encoded), "name") {
				t.Fatal("output fact retained a raw failure target or diagnostic")
			}
		})
	}
	for _, target := range []string{"stdout", "changed-output"} {
		t.Run("in-flight request mutation "+target, func(t *testing.T) {
			request := fixtureRequest()
			request.Commands[0].Files[1].CollectPipe = true
			client := mockClient(t, Limits{}, func(w http.ResponseWriter, r *http.Request) {
				var wire struct {
					Commands []struct {
						Files         []wireFile `json:"files"`
						CopyOutCached []string   `json:"copyOutCached"`
					} `json:"cmd"`
				}
				if json.NewDecoder(r.Body).Decode(&wire) != nil || *wire.Commands[0].Files[1].Name != "stdout" || wire.Commands[0].CopyOutCached[0] != "stdout" {
					t.Fatal("request was changed before dispatch")
				}
				request.Commands[0].CopyOutCached[0].Name = "changed-output"
				request.Commands[0].Files[1].Collector = "changed-output"
				request.Commands[0].CopyIn["main.cc"] = stdoutID
				_, _ = fmt.Fprintf(w, `[{"status":"Output Limit Exceeded","exitStatus":0,"time":1,"memory":2,"runTime":3,"error":"Output Limit Exceeded","fileError":[{"name":%q,"type":"CollectSizeExceeded","message":"Output Limit Exceeded"}]}]`, target)
			})
			results, err := client.Run(context.Background(), request)
			if err != nil || len(results) != 1 || results[0].RequestedOutputSizeExceeded != (target == "stdout") || results[0].CollectorOutputLimitError != (target == "stdout") {
				t.Fatal("response facts bound to a mutated request instead of dispatched targets", err)
			}
		})
	}
}

func TestMixedFileErrorsNeverBecomeOutputOnlyFacts(t *testing.T) {
	for _, kind := range []FileErrorType{CopyInOpenFile, CopyInCreateDir, CopyInCreateFile, CopyInCopyContent, CopyOutOpen, CopyOutNotRegularFile, CopyOutCreateFile, CopyOutCopyContent, Symlink} {
		t.Run(string(kind), func(t *testing.T) {
			request := fixtureRequest()
			request.Commands[0].Files[1].CollectPipe, request.Commands[0].Files[2].CollectPipe = true, true
			client := mockClient(t, Limits{}, func(w http.ResponseWriter, _ *http.Request) {
				_, _ = fmt.Fprintf(w, `[{"status":"Output Limit Exceeded","exitStatus":0,"time":1,"memory":2,"runTime":3,"error":"Output Limit Exceeded","fileError":[{"name":"stdout","type":"CollectSizeExceeded","message":"Output Limit Exceeded"},{"name":"stderr","type":%q,"message":"private-error-canary"}]}]`, kind)
			})
			results, err := client.Run(context.Background(), request)
			if err != nil || len(results) != 1 || !results[0].HasError || results[0].FileErrorCount != 2 || results[0].RequestedOutputSizeExceeded || results[0].CollectorOutputLimitError {
				t.Fatal("mixed infrastructure failure qualified as output-only", err)
			}
		})
	}
}
