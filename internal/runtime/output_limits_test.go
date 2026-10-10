// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/runtime/restclient"
)

type outputTransport func(*http.Request) (*http.Response, error)

func (f outputTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type outputWireError struct {
	Name, Type, Message string
}

// Exercise the real private REST decoder/projection before role classification.
// Wire observations are synthetic; no authored source executes on this host.
func TestProjectedOutputCapsRespectRolesAndFailurePrecedence(t *testing.T) {
	collector := outputWireError{"stdout", "CollectSizeExceeded", "Output Limit Exceeded"}
	for _, tc := range []struct {
		name     string
		status   restclient.Status
		exit     int
		outer    string
		failures []outputWireError
		user     contract.JudgeVerdict
		compiler contract.JudgeVerdict
	}{
		{"finite stdout", restclient.OutputLimit, 0, "Output Limit Exceeded", []outputWireError{collector}, contract.VerdictOLE, contract.VerdictCE},
		{"finite stderr", restclient.OutputLimit, 0, "Output Limit Exceeded", []outputWireError{{"stderr", "CollectSizeExceeded", "Output Limit Exceeded"}}, contract.VerdictOLE, contract.VerdictCE},
		{"both finite streams", restclient.OutputLimit, 0, "Output Limit Exceeded", []outputWireError{collector, {"stderr", "CollectSizeExceeded", "Output Limit Exceeded"}}, contract.VerdictOLE, contract.VerdictCE},
		{"collector then cpu limit", restclient.TimeLimit, 9, "", []outputWireError{collector}, contract.VerdictOLE, contract.VerdictCE},
		{"collector then memory limit", restclient.MemoryLimit, 0, "", []outputWireError{collector}, contract.VerdictOLE, contract.VerdictCE},
		{"collector then signal", restclient.Signalled, 9, "", []outputWireError{collector}, contract.VerdictOLE, contract.VerdictCE},
		{"requested cached size cap", restclient.FileError, 0, "", []outputWireError{{"stdout", "CopyOutSizeExceeded", "private-diagnostic-canary"}}, contract.VerdictOLE, contract.VerdictCE},
		{"dynamic copyout error remains infrastructure", restclient.FileError, 0, "private-diagnostic-canary", []outputWireError{{"stdout", "CopyOutSizeExceeded", "private-diagnostic-canary"}}, contract.VerdictIE, contract.VerdictIE},
		{"unrelated outer error", restclient.OutputLimit, 0, "private-diagnostic-canary", []outputWireError{collector}, contract.VerdictIE, contract.VerdictIE},
		{"unrelated collector message", restclient.OutputLimit, 0, "Output Limit Exceeded", []outputWireError{{"stdout", "CollectSizeExceeded", "private-diagnostic-canary"}}, contract.VerdictIE, contract.VerdictIE},
		{"unrequested target", restclient.OutputLimit, 0, "Output Limit Exceeded", []outputWireError{{"private/target-canary", "CollectSizeExceeded", "Output Limit Exceeded"}}, contract.VerdictIE, contract.VerdictIE},
		{"mixed collection and open failure", restclient.OutputLimit, 0, "Output Limit Exceeded", []outputWireError{collector, {"stderr", "CopyOutOpen", "private-diagnostic-canary"}}, contract.VerdictIE, contract.VerdictIE},
		{"mixed collection and write failure", restclient.OutputLimit, 0, "Output Limit Exceeded", []outputWireError{collector, {"stderr", "CopyOutCopyContent", "private-diagnostic-canary"}}, contract.VerdictIE, contract.VerdictIE},
		{"missing collector proof", restclient.OutputLimit, 0, "Output Limit Exceeded", nil, contract.VerdictIE, contract.VerdictIE},
		{"ordinary cpu limit", restclient.TimeLimit, 9, "", nil, contract.VerdictTLE, contract.VerdictCE},
		{"ordinary memory limit", restclient.MemoryLimit, 0, "", nil, contract.VerdictMLE, contract.VerdictCE},
		{"ordinary user exit", restclient.NonzeroExit, 2, "", nil, contract.VerdictRE, contract.VerdictCE},
		{"compiler launch failure", restclient.NonzeroExit, 127, "", []outputWireError{collector}, contract.VerdictOLE, contract.VerdictIE},
		{"checker accepted exit with cap", restclient.NonzeroExit, 42, "", []outputWireError{collector}, contract.VerdictOLE, contract.VerdictCE},
		{"checker wrong-answer exit with cap", restclient.NonzeroExit, 43, "", []outputWireError{collector}, contract.VerdictOLE, contract.VerdictCE},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := projectOutputWireResult(t, tc.status, tc.exit, tc.outer, tc.failures)
			compiler, _ := compilerVerdict(r)
			if contestantVerdict(r) != tc.user || compiler != tc.compiler || checkerVerdict(r) != contract.VerdictIE {
				t.Fatal("private projected result changed role or infrastructure precedence")
			}
			if r.Status != tc.status || r.ExitStatus != tc.exit || r.CPUTimeNS != 123 || r.WallTimeNS != 789 || r.MemoryBytes != 456 || r.HasError != (tc.outer != "") {
				t.Fatal("output classification rewrote original sandbox observations")
			}
		})
	}
	for _, status := range []restclient.Status{restclient.Invalid, restclient.InternalError, restclient.JudgementFailed, restclient.InvalidInteraction, restclient.WrongAnswer, restclient.PartiallyCorrect} {
		t.Run("fatal precedence "+string(status), func(t *testing.T) {
			r := projectOutputWireResult(t, status, 0, "", []outputWireError{collector})
			compiler, _ := compilerVerdict(r)
			if !r.RequestedOutputSizeExceeded || contestantVerdict(r) != contract.VerdictIE || compiler != contract.VerdictIE || checkerVerdict(r) != contract.VerdictIE {
				t.Fatal("output-size fact masked a fatal or impossible role status")
			}
		})
	}
	valid := projectOutputWireResult(t, restclient.TimeLimit, 9, "", []outputWireError{collector})
	for _, mutate := range []func(*restclient.Result){
		func(r *restclient.Result) { r.FileErrorCount++ },
		func(r *restclient.Result) { r.FileErrorTypes = nil },
		func(r *restclient.Result) { r.FileErrorTypes[0] = restclient.CopyOutOpen },
		func(r *restclient.Result) { r.Status = "unknown" },
		func(r *restclient.Result) { r.RequestedOutputSizeExceeded = false },
	} {
		r := valid
		r.FileErrorTypes = append([]restclient.FileErrorType(nil), valid.FileErrorTypes...)
		mutate(&r)
		compiler, _ := compilerVerdict(r)
		if contestantVerdict(r) != contract.VerdictIE || compiler != contract.VerdictIE {
			t.Fatal("malformed or absent structural evidence qualified as an output cap")
		}
	}
}

func projectOutputWireResult(t *testing.T, status restclient.Status, exit int, outer string, failures []outputWireError) restclient.Result {
	t.Helper()
	client, err := restclient.New(restclient.Options{Token: strings.Repeat("r", 64), RoundTripper: outputTransport(func(_ *http.Request) (*http.Response, error) {
		response := httptest.NewRecorder()
		writeOutputWire(t, response, status, exit, outer, failures, nil)
		return response.Result(), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	request := restclient.Request{RequestID: "output-role-proof", Commands: []restclient.Command{command([]string{"/w/main"}, "ABCD2345", nil, Limits{CPUTimeNS: 1000, WallTimeNS: 2000, MemoryBytes: 1 << 20, OutputBytes: 64, Processes: 8})}}
	results, err := client.Run(context.Background(), request)
	if err != nil || len(results) != 1 {
		t.Fatal("synthetic role response rejected by private REST boundary", err)
	}
	return results[0]
}

func writeOutputWire(t *testing.T, w http.ResponseWriter, status restclient.Status, exit int, outer string, failures []outputWireError, files map[string]restclient.FileID) {
	t.Helper()
	errors := make([]map[string]string, 0, len(failures))
	for _, failure := range failures {
		errors = append(errors, map[string]string{"name": failure.Name, "type": failure.Type, "message": failure.Message})
	}
	if err := json.NewEncoder(w).Encode([]map[string]any{{"status": status, "exitStatus": exit, "error": outer, "time": 123, "memory": 456, "runTime": 789, "fileError": errors, "fileIds": files}}); err != nil {
		t.Fatal("bounded synthetic wire could not be encoded")
	}
}

func TestOutputOverflowStopsExecutionAndReclaimsAcknowledgedCache(t *testing.T) {
	for _, role := range []string{"contestant", "compiler", "checker", "mature", "validator"} {
		t.Run(role, func(t *testing.T) {
			a, _, _, blobs := testAdapter(t)
			allocated, deleted := map[restclient.FileID]bool{}, map[restclient.FileID]int{}
			next, runs, checkers := byte(0), 0, 0
			newID := func() restclient.FileID {
				next++
				id := restclient.FileID(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte{0, 0, 0, 0, next}))
				allocated[id] = true
				return id
			}
			client, err := restclient.New(restclient.Options{Token: strings.Repeat("r", 64), RoundTripper: outputTransport(func(request *http.Request) (*http.Response, error) {
				response := httptest.NewRecorder()
				switch {
				case request.Method == http.MethodPost && request.URL.Path == "/file":
					fmt.Fprintf(response, "%q", newID())
				case request.Method == http.MethodDelete:
					deleted[restclient.FileID(strings.TrimPrefix(request.URL.Path, "/file/"))]++
				case request.Method == http.MethodGet:
					response.Write([]byte{0x7f, 'E', 'L', 'F', 0})
				case request.URL.Path == "/run":
					runs++
					var body struct {
						Commands []struct {
							Args          []string `json:"args"`
							CopyOutCached []string `json:"copyOutCached"`
						} `json:"cmd"`
					}
					if json.NewDecoder(request.Body).Decode(&body) != nil || len(body.Commands) != 1 {
						t.Fatal("owned output fixture request changed")
					}
					files := map[string]restclient.FileID{}
					for _, name := range body.Commands[0].CopyOutCached {
						files[strings.TrimSuffix(name, "?")] = newID()
					}
					compile := body.Commands[0].Args[0] == "/usr/bin/g++"
					if strings.Contains(body.Commands[0].Args[0], "checker") {
						checkers++
					}
					if role == "compiler" || !compile {
						writeOutputWire(t, response, restclient.OutputLimit, 0, "Output Limit Exceeded", []outputWireError{{"stdout", "CollectSizeExceeded", "Output Limit Exceeded"}}, files)
					} else {
						writeOutputWire(t, response, restclient.Accepted, 0, "", nil, files)
					}
				default:
					t.Fatal("unexpected runtime fixture route")
				}
				return response.Result(), nil
			})})
			if err != nil {
				t.Fatal(err)
			}
			a.factory = restFactory{client}
			if role == "checker" {
				verdict, status, err := a.checkBytes(context.Background(), "checker/overflow", []byte("5\n"), []byte("2 3\n"), []byte("5\n"), DefaultChecker())
				if err != nil || verdict != contract.VerdictIE || status != restclient.OutputLimit || runs != 1 || checkers != 1 {
					t.Fatal("checker output cap became a user result", err)
				}
			} else if role == "mature" {
				_, err = a.matureRunBytes(context.Background(), "mature/overflow", []string{"/w/main"}, nil, map[string][]byte{"main": {0x7f, 'E', 'L', 'F'}}, compilerLimits())
				var failure *Failure
				if !errors.As(err, &failure) || failure.Code != "MATURE_SANDBOX_INFRASTRUCTURE_FAILED" || runs != 1 {
					t.Fatal("mature tool overflow was accepted as a successful role", err)
				}
			} else if role == "validator" {
				input := matureFixture(t, a, blobs)
				programInput, err := ValidationFromManifest(input.JobID, input.ItemID, input.FencingToken, input.Identity, input.Manifest)
				if err != nil {
					t.Fatal(err)
				}
				result, err := a.ValidatePrograms(context.Background(), programInput)
				if err != nil || result.ValidatorsPassed || len(result.ValidatorCases) == 0 {
					t.Fatal("validator output cap did not fail technical validation", err)
				}
				for _, evidence := range result.ValidatorCases {
					if evidence.Passed || evidence.Verdict != contract.VerdictIE || evidence.DiagnosticCode != "INPUT_VALIDATOR_FAILED" {
						t.Fatal("validator output cap became a contestant verdict")
					}
				}
				if result.ReferencesPassed || len(result.ReferenceCases) == 0 {
					t.Fatal("accepted-reference overflow did not fail technical validation")
				}
				for _, evidence := range result.ReferenceCases {
					if evidence.Passed || evidence.DiagnosticCode != "ACCEPTED_REFERENCE_FAILED" {
						t.Fatal("accepted-reference overflow was accepted as package qualification")
					}
				}
			} else {
				task := testTask(a, blobs, 1)
				result, err := a.Execute(context.Background(), task, nil)
				want, wantRuns := contract.VerdictOLE, 2
				if role == "compiler" {
					want, wantRuns = contract.VerdictCE, 1
				}
				if err != nil || result.Result.Verdict != want || runs != wantRuns || checkers != 0 {
					t.Fatalf("overflow did not stop before contestant/checker work: verdict=%s runs=%d checkers=%d error=%v", result.Result.Verdict, runs, checkers, err)
				}
				if role == "contestant" && (len(result.Cases) != 1 || result.Cases[0].CPUTimeNS != 123 || result.Cases[0].WallTimeNS != 789 || result.Cases[0].MemoryBytes != 456 || result.Cases[0].SandboxStatus != restclient.OutputLimit) {
					t.Fatal("contestant OLE lost original case observations")
				}
			}
			for id := range allocated {
				if deleted[id] != 1 {
					t.Fatal("overflow leaked or multiply deleted an acknowledged cached file")
				}
			}
			if len(allocated) != len(deleted) || len(allocated) == 0 {
				t.Fatal("overflow cleanup omitted acknowledged cache or deleted an unrelated ID")
			}
		})
	}
}
