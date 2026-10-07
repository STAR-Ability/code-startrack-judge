// SPDX-License-Identifier: Apache-2.0
package runtime

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/packages"
	"github.com/STAR-Ability/code-startrack-judge/internal/runtime/restclient"
)

type matureRunnerFunc func(context.Context, MatureInput, BlobReader, MatureHandler) (MatureOutcome, error)

func (f matureRunnerFunc) Run(ctx context.Context, in MatureInput, reader BlobReader, h MatureHandler) (MatureOutcome, error) {
	return f(ctx, in, reader, h)
}
func matureFixture(t *testing.T, a *Adapter, blobs memoryBlobs) MatureInput {
	t.Helper()
	artifact, e := packages.Adapt(packages.PinnedSource("problems/private-runtime-fixture"), []packages.File{
		{Path: "problem.yaml", Data: []byte("name: Mature fixture\n")}, {Path: ".timelimit", Data: []byte("1.250")},
		{Path: "problem_statement/problem.md", Data: []byte("Portable statement")}, {Path: "problem_statement/asset.bin", Data: []byte("public asset")},
		{Path: "data/sample/1.in", Data: []byte("public input")}, {Path: "data/sample/1.ans", Data: []byte("public answer")},
		{Path: "data/secret/2.in", Data: []byte("HIDDEN_INPUT")}, {Path: "data/secret/2.ans", Data: []byte("HIDDEN_ANSWER")},
		{Path: "input_validators/main.cpp", Data: []byte("inert validator")}, {Path: "submissions/accepted/main.cpp", Data: []byte("inert reference")},
		{Path: "submissions/wrong_answer/other.cpp", Data: []byte("inert wrong reference")},
	})
	if e != nil {
		t.Fatal(e)
	}
	for _, file := range artifact.NormalizedFiles {
		blobs[canonical.HashBytes(file.Data)] = bytes.Clone(file.Data)
	}
	// This is an explicit portable control-flow seam, never real qualification.
	a.grader = []byte("mock original grader")
	a.mu.Lock()
	a.matureReady = true
	a.mu.Unlock()
	return MatureInput{JobID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", ItemID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", FencingToken: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", Identity: a.identity, Manifest: *artifact.Manifest}
}
func completeMatureOutcome() MatureOutcome {
	out := MatureOutcome{Completed: true, RawLog: []byte("PRIVATE_TOOL_LOG")}
	for _, p := range []string{"STRUCTURE", "STATEMENT", "TEST_DATA", "VALIDATORS", "REFERENCES"} {
		out.Parts = append(out.Parts, MaturePartOutcome{Part: p, Passed: true})
	}
	return out
}

func TestMatureProtocolSeparatesRolesAndCachesCompilation(t *testing.T) {
	a, f, _, blobs := testAdapter(t)
	input := matureFixture(t, a, blobs)
	start := len(f.requests)
	a.matureRunner = matureRunnerFunc(func(ctx context.Context, in MatureInput, reader BlobReader, h MatureHandler) (MatureOutcome, error) {
		for _, p := range in.Manifest.ReferenceSolutions {
			for i := 0; i < 2; i++ {
				out, e := h(ctx, MatureRequest{Operation: "COMPILE", ProgramPath: p.File.Path})
				if e != nil || !out.Compiled {
					t.Fatalf("frozen compile failed: %v", e)
				}
			}
			if _, e := h(ctx, MatureRequest{Operation: "RUN_REFERENCE", ProgramPath: p.File.Path, Ordinal: 2}); e != nil {
				return MatureOutcome{}, e
			}
		}
		p := in.Manifest.InputValidators[0]
		if _, e := h(ctx, MatureRequest{Operation: "COMPILE", ProgramPath: p.File.Path}); e != nil {
			return MatureOutcome{}, e
		}
		mutation := []byte{0xff, 0, 1, 'x'}
		if _, e := h(ctx, MatureRequest{Operation: "RUN_VALIDATOR", ProgramPath: p.File.Path, InputBase64: base64.StdEncoding.EncodeToString(mutation)}); e != nil {
			return MatureOutcome{}, e
		}
		for _, bad := range []MatureRequest{{Operation: "COMPILE", ProgramPath: "/etc/passwd"}, {Operation: "RUN_VALIDATOR", ProgramPath: in.Manifest.ReferenceSolutions[0].File.Path}, {Operation: "RUN_REFERENCE", ProgramPath: p.File.Path, Ordinal: 1}, {Operation: "CHECK_OUTPUT", Ordinal: 99}, {Operation: "GRADE", ProgramPath: "caller-script"}, {Operation: "SHELL"}} {
			before := len(f.requests)
			if _, e := h(ctx, bad); e == nil {
				t.Fatalf("unsafe native operation accepted: %s", bad.Operation)
			}
			if len(f.requests) != before {
				t.Fatal("invalid operation reached sandbox")
			}
		}
		out, e := h(ctx, MatureRequest{Operation: "CHECK_OUTPUT", Ordinal: 2, OutputBase64: base64.StdEncoding.EncodeToString([]byte("answer"))})
		if e != nil || out.WaitStatus != 42<<8 {
			t.Fatalf("checker status lost: %v", e)
		}
		return completeMatureOutcome(), nil
	})
	out, e := a.RunMature(context.Background(), input)
	if e != nil || !out.Completed {
		t.Fatal(e)
	}
	compileCount := 0
	for _, r := range f.requests[start:] {
		c := r.request.Commands[0]
		if c.Args[0] == "/usr/bin/g++" {
			compileCount++
			continue
		}
		if c.Args[0] == "/w/main" {
			if len(r.inputs) != 1 || r.inputs["main"] == nil {
				t.Fatal("program received sibling source or answer")
			}
		} else if c.Args[0] == "/usr/local/bin/startrack-checker-launcher" {
			if len(r.inputs) != 3 || string(r.inputs["answer"]) != "HIDDEN_ANSWER" {
				t.Fatal("checker did not receive exact frozen private answer")
			}
		}
	}
	if compileCount != 3 {
		t.Fatalf("compiled %d times; exact source cache should compile each role once", compileCount)
	}
	if _, e := a.RunMature(context.Background(), input); e == nil {
		t.Fatal("mature import step executed twice under same fence")
	}
	if strings.Contains(fmt.Sprintf("%+v", out), "PRIVATE_TOOL_LOG") {
		t.Fatal("private mature log leaked by ordinary formatting")
	}
}

func TestMatureStatementBundleContainsOnlyPublicStatementScope(t *testing.T) {
	a, _, _, blobs := testAdapter(t)
	input := matureFixture(t, a, blobs)
	chunks, e := a.matureStatementFiles(context.Background(), input.Manifest)
	if e != nil {
		t.Fatal(e)
	}
	keys := make([]string, 0, len(chunks))
	for key := range chunks {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	readers := []io.Reader{}
	for i, key := range keys {
		if key != fmt.Sprintf("statement.%06d.tarpart", i+1) || len(chunks[key]) > MaxFileBytes {
			t.Fatal("unsafe statement bundle chunk")
		}
		readers = append(readers, bytes.NewReader(chunks[key]))
	}
	archive := tar.NewReader(io.MultiReader(readers...))
	found := map[string]bool{}
	for {
		h, e := archive.Next()
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		raw, e := io.ReadAll(archive)
		if e != nil {
			t.Fatal(e)
		}
		if strings.Contains(h.Name, "secret") || strings.Contains(h.Name, "submissions") || strings.Contains(h.Name, "input_validators") || bytes.Contains(raw, []byte("HIDDEN_")) {
			t.Fatal("statement converter received private execution artifacts")
		}
		found[h.Name] = true
	}
	for _, path := range []string{"problem/problem.yaml", "problem/problem_statement/problem.en.tex", "problem/problem_statement/asset.bin", "problem/data/sample/1.in", "problem/data/sample/1.ans"} {
		if !found[path] {
			t.Fatalf("statement artifact omitted: %s", path)
		}
	}
}

func TestMaturePrivateFailureLogsCrossAuthenticatedScheduler(t *testing.T) {
	c, a, _, blobs, _ := schedulerFixture(t)
	input := matureFixture(t, a, blobs)
	a.matureRunner = matureRunnerFunc(func(context.Context, MatureInput, BlobReader, MatureHandler) (MatureOutcome, error) {
		return MatureOutcome{RawLog: []byte("PRIVATE_TOOL_FAILURE")}, failure("MATURE_HELPER_FAILED", false)
	})
	out, e := c.RunMature(context.Background(), input)
	if e == nil || string(out.RawLog) != "PRIVATE_TOOL_FAILURE" || strings.Contains(e.Error(), "PRIVATE_TOOL_FAILURE") {
		t.Fatal("failed helper private evidence was lost or exposed")
	}
}

func TestSchedulerPanicAbortsWithoutPrivatePanicLog(t *testing.T) {
	a, _, _, blobs := testAdapter(t)
	input := matureFixture(t, a, blobs)
	a.matureRunner = matureRunnerFunc(func(context.Context, MatureInput, BlobReader, MatureHandler) (MatureOutcome, error) {
		panic("CREDENTIAL_PRIVATE_PANIC_CANARY")
	})
	token := "scheduler-credential-abcdefghijklmnopqrstuvwxyz"
	handler, e := NewSchedulerServer(a, token, privateTempDir(t))
	if e != nil {
		t.Fatal(e)
	}
	var logs bytes.Buffer
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(&logs, "", 0)
	server.Start()
	defer server.Close()
	base, _ := url.Parse(server.URL)
	c, e := newSchedulerClient(token, blobs, testRouteTransport{base: base, next: http.DefaultTransport})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, e := c.RunMature(ctx, input); e == nil {
		t.Fatal("panicked private execution reported success")
	}
	if logs.Len() != 0 || a.Snapshot(ctx).Qualified {
		t.Fatal("private panic was logged or readiness survived")
	}
}

func TestMatureOutcomeRequiresCompletedCheckpointFacts(t *testing.T) {
	out := completeMatureOutcome()
	out.Parts[1].Passed = false
	if out.valid() {
		t.Fatal("zero errors substituted for missing statement checkpoint")
	}
	out.Parts[1].NotRun = true
	if !out.valid() {
		t.Fatal("explicit not-run evidence rejected")
	}
	out.Errors = 1
	if out.valid() {
		t.Fatal("aggregate counts did not reconcile with exact parts")
	}
	if _, e := decodeMatureBytes("YWFhYQ==", 3); e == nil {
		t.Fatal("decoded input exceeded native limit")
	}
	var request MatureRequest
	if strictDecode([]byte(`{"operation":"GRADE","args":["arbitrary"]}`), &request) == nil {
		t.Fatal("arbitrary caller argv was accepted")
	}
	if (MatureInput{JobID: contract.UUID("invalid")}).valid() {
		t.Fatal("unfenced mature work accepted")
	}
}

func TestMatureTimeLimitProjectionPreservesExactCPUAndWallFacts(t *testing.T) {
	for _, r := range []restclient.Result{{Status: restclient.TimeLimit, CPUTimeNS: 500000000, WallTimeNS: 510000000, ExitStatus: 9}, {Status: restclient.TimeLimit, CPUTimeNS: 1000000, WallTimeNS: 1000000000, ExitStatus: 9}} {
		before := r
		if matureWaitStatus(r) != 24 || r.CPUTimeNS != before.CPUTimeNS || r.WallTimeNS != before.WallTimeNS || r.ExitStatus != before.ExitStatus || r.Status != before.Status {
			t.Fatal("real time-limit status/measurements were changed or mature TLE became runtime error")
		}
	}
}
