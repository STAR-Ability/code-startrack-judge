// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/packages"
	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
)

type privateLogEvidence struct {
	SHA256         string `json:"sha256"`
	Bytes          int    `json:"bytes"`
	RetainedSHA256 string `json:"retainedSha256"`
	RetainedBytes  int    `json:"retainedBytes"`
	Truncated      bool   `json:"truncated"`
}
type matureEvidence struct {
	Name        string                           `json:"name"`
	Passed      bool                             `json:"passed"`
	Completed   bool                             `json:"completed"`
	Parts       []judgeruntime.MaturePartOutcome `json:"parts"`
	Errors      int                              `json:"errors"`
	Warnings    int                              `json:"warnings"`
	PrivateLog  privateLogEvidence               `json:"privateLog"`
	FailureCode string                           `json:"failureCode,omitempty"`
}
type statementEvidence struct {
	Passed              bool                                     `json:"passed"`
	ParentProcessDenied bool                                     `json:"parentProcessDenied"`
	Artifacts           []judgeruntime.StatementArtifactEvidence `json:"artifacts"`
	Workspaces          []judgeruntime.StatementWorkspaceFacts   `json:"workspaces"`
	PrivateLog          privateLogEvidence                       `json:"privateLog"`
	FailureCode         string                                   `json:"failureCode,omitempty"`
}

func runMatureMatrix(ctx context.Context, adapter *judgeruntime.Adapter, blobs *matrixBlobs, factory *matrixFactory, report *matrixReport) error {
	// These are authored qualification fixtures. The pinned source namespace is
	// required by the manifest protocol; no repository/import provenance claim is
	// made for synthetic files, and they can never be published by this command.
	fixtures := []struct {
		name, validator, accepted, failedPart string
	}{
		{"ALL_PARTS", inputValidatorProgram, sumProgram, ""},
		// At the pinned revision, check_testdata reports non-42 testcase exits
		// through its data diagnostic; validator sanity accepts non-42 junk exits.
		{"VALIDATOR_EXIT_ZERO", "int main(){return 0;}\n", sumProgram, "TEST_DATA"},
		{"ACCEPTED_REFERENCE_WRONG", inputValidatorProgram, printProgram("6"), "REFERENCES"},
	}
	var positive packages.Manifest
	for i, fixture := range fixtures {
		manifest, e := matureMatrixManifest(blobs, fixture.validator, fixture.accepted)
		if e != nil {
			return e
		}
		if i == 0 {
			positive = manifest
		}
		if adapter.Qualify(ctx) != nil {
			return errors.New("mature matrix refresh failed")
		}
		input := judgeruntime.MatureInput{JobID: matrixUUID(1000 + i*3), ItemID: matrixUUID(1001 + i*3), FencingToken: matrixUUID(1002 + i*3), Identity: adapter.Identity(), Manifest: manifest}
		out, runErr := adapter.RunMature(ctx, input)
		log, logErr := retainMatrixLog(fixture.name, out.RawLog)
		ev := matureEvidence{Name: fixture.name, Completed: out.Completed, Parts: out.Parts, Errors: out.Errors, Warnings: out.Warnings, PrivateLog: log}
		if runErr != nil {
			ev.FailureCode = "MATURE_RUN_FAILED"
			var failure *judgeruntime.Failure
			if errors.As(runErr, &failure) {
				ev.FailureCode = failure.Code
			}
		}
		allPassed, failedExpected, otherPartsPassed := len(out.Parts) == 5, false, true
		for _, part := range out.Parts {
			allPassed = allPassed && part.Passed && !part.NotRun && part.Errors == 0
			if part.Part == fixture.failedPart && !part.Passed && !part.NotRun && part.Errors > 0 {
				failedExpected = true
			}
			if part.Part != fixture.failedPart {
				otherPartsPassed = otherPartsPassed && part.Passed && !part.NotRun && part.Errors == 0
			}
		}
		ev.Passed = runErr == nil && logErr == nil && out.Completed && len(out.Parts) == 5
		if fixture.failedPart == "" {
			ev.Passed = ev.Passed && allPassed && out.Errors == 0
		} else {
			ev.Passed = ev.Passed && !allPassed && failedExpected && otherPartsPassed && out.Errors > 0 && len(out.RawLog) > 0
		}
		report.Mature = append(report.Mature, ev)
		if !ev.Passed {
			return errors.New("real mature helper matrix mismatch")
		}
		if i == 0 {
			before := factory.opened.Load()
			_, duplicate := adapter.RunMature(ctx, input)
			report.MatureDuplicateFenceRejected = duplicate != nil && factory.opened.Load() == before
			if !report.MatureDuplicateFenceRejected {
				return errors.New("mature matrix fence reused")
			}
		}
	}
	// Production Adapt escapes Markdown into a safe plain TeX view. This authored
	// qualification-only view adds native math to prove the exact original HTML
	// MathJax-source representation and sanitized PDF artifact paths. Its frozen
	// mapping and bytes are updated together; production adaptation is unchanged.
	math := []byte("\\problemname{Runtime helper qualification}\nCompute $a+b$ for two integers.\n\\[\\frac{a^2+b^2}{c^2}=1\\]\n")
	ref := blobs.add(math)
	positive.Statement.ValidationView.SHA256 = ref.SHA256
	positive.Statement.ValidationView.SizeBytes = ref.SizeBytes
	for i := range positive.Files {
		if positive.Files[i].NormalizedPath == positive.Statement.ValidationView.Path {
			positive.Files[i].NormalizedSHA256 = ref.SHA256
			positive.Files[i].NormalizedSizeBytes = ref.SizeBytes
		}
	}
	if packages.ValidateManifest(positive) != nil || adapter.Qualify(ctx) != nil {
		return errors.New("statement matrix fixture invalid")
	}
	statement, statementErr := adapter.QualifyStatement(ctx, positive)
	log, logErr := retainMatrixLog("STATEMENT_ARTIFACTS", statement.RawLog)
	report.Statement = statementEvidence{Artifacts: statement.Artifacts, Workspaces: statement.Workspaces, ParentProcessDenied: statement.ParentProcessDenied, PrivateLog: log}
	if statementErr != nil {
		report.Statement.FailureCode = "STATEMENT_QUALIFICATION_FAILED"
		var failure *judgeruntime.Failure
		if errors.As(statementErr, &failure) {
			report.Statement.FailureCode = failure.Code
		}
	}
	report.Statement.Passed = statementErr == nil && logErr == nil && statement.ParentProcessDenied && len(statement.Artifacts) == 2 && statement.Artifacts[0].Kind == "PDF" && statement.Artifacts[1].Kind == "HTML" && statement.Artifacts[1].MathElements > 0
	if !report.Statement.Passed {
		return errors.New("real original statement artifact qualification failed")
	}
	return nil
}

func matureMatrixManifest(blobs *matrixBlobs, validator, accepted string) (packages.Manifest, error) {
	artifact, e := packages.Adapt(packages.PinnedSource("problems/synthetic-runtime-qualification"), []packages.File{
		{Path: "problem.yaml", Data: []byte("name: Runtime helper qualification\nlimits:\n  memory: 64\n  output: 8\n")},
		{Path: ".timelimit", Data: []byte("0.500\n")},
		{Path: "problem_statement/problem.en.md", Data: []byte("Compute the sum of two positive integers, each at most 99. Input is two integers separated by one space and a newline. Output their sum and a newline.\n")},
		{Path: "data/sample/1.in", Data: []byte("2 3\n")}, {Path: "data/sample/1.ans", Data: []byte("5\n")},
		{Path: "data/secret/2.in", Data: []byte("8 5\n")}, {Path: "data/secret/2.ans", Data: []byte("13\n")},
		{Path: "input_validators/main.cpp", Data: []byte(validator)},
		{Path: "submissions/accepted/main.cpp", Data: []byte(accepted)},
		{Path: "submissions/accepted/python.py", Data: []byte("import sys\na,b=map(int,sys.stdin.buffer.read().split())\nprint(a+b)\n")},
		{Path: "submissions/wrong_answer/main.cpp", Data: []byte(printProgram("6"))},
		{Path: "submissions/time_limit_exceeded/main.cpp", Data: []byte(busyProgram)},
		{Path: "submissions/run_time_error/main.cpp", Data: []byte(signalProgram)},
	})
	if e != nil || artifact == nil || !artifact.ManifestReady || artifact.Manifest == nil {
		return packages.Manifest{}, errors.New("mature matrix adaptation failed")
	}
	if packages.VerifyFiles(*artifact.Manifest, artifact.NormalizedFiles) != nil {
		return packages.Manifest{}, errors.New("mature matrix frozen files invalid")
	}
	for _, file := range artifact.NormalizedFiles {
		blobs.add(file.Data)
	}
	return *artifact.Manifest, nil
}

// Qualification logs use a fixed private evidence directory, separate from the
// execution spool cleanup claim. The Linux harness privately collects failures
// and removes the container; ordinary artifacts contain only these digests.
func retainMatrixLog(name string, raw []byte) (privateLogEvidence, error) {
	retained := raw
	if len(retained) > 65536 {
		retained = retained[:65536]
	}
	ev := privateLogEvidence{SHA256: canonical.HashBytes(raw), Bytes: len(raw), RetainedSHA256: canonical.HashBytes(retained), RetainedBytes: len(retained), Truncated: len(retained) != len(raw)}
	switch name {
	case "ALL_PARTS", "VALIDATOR_EXIT_ZERO", "ACCEPTED_REFERENCE_WRONG", "STATEMENT_ARTIFACTS", "LARGE_STATEMENT", "WORKSPACE", "DEFAULT_CHECKER_REGRESSIONS":
	default:
		return ev, errors.New("matrix evidence name invalid")
	}
	const directory = "/run/startrack-judger/tmp/matrix-evidence"
	if e := os.Mkdir(directory, 0700); e != nil && !errors.Is(e, os.ErrExist) {
		return ev, errors.New("private matrix evidence unavailable")
	}
	info, e := os.Lstat(directory)
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Mode()&os.ModeSymlink != 0 {
		return ev, errors.New("private matrix evidence invalid")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return ev, errors.New("private matrix evidence owner invalid")
	}
	// Exclusive creation avoids overwriting evidence from another qualification.
	f, e := os.CreateTemp(directory, name+"-*.log")
	if e != nil {
		return ev, errors.New("private matrix evidence unavailable")
	}
	if f.Chmod(0600) != nil {
		f.Close()
		return ev, errors.New("private matrix evidence mode invalid")
	}
	_, e = bytes.NewReader(retained).WriteTo(f)
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil || closeErr != nil || filepath.Dir(f.Name()) != directory {
		return ev, errors.New("private matrix evidence write failed")
	}
	return ev, nil
}

const inputValidatorProgram = "#include <cstdio>\n#include <string>\n#include <regex>\nint main(){std::string s;for(int c;(c=std::getchar())!=EOF;){if(s.size()>100)return 43;s+=char(c);}return std::regex_match(s,std::regex(\"[1-9][0-9]? [1-9][0-9]?\\n\"))?42:43;}\n"
