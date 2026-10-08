// SPDX-License-Identifier: Apache-2.0
package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
)

const defaultCheckerFixtureRoot = "/opt/startrack/qualification/default_validator_tests"

// This digest covers the sorted {path,sha256,sizeBytes} manifest of all 108
// verbatim fixture files at the reviewed problemtools revision. The original
// files stay in upstream inputs and retain their original MIT legal evidence.
const DefaultCheckerFixtureSHA256 = "11ddcd34100a82c79ac2dd511cc5b34bf5643f040a92bcb48c84bb2491fa8fb3"

const DefaultCheckerFixtureRevision = "6010cbaa37a1612117f49566b2fff8646d53faa2"

type DefaultCheckerCaseEvidence struct {
	Name               string `json:"name"`
	SourceSHA256       string `json:"sourceSha256"`
	Passed             bool   `json:"passed"`
	ExpectedExitCode   int    `json:"expectedExitCode"`
	ActualWaitStatus   int    `json:"actualWaitStatus"`
	AnswerSHA256       string `json:"answerSha256"`
	OutputSHA256       string `json:"outputSha256"`
	ArgumentsSHA256    string `json:"argumentsSha256"`
	ExpectedFeedback   string `json:"expectedFeedbackSha256"`
	ActualFeedback     string `json:"actualFeedbackSha256"`
	ActualFeedbackSize int    `json:"actualFeedbackBytes"`
}

type DefaultCheckerQualification struct {
	Passed         bool                         `json:"passed"`
	SourceRevision string                       `json:"sourceRevision"`
	CorpusSHA256   string                       `json:"corpusSha256"`
	FixtureFiles   int                          `json:"fixtureFiles"`
	FixtureBytes   int64                        `json:"fixtureBytes"`
	Profile        Limits                       `json:"profile"`
	Cases          []DefaultCheckerCaseEvidence `json:"cases"`
	RawLog         []byte                       `json:"-"`
}

func (DefaultCheckerQualification) String() string {
	return "private default checker qualification [fixtures and diagnostics redacted]"
}
func (q DefaultCheckerQualification) GoString() string { return q.String() }

type checkerFixtureRecord struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"sizeBytes"`
}

type checkerFixture struct {
	name     string
	source   string
	files    map[string][]byte
	exitCode int
}

func loadDefaultCheckerFixtures(root string, read func(string, int64) ([]byte, error)) ([]checkerFixture, []checkerFixtureRecord, error) {
	invalid := func() ([]checkerFixture, []checkerFixtureRecord, error) {
		return nil, nil, failure("DEFAULT_CHECKER_FIXTURE_INVALID", false)
	}
	directories, e := os.ReadDir(root)
	if e != nil {
		return invalid()
	}
	var fixtures []checkerFixture
	var records []checkerFixtureRecord
	for _, directory := range directories {
		if directory.Name() == "README.md" || directory.Name() == "run_and_generate_expected.py" {
			if !directory.Type().IsRegular() || directory.Type()&os.ModeSymlink != 0 {
				return invalid()
			}
			continue // Preserved upstream documentation; this operation executes neither.
		}
		if !directory.IsDir() || directory.Type()&os.ModeSymlink != 0 || !strings.HasPrefix(directory.Name(), "test_") {
			return invalid()
		}
		files, e := os.ReadDir(filepath.Join(root, directory.Name()))
		if e != nil || len(files) < 3 || len(files) > 5 {
			return invalid()
		}
		fixture := checkerFixture{name: directory.Name(), files: map[string][]byte{}}
		firstRecord := len(records)
		for _, file := range files {
			switch file.Name() {
			case "judge.ans", "user.out", "args.txt", "expected_exit_code.txt", "expected_message.txt":
			default:
				return invalid()
			}
			if !file.Type().IsRegular() || file.Type()&os.ModeSymlink != 0 {
				return invalid()
			}
			name := directory.Name() + "/" + file.Name()
			raw, e := read(filepath.Join(root, name), 65536)
			if e != nil || len(raw) > 65536 {
				return invalid()
			}
			fixture.files[file.Name()] = raw
			records = append(records, checkerFixtureRecord{"tests/default_validator_tests/" + name, canonical.HashBytes(raw), int64(len(raw))})
		}
		for _, name := range []string{"judge.ans", "user.out", "expected_exit_code.txt"} {
			if _, ok := fixture.files[name]; !ok {
				return invalid()
			}
		}
		fixture.exitCode, e = strconv.Atoi(strings.TrimSpace(string(fixture.files["expected_exit_code.txt"])))
		if e != nil || fixture.exitCode != 42 && fixture.exitCode != 43 {
			return invalid()
		}
		manifest, e := json.Marshal(records[firstRecord:])
		if e != nil {
			return invalid()
		}
		fixture.source = canonical.HashBytes(manifest)
		fixtures = append(fixtures, fixture)
	}
	manifest, e := json.Marshal(records)
	if e != nil || len(fixtures) != 24 || len(records) != 108 || canonical.HashBytes(manifest) != DefaultCheckerFixtureSHA256 {
		return invalid()
	}
	return fixtures, records, nil
}

func defaultCheckerEvidence(fixture checkerFixture, response MatureResponse, runErr error) DefaultCheckerCaseEvidence {
	feedback, e := decodeMatureBytes(response.FeedbackBase64, 65536)
	expected := fixture.files["expected_message.txt"]
	return DefaultCheckerCaseEvidence{Name: fixture.name, SourceSHA256: fixture.source, ExpectedExitCode: fixture.exitCode, ActualWaitStatus: response.WaitStatus,
		AnswerSHA256: canonical.HashBytes(fixture.files["judge.ans"]), OutputSHA256: canonical.HashBytes(fixture.files["user.out"]),
		ArgumentsSHA256: canonical.HashBytes(fixture.files["args.txt"]), ExpectedFeedback: canonical.HashBytes(expected),
		ActualFeedback: canonical.HashBytes(feedback), ActualFeedbackSize: len(feedback),
		Passed: runErr == nil && e == nil && response.OK && response.WaitStatus == fixture.exitCode<<8 && bytes.Equal(feedback, expected)}
}

// QualifyDefaultChecker is a fixed offline operation, absent from scheduler/API
// routes. It runs the exact pinned regression bytes and original arguments
// through the same mature checker launcher, sandbox profile and limits. The
// complete frozen corpus is verified before any vector can execute.
func (a *Adapter) QualifyDefaultChecker(ctx context.Context) (out DefaultCheckerQualification, err error) {
	if !a.Snapshot(ctx).MatureReady {
		return out, failure("RUNTIME_NOT_READY", false)
	}
	fixtures, records, e := loadDefaultCheckerFixtures(defaultCheckerFixtureRoot, readTrustedHelper)
	if e != nil {
		return out, e
	}
	out.SourceRevision, out.CorpusSHA256 = DefaultCheckerFixtureRevision, DefaultCheckerFixtureSHA256
	out.FixtureFiles, out.Profile = len(records), checkerLimits()
	for _, record := range records {
		out.FixtureBytes += record.Size
	}
	for _, fixture := range fixtures {
		args := []string{"/usr/local/bin/startrack-checker-launcher", "/w/default_validator", "/w/input", "/w/answer", "/w/feedback"}
		args = append(args, strings.Fields(string(fixture.files["args.txt"]))...)
		response, e := a.matureRunBytes(ctx, "default-checker-qualification/"+fixture.name, args, fixture.files["user.out"],
			map[string][]byte{"default_validator": a.checker, "input": {}, "answer": fixture.files["judge.ans"]}, checkerLimits())
		evidence := defaultCheckerEvidence(fixture, response, e)
		out.Cases = append(out.Cases, evidence)
		for _, encoded := range []string{response.StdoutBase64, response.StderrBase64, response.FeedbackBase64} {
			if raw, decodeErr := decodeMatureBytes(encoded, 8<<20); decodeErr == nil {
				remaining := (2 << 20) - len(out.RawLog)
				if len(raw) > remaining {
					raw = raw[:remaining]
				}
				out.RawLog = append(out.RawLog, raw...)
			}
		}
		if !evidence.Passed {
			return out, failure("DEFAULT_CHECKER_REGRESSION_FAILED", false)
		}
	}
	out.Passed = len(out.Cases) == 24
	return out, nil
}
