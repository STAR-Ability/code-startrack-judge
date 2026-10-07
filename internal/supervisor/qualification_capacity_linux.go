//go:build linux

package supervisor

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const CapacityPath = "/run/startrack-supervisor/import-capacity.json"

type capacityCase struct {
	Name, PackagePath, JobID, Status               string
	SourceFiles, NormalizedFiles                   int
	SourceRegularBytes, SourceArchiveBytes         int64
	NormalizedRegularBytes, NormalizedArchiveBytes int64
	SourceSHA256, NormalizedSHA256, ManifestSHA256 string
	RejectedEvidenceID, PreviousLicenseEvidenceID  string
	LicenseTextSHA256, ValidationRunID, ProblemID  string
	ProblemVersionID                               string
	CheckpointsPassed                              int
	ProgramEvidenceCount                           uint64
	StoredSampleBytes, DetailEnvelopeBytes         int64
	DetailHTTPStatus, DetailResponseBytes          int
	DetailResponseCode                             string
	SampleTextBytes                                int64
	ExpectedOversizeRejection                      bool
	OversizeRejectedEvidenceID, RejectionStage     string
	ApprovedLicenseEvidenceID                      string
	RejectionCode                                  string
	NoPublication                                  bool
}

type capacityOutcome struct {
	SchemaVersion                              int
	Scope, Phase, Code, Cgroup, DeclaredLimits string
	SyntheticFixture, Passed                   bool
	UID                                        int
	Cases                                      []capacityCase
}

// A complete typed decoding prevents an accidental credential/log field from
// being retained in this public structural report. The fixed child command is
// the only source of the outcome; callers never select a binary, path or argv.
func decodeCapacityOutcome(data []byte, phase string) (capacityOutcome, error) {
	var report capacityOutcome
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if len(data) > 65536 || decoder.Decode(&report) != nil || decoder.Decode(new(any)) != io.EOF || report.SchemaVersion != 1 || report.Scope != "DISPOSABLE_SYNTHETIC_API_IMPORT_CAPACITY" || !report.SyntheticFixture || report.Phase != phase || report.UID != APIUID || report.Cgroup != "/service" || len(report.Cases) > 3 {
		return report, fail("qualification_capacity_report")
	}
	if report.Passed {
		if report.Code != "IMPORT_CAPACITY_PASSED" || len(report.Cases) != 3 || report.Cases[0].Name != "MEMBER_PAYLOAD" || report.Cases[1].Name != "SAMPLE_SUPPORTED" || report.Cases[2].Name != "SAMPLE_HEAVY" {
			return report, fail("qualification_capacity_report")
		}
		for index, current := range report.Cases {
			if !current.NoPublication || phase == "reject" && current.Status != "FAILED" || phase == "validate" && (index < 2 && current.Status != "SUCCEEDED" || index == 2 && (current.Status != "FAILED" || !current.ExpectedOversizeRejection || current.RejectionStage != "UNSUPPORTED" || current.RejectionCode != "PACKAGE_UNSUPPORTED" || current.OversizeRejectedEvidenceID == "")) {
				return report, fail("qualification_capacity_report")
			}
		}
	}
	return report, nil
}

func runImportCapacity(ctx context.Context, s settings, accounting *cgroupAccounting) error {
	if !s.qualificationOnly || (s.capacityPhase != "reject" && s.capacityPhase != "validate") {
		return fail("qualification_capacity_mode")
	}
	waitCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	for {
		if info, err := os.Lstat(QualificationPath); err == nil && info.Mode().IsRegular() {
			break
		}
		select {
		case <-waitCtx.Done():
			return fail("qualification_capacity_measurement")
		case <-time.After(100 * time.Millisecond):
		}
	}
	log, err := openPrivateLog(filepath.Join(filepath.Dir(CapacityPath), "capacity-private.log"), 0)
	if err != nil {
		return err
	}
	defer log.Close()
	before, err := accounting.snapshot()
	if err != nil {
		return err
	}
	output := &matrixReportWriter{}
	child := ownedChild("/opt/startrack/bin/startrack-import-capacity", s.capacityEnvironment(), APIUID, []uint32{SchedulingGID})
	child.Args = append(child.Args, "--phase", s.capacityPhase)
	child.Stdout, child.Stderr = output, &matrixPrivateWriter{file: log, remaining: 65536}
	if child.Start() != nil {
		return fail("qualification_capacity_start")
	}
	pid := child.Process.Pid
	group, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil || strings.TrimSpace(string(group)) != "0::/service" {
		child.Process.Kill()
		child.Wait()
		return fail("qualification_capacity_cgroup")
	}
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	deadline := time.NewTimer(75 * time.Minute)
	defer deadline.Stop()
	select {
	case err = <-done:
	case <-ctx.Done():
		child.Process.Kill()
		<-done
		return fail("qualification_capacity_interrupted")
	case <-deadline.C:
		child.Process.Kill()
		<-done
		return fail("qualification_capacity_timeout")
	}
	outcome, decodeErr := decodeCapacityOutcome(output.Bytes(), s.capacityPhase)
	if decodeErr != nil {
		return decodeErr
	}
	after, snapshotErr := accounting.snapshot()
	if snapshotErr != nil {
		return snapshotErr
	}
	report := struct {
		ExecutionPassed   bool                         `json:"executionPassed"`
		WorkerImageDigest string                       `json:"workerImageDigest"`
		CapacityUID       uint32                       `json:"capacityUID"`
		CapacityPID       int                          `json:"capacityPID"`
		CapacityCgroup    string                       `json:"capacityCgroup"`
		Before            map[string]map[string]string `json:"cgroupsBefore"`
		After             map[string]map[string]string `json:"cgroupsAfter"`
		Outcome           json.RawMessage              `json:"outcome"`
	}{err == nil && outcome.Passed, s.imageDigest, APIUID, pid, "/service", before, after, output.Bytes()}
	data, marshalErr := json.Marshal(report)
	if marshalErr != nil || len(data) > 65536 {
		return fail("qualification_capacity_report_size")
	}
	if writeErr := writeStructuralReport(CapacityPath, data); writeErr != nil {
		return writeErr
	}
	if err != nil || !outcome.Passed {
		return fail("qualification_capacity_execution")
	}
	return nil
}
