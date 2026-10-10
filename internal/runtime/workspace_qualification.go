// SPDX-License-Identifier: Apache-2.0
package runtime

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/runtime/restclient"
)

//go:embed native/workspace-qualification.cc
var workspaceQualificationSource []byte

type WorkspaceFacts struct {
	Phase            string `json:"phase"`
	TotalBytes       uint64 `json:"totalBytes"`
	TotalInodes      uint64 `json:"totalInodes"`
	CreatedFiles     uint64 `json:"createdFiles"`
	AllocatedBytes   uint64 `json:"allocatedBytes"`
	PeakUsedBytes    uint64 `json:"peakUsedBytes"`
	PeakUsedInodes   uint64 `json:"peakUsedInodes"`
	AllocationDenied bool   `json:"allocationDenied"`
	CleanupComplete  bool   `json:"cleanupComplete"`
}
type WorkspaceProbeEvidence struct {
	Passed          bool              `json:"passed"`
	Profile         Limits            `json:"profile"`
	Status          restclient.Status `json:"status"`
	ExitStatus      int               `json:"exitStatus"`
	CPUTimeNS       uint64            `json:"cpuTimeNs"`
	WallTimeNS      uint64            `json:"wallTimeNs"`
	MemoryBytes     uint64            `json:"memoryBytes"`
	Facts           WorkspaceFacts    `json:"facts"`
	CacheRemoved    bool              `json:"cacheRemoved"`
	DenialMechanism string            `json:"denialMechanism"`
}
type WorkspaceQualification struct {
	Probes []WorkspaceProbeEvidence `json:"probes"`
	RawLog []byte                   `json:"-"`
}

func (WorkspaceQualification) String() string {
	return "private workspace qualification [diagnostics redacted]"
}
func (q WorkspaceQualification) GoString() string { return q.String() }

type qualificationBlob struct{ data []byte }

func (b qualificationBlob) ReadBlob(ctx context.Context, sha string, size, max int64) ([]byte, error) {
	if ctx.Err() != nil || size > max || !bytesMatch(b.data, BlobRef{SHA256: sha, SizeBytes: size}) {
		return nil, failure("QUALIFICATION_SOURCE_INVALID", false)
	}
	return bytes.Clone(b.data), nil
}

// QualifyWorkspace is a fixed offline operation, with no scheduler/API route.
// Its longer inode workload uses the explicit statement qualification profile;
// it never changes frozen public-task or imported-reference limits.
func (a *Adapter) QualifyWorkspace(ctx context.Context) (out WorkspaceQualification, err error) {
	if !a.Snapshot(ctx).MatureReady {
		return out, failure("RUNTIME_NOT_READY", false)
	}
	source := bytes.Clone(workspaceQualificationSource)
	compileCtx := context.WithValue(ctx, blobReaderContextKey{}, qualificationBlob{source})
	artifact, response, e := a.matureCompile(compileCtx, "workspace-qualification/compile", Program{LanguageID: LanguageID, File: BlobRef{SHA256: canonical.HashBytes(source), SizeBytes: int64(len(source))}})
	for _, encoded := range []string{response.StdoutBase64, response.StderrBase64} {
		if raw, decodeErr := decodeMatureBytes(encoded, 8<<20); decodeErr == nil {
			if len(raw) > (2<<20)-len(out.RawLog) {
				raw = raw[:(2<<20)-len(out.RawLog)]
			}
			out.RawLog = append(out.RawLog, raw...)
		}
	}
	if e != nil || !response.Compiled {
		return out, failure("WORKSPACE_QUALIFICATION_COMPILE_FAILED", false)
	}
	for _, phase := range []string{"inode", "allocation"} {
		probe, private, e := a.workspaceProbe(ctx, artifact, phase)
		if len(private) > (2<<20)-len(out.RawLog) {
			private = private[:(2<<20)-len(out.RawLog)]
		}
		out.RawLog = append(out.RawLog, private...)
		out.Probes = append(out.Probes, probe)
		if e != nil || !probe.Passed {
			return out, failure("WORKSPACE_QUALIFICATION_FAILED", false)
		}
	}
	return out, nil
}

func (a *Adapter) workspaceProbe(ctx context.Context, artifact programArtifact, phase string) (out WorkspaceProbeEvidence, private []byte, err error) {
	if phase != "inode" && phase != "allocation" {
		return out, nil, failure("WORKSPACE_QUALIFICATION_PHASE_INVALID", false)
	}
	if e := a.verifyOperation(ctx); e != nil {
		return out, nil, e
	}
	out.Profile = statementLimits()
	out.Profile.OutputBytes = 65536
	s := a.factory.NewSession()
	defer func() {
		if e := s.Close(); e != nil {
			a.failClosed()
			out.Passed = false
			err = failure("SANDBOX_CLEANUP_FAILED", true)
		} else {
			out.CacheRemoved = true
		}
	}()
	stdin, e := s.Upload(ctx, nil)
	if e != nil {
		return out, nil, transportFailure(e, false)
	}
	file, e := s.Upload(ctx, artifact.data)
	if e != nil {
		return out, nil, transportFailure(e, false)
	}
	r, e := a.runOne(ctx, s, "workspace-qualification/"+phase, command([]string{"/w/main", phase}, stdin, map[string]restclient.FileID{"main": file}, out.Profile))
	if e != nil {
		return out, nil, e
	}
	out.Status, out.ExitStatus, out.CPUTimeNS, out.WallTimeNS, out.MemoryBytes = r.Status, r.ExitStatus, r.CPUTimeNS, r.WallTimeNS, r.MemoryBytes
	var raw []byte
	for name, target := range map[string]*[]byte{"stdout": &raw, "stderr": &private} {
		file, exists := r.CachedFiles[name]
		if !exists {
			return out, private, failure("WORKSPACE_QUALIFICATION_STDIO_MISSING", false)
		}
		*target, e = s.Download(ctx, file, 65536)
		if e != nil {
			return out, private, transportFailure(e, false)
		}
	}
	private = append(private, raw...)
	lines := bytes.Split(bytes.TrimSpace(raw), []byte{'\n'})
	if len(lines) < 1 || len(lines) > 64 {
		return out, private, failure("WORKSPACE_QUALIFICATION_REPORT_INVALID", false)
	}
	var previous WorkspaceFacts
	for _, line := range lines {
		var facts WorkspaceFacts
		if workspaceFactsReport(line, &facts) != nil || facts.Phase != phase || facts.TotalBytes != 2<<30 || facts.TotalInodes != 262144 || facts.CreatedFiles > 262144 || facts.AllocatedBytes > 3<<30 || facts.PeakUsedBytes > facts.TotalBytes || facts.PeakUsedInodes > facts.TotalInodes || facts.PeakUsedBytes < previous.PeakUsedBytes || facts.PeakUsedInodes < previous.PeakUsedInodes || facts.AllocatedBytes < previous.AllocatedBytes {
			return out, private, failure("WORKSPACE_QUALIFICATION_REPORT_INVALID", false)
		}
		previous = facts
	}
	out.Facts = previous
	out.DenialMechanism = workspaceDenialMechanism(phase, r, previous)
	out.Passed = out.DenialMechanism != ""
	return out, private, nil
}

func workspaceDenialMechanism(phase string, r restclient.Result, facts WorkspaceFacts) string {
	if phase == "inode" {
		if r.Status == restclient.Accepted && r.ExitStatus == 0 && facts.CreatedFiles >= 250000 && facts.PeakUsedInodes == 262144 && facts.AllocationDenied && facts.CleanupComplete {
			return "FILESYSTEM"
		}
	} else if phase == "allocation" {
		if r.Status == restclient.Accepted && r.ExitStatus == 0 && facts.AllocationDenied && facts.CleanupComplete && facts.AllocatedBytes >= 1536<<20 {
			return "FILESYSTEM"
		}
		if r.Status == restclient.MemoryLimit && facts.AllocatedBytes >= 1<<30 && r.MemoryBytes >= 1536<<20 {
			return "CGROUP_MEMORY"
		}
	}
	return ""
}

func workspaceFactsReport(raw []byte, out *WorkspaceFacts) error {
	if strictDecode(raw, out) != nil {
		return failure("WORKSPACE_QUALIFICATION_REPORT_INVALID", false)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 9 {
		return failure("WORKSPACE_QUALIFICATION_REPORT_INVALID", false)
	}
	for _, name := range []string{"phase", "totalBytes", "totalInodes", "createdFiles", "allocatedBytes", "peakUsedBytes", "peakUsedInodes", "allocationDenied", "cleanupComplete"} {
		if fields[name] == nil || bytes.Equal(bytes.TrimSpace(fields[name]), []byte("null")) {
			return failure("WORKSPACE_QUALIFICATION_REPORT_INVALID", false)
		}
	}
	return nil
}
