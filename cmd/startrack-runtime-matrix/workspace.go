// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/packages"
	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
)

type largeStatementEvidence struct {
	ManifestFiles        int               `json:"manifestFiles"`
	ManifestRegularBytes int64             `json:"manifestRegularBytes"`
	ManifestSHA256       string            `json:"manifestSha256"`
	Statement            statementEvidence `json:"statement"`
}
type workspaceEvidence struct {
	Passed      bool                                  `json:"passed"`
	Probes      []judgeruntime.WorkspaceProbeEvidence `json:"probes"`
	PrivateLog  privateLogEvidence                    `json:"privateLog"`
	FailureCode string                                `json:"failureCode,omitempty"`
}

func runWorkspaceMatrix(ctx context.Context, adapter *judgeruntime.Adapter, blobs *matrixBlobs, report *matrixReport) error {
	m, e := matureMatrixManifest(blobs, inputValidatorProgram, sumProgram)
	if e != nil {
		return e
	}
	m, e = largestStatementManifest(blobs, m)
	if e != nil {
		return e
	}
	report.LargeStatement.ManifestFiles = len(m.Files)
	for _, file := range m.Files {
		report.LargeStatement.ManifestRegularBytes += file.NormalizedSizeBytes
	}
	manifest, e := m.CanonicalJSON()
	if e != nil {
		return e
	}
	report.LargeStatement.ManifestSHA256 = canonical.HashBytes(manifest)
	if adapter.Qualify(ctx) != nil {
		return errors.New("large statement refresh failed")
	}
	out, runErr := adapter.QualifyStatement(ctx, m)
	log, logErr := retainMatrixLog("LARGE_STATEMENT", out.RawLog)
	ev := statementEvidence{Artifacts: out.Artifacts, Workspaces: out.Workspaces, ParentProcessDenied: out.ParentProcessDenied, PrivateLog: log}
	ev.Passed = runErr == nil && logErr == nil && out.ParentProcessDenied && len(out.Artifacts) == 2 && len(m.Files) == packages.MaxFiles && report.LargeStatement.ManifestRegularBytes == packages.MaxTotalBytes
	if runErr != nil {
		ev.FailureCode = "LARGE_STATEMENT_QUALIFICATION_FAILED"
	}
	report.LargeStatement.Statement = ev
	if !ev.Passed {
		return errors.New("largest public statement qualification failed")
	}
	if adapter.Qualify(ctx) != nil {
		return errors.New("workspace refresh failed")
	}
	workspace, workspaceErr := adapter.QualifyWorkspace(ctx)
	log, logErr = retainMatrixLog("WORKSPACE", workspace.RawLog)
	report.Workspace = workspaceEvidence{Probes: workspace.Probes, PrivateLog: log, Passed: workspaceErr == nil && logErr == nil && len(workspace.Probes) == 2}
	for _, probe := range workspace.Probes {
		report.Workspace.Passed = report.Workspace.Passed && probe.Passed && probe.CacheRemoved
	}
	if workspaceErr != nil {
		report.Workspace.FailureCode = "WORKSPACE_QUALIFICATION_FAILED"
	}
	if !report.Workspace.Passed {
		return errors.New("bounded workspace qualification failed")
	}
	return nil
}

func largestStatementManifest(blobs *matrixBlobs, m packages.Manifest) (packages.Manifest, error) {
	var existing int64
	for _, file := range m.Files {
		existing += file.NormalizedSizeBytes
	}
	remaining := int64(packages.MaxTotalBytes) - existing
	// Reuse verified zero bytes by checksum, so fixture storage need not allocate
	// the entire package. The real Go tar/upload/extraction still transports every
	// recorded byte and member under the actual bounded runtime workspace.
	block := bytes.Repeat([]byte{0}, int(packages.MaxFileBytes))
	full := blobs.add(block)
	empty := blobs.add(nil)
	for index := 0; len(m.Files) < packages.MaxFiles; index++ {
		path := fmt.Sprintf("problem_statement/qualification/asset-%06d.bin", index)
		ref := empty
		if remaining >= packages.MaxFileBytes {
			ref = full
			remaining -= packages.MaxFileBytes
		} else if remaining > 0 {
			ref = blobs.add(block[:int(remaining)])
			remaining = 0
		}
		original, hash, size := path, ref.SHA256, ref.SizeBytes
		m.Files = append(m.Files, packages.FileMapping{OriginalPath: &original, SourceSHA256: &hash, SourceSizeBytes: &size, NormalizedPath: path, NormalizedSHA256: hash, NormalizedSizeBytes: size, Role: "OTHER"})
	}
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].NormalizedPath < m.Files[j].NormalizedPath })
	if remaining != 0 || packages.ValidateManifest(m) != nil {
		return packages.Manifest{}, errors.New("largest public statement manifest invalid")
	}
	return m, nil
}
