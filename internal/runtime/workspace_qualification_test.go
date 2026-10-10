// SPDX-License-Identifier: Apache-2.0
package runtime

import (
	"strings"
	"testing"

	"github.com/STAR-Ability/code-startrack-judge/internal/runtime/restclient"
)

func TestWorkspaceQualificationRequiresMeasuredDenialAndPreservesOriginalFacts(t *testing.T) {
	facts := WorkspaceFacts{Phase: "allocation", AllocatedBytes: 1 << 30, PeakUsedBytes: 1 << 30}
	result := restclient.Result{Status: restclient.MemoryLimit, CPUTimeNS: 999, WallTimeNS: 1111, MemoryBytes: 2 << 30}
	if workspaceDenialMechanism("allocation", result, facts) != "CGROUP_MEMORY" || facts.AllocationDenied || facts.CleanupComplete || result.CPUTimeNS != 999 || result.WallTimeNS != 1111 {
		t.Fatal("qualification changed original memory-denial facts")
	}
	for _, status := range []restclient.Status{restclient.Accepted, restclient.TimeLimit, restclient.Signalled, restclient.OutputLimit, restclient.InternalError} {
		result.Status = status
		if workspaceDenialMechanism("allocation", result, facts) != "" {
			t.Fatal("unmeasured allocation denial qualified")
		}
	}
	inode := WorkspaceFacts{CreatedFiles: 262140, PeakUsedInodes: 262144, AllocationDenied: true, CleanupComplete: true}
	if workspaceDenialMechanism("inode", restclient.Result{Status: restclient.Accepted}, inode) != "FILESYSTEM" {
		t.Fatal("measured inode denial rejected")
	}
	inode.CreatedFiles = 12
	if workspaceDenialMechanism("inode", restclient.Result{Status: restclient.Accepted}, inode) != "" {
		t.Fatal("premature inode failure qualified")
	}
}

func TestWorkspaceNativeReportRequiresEveryBoundedFact(t *testing.T) {
	raw := `{"phase":"inode","totalBytes":2147483648,"totalInodes":262144,"createdFiles":262140,"allocatedBytes":0,"peakUsedBytes":4096,"peakUsedInodes":262144,"allocationDenied":true,"cleanupComplete":true}`
	var out WorkspaceFacts
	if workspaceFactsReport([]byte(raw), &out) != nil {
		t.Fatal("valid native facts rejected")
	}
	for _, invalid := range []string{
		strings.Replace(raw, `"allocatedBytes":0,`, "", 1),
		strings.Replace(raw, `"allocatedBytes":0`, `"allocatedBytes":null`, 1),
		strings.Replace(raw, `"allocatedBytes":0`, `"allocatedBytes":0,"allocatedBytes":1`, 1),
		strings.Replace(raw, `"allocatedBytes":0`, `"allocatedBytes":0,"privatePath":"canary"`, 1),
	} {
		if workspaceFactsReport([]byte(invalid), &out) == nil {
			t.Fatal("incomplete or unbounded native facts accepted")
		}
	}
}
