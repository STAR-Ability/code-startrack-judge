package supervisor

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestBoundaryProtocolHasFiniteIdentities(t *testing.T) {
	valid := []processBoundaryRequest{
		{Version: 1, Kind: "probe", Role: "api", PID: 42, StartTicks: 123},
		{Version: 1, Kind: "probe", Role: "judger", PID: 43, StartTicks: 124},
		{Version: 1, Kind: "control"},
	}
	for _, request := range valid {
		body, _ := json.Marshal(request)
		var got processBoundaryRequest
		if err := decodeBoundaryMessage(append(body, '\n'), &got); err != nil || got != request || !got.valid() {
			t.Fatalf("valid private message rejected: %v", err)
		}
	}
	invalid := []processBoundaryRequest{
		{Version: 2, Kind: "control"},
		{Version: 1, Kind: "control", Role: "api"},
		{Version: 1, Kind: "control", PID: 1},
		{Version: 1, Kind: "control", StartTicks: 1},
		{Version: 1, Kind: "probe", Role: "runtime", PID: 42, StartTicks: 1},
		{Version: 1, Kind: "probe", Role: "api", PID: 1, StartTicks: 1},
		{Version: 1, Kind: "probe", Role: "api", PID: 42},
		{Version: 1, Kind: "other", Role: "api", PID: 42, StartTicks: 1},
	}
	for _, request := range invalid {
		if request.valid() {
			t.Fatalf("unbounded or unknown identity accepted: %#v", request)
		}
	}
	api, ok := boundaryRole("api")
	if !ok || api.uid != 20000 || api.binary != APIBinary || fmt.Sprint(api.fds) != "[1 2]" {
		t.Fatal("API role differs from fixed ownership")
	}
	judger, ok := boundaryRole("judger")
	if !ok || judger.uid != 20001 || judger.binary != JudgerBinary || fmt.Sprint(judger.fds) != "[1 2 3]" {
		t.Fatal("judger role differs from fixed ownership")
	}
}

func TestBoundaryProtocolRejectsAmbiguousOrOversizedMessages(t *testing.T) {
	valid := `{"version":1,"kind":"control","role":"","pid":0,"startTicks":0}`
	for _, body := range []string{
		"", "null", `{}`, valid + valid,
		strings.Replace(valid, `"kind":"control"`, `"kind":"probe","kind":"control"`, 1),
		strings.Replace(valid, `"version":1`, `"Version":1`, 1),
		strings.Replace(valid, `"version":1`, `"version":1,"path":"/caller/path"`, 1),
		strings.Replace(valid, `"version":1`, `"version":1.0`, 1),
		valid + strings.Repeat(" ", processBoundaryLimit),
	} {
		var request processBoundaryRequest
		if decodeBoundaryMessage([]byte(body), &request) == nil {
			t.Fatalf("ambiguous message accepted: %.100s", body)
		}
	}
}

func TestBoundaryDenialRequiresPermissionErrno(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EACCES, syscall.EPERM} {
		wrapped := &os.PathError{Op: "open", Path: "synthetic", Err: errno}
		if !boundaryPermissionDenied(wrapped) {
			t.Fatal("permission errno rejected")
		}
		if outcome, ok := boundaryControlOutcome(wrapped); !ok || outcome != "permission_denied" {
			t.Fatal("permission control outcome rejected")
		}
	}
	for _, err := range []error{nil, syscall.ENOENT, syscall.ESRCH, syscall.EFAULT, syscall.ENOSYS, syscall.EIO} {
		if boundaryPermissionDenied(err) {
			t.Fatalf("non-permission error counted as denial: %v", err)
		}
		if err != nil {
			if _, ok := boundaryControlOutcome(err); ok {
				t.Fatalf("invalid control result accepted: %v", err)
			}
		}
	}
}

func TestBoundaryCredentialsRequireAllFourUIDAndGIDValues(t *testing.T) {
	valid := "Name:\tsynthetic\nUid:\t20000\t20000\t20000\t20000\nGid:\t20000\t20000\t20000\t20000\n"
	if err := boundaryCredentials([]byte(valid), APIUID); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		strings.Replace(valid, "Uid:\t20000", "Uid:\t0", 1),
		strings.Replace(valid, "Gid:\t20000", "Gid:\t20001", 1),
		strings.Replace(valid, "Uid:\t20000\t20000\t20000\t20000", "Uid:\t20000\t20000\t20000", 1),
		strings.Replace(valid, "Gid:", "Groups:", 1),
		valid + "Uid:\t20000\t20000\t20000\t20000\n",
		strings.Replace(valid, "20000", "-1", 1),
	} {
		if boundaryCredentials([]byte(body), APIUID) == nil {
			t.Fatal("partial, changed, or ambiguous credentials accepted")
		}
	}
}

func syntheticBoundaryStat(pid int, state, start string) []byte {
	fields := []string{state}
	for i := 1; i < 19; i++ {
		fields = append(fields, "0")
	}
	fields = append(fields, start)
	return []byte(fmt.Sprint(pid) + " (synthetic name) with ) parentheses) " + strings.Join(fields, " "))
}

func TestBoundaryStatRequiresLivePIDAndStartTicks(t *testing.T) {
	if start, err := boundaryStat(syntheticBoundaryStat(42, "S", "123"), 42); err != nil || start != 123 {
		t.Fatalf("valid process with parentheses in comm rejected: %d %v", start, err)
	}
	for _, body := range [][]byte{
		syntheticBoundaryStat(43, "S", "123"),
		syntheticBoundaryStat(42, "Z", "123"),
		syntheticBoundaryStat(42, "X", "123"),
		syntheticBoundaryStat(42, "x", "123"),
		syntheticBoundaryStat(42, "?", "123"),
		syntheticBoundaryStat(42, "S", "0"),
		syntheticBoundaryStat(42, "S", "-1"),
		[]byte("42 (truncated) S"),
	} {
		if _, err := boundaryStat(body, 42); err == nil {
			t.Fatal("missing, reused, or dead process identity accepted")
		}
	}
}

func validBoundaryReport() processBoundaryReport {
	return processBoundaryReport{
		Version: 1, ImageDigest: "sha256:" + strings.Repeat("a", 64), BootID: "12345678-1234-1234-1234-123456789abc", MeasuredAt: time.Unix(42, 0).UTC(),
		Observations: []processBoundaryObservation{
			{Role: "api", UID: APIUID, PID: 42, StartTicks: 123, ControlMem: "allowed", ControlVMRead: "allowed", ControlPtrace: "permission_denied", Denied: true},
			{Role: "judger", UID: JudgerUID, PID: 43, StartTicks: 124, ControlMem: "permission_denied", ControlVMRead: "permission_denied", ControlPtrace: "permission_denied", Denied: true},
		},
	}
}

func TestBoundaryReportRetainsBothControlOutcomesAndFixedRoleIdentities(t *testing.T) {
	report := validBoundaryReport()
	body, err := encodeBoundaryReport(report)
	if err != nil || len(body) > 4096 {
		t.Fatal("valid structural evidence rejected", err)
	}
	var got processBoundaryReport
	if err := json.Unmarshal(body, &got); err != nil || got.Observations[0].ControlVMRead != "allowed" || got.Observations[1].ControlVMRead != "permission_denied" {
		t.Fatal("memory control distinction lost", err)
	}
	for _, prohibited := range []string{"address", "/proc/", "/usr/local/", "environment", "content"} {
		if strings.Contains(string(body), prohibited) {
			t.Fatal("private probe data entered structural report")
		}
	}
	mutations := []func(*processBoundaryReport){
		func(r *processBoundaryReport) { r.Version = 2 },
		func(r *processBoundaryReport) { r.ImageDigest = "sha256:unverified" },
		func(r *processBoundaryReport) { r.BootID = "missing" },
		func(r *processBoundaryReport) { r.MeasuredAt = time.Time{} },
		func(r *processBoundaryReport) { r.Observations = r.Observations[:1] },
		func(r *processBoundaryReport) { r.Observations[0].Denied = false },
		func(r *processBoundaryReport) { r.Observations[0].Role = "judger" },
		func(r *processBoundaryReport) { r.Observations[0].UID = 0 },
		func(r *processBoundaryReport) { r.Observations[0].PID = 1 },
		func(r *processBoundaryReport) { r.Observations[0].PID = r.Observations[1].PID },
		func(r *processBoundaryReport) { r.Observations[0].StartTicks = 0 },
		func(r *processBoundaryReport) { r.Observations[0].ControlMem = "missing" },
		func(r *processBoundaryReport) { r.Observations[0].ControlVMRead = "missing" },
		func(r *processBoundaryReport) { r.Observations[0].ControlPtrace = "missing" },
	}
	for _, mutate := range mutations {
		invalid := validBoundaryReport()
		mutate(&invalid)
		if _, err := encodeBoundaryReport(invalid); err == nil {
			t.Fatal("incomplete or unbound structural evidence accepted")
		}
	}
}
