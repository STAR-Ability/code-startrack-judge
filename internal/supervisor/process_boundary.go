package supervisor

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	processBoundaryBinary = "/usr/local/libexec/startrack/supervisor"
	processBoundaryFlag   = "--process-boundary-peer"
	processBoundaryLimit  = 1024
	ProcessBoundaryPath   = "/run/startrack-supervisor/process-boundary.json"
)

var boundaryBootIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// This private protocol contains only process identities and synthetic control
// data. Roles select fixed paths and credentials; no caller supplies either.
type processBoundaryRequest struct {
	Version    int    `json:"version"`
	Kind       string `json:"kind"`
	Role       string `json:"role"`
	PID        int    `json:"pid"`
	StartTicks uint64 `json:"startTicks"`
}

type processBoundaryControl struct {
	Version    int    `json:"version"`
	PID        int    `json:"pid"`
	StartTicks uint64 `json:"startTicks"`
	Address    uint64 `json:"address"`
}

type processBoundaryResult struct {
	Version       int    `json:"version"`
	Result        string `json:"result"`
	ControlMem    string `json:"controlMem"`
	ControlVMRead string `json:"controlVMRead"`
	ControlPtrace string `json:"controlPtrace"`
}

type processBoundaryObservation struct {
	Role          string `json:"role"`
	UID           uint32 `json:"uid"`
	PID           int    `json:"pid"`
	StartTicks    uint64 `json:"startTicks"`
	ControlMem    string `json:"controlMem"`
	ControlVMRead string `json:"controlVMRead"`
	ControlPtrace string `json:"controlPtrace"`
	Denied        bool   `json:"denied"`
}

type processBoundaryReport struct {
	Version      int                          `json:"version"`
	ImageDigest  string                       `json:"imageDigest"`
	BootID       string                       `json:"bootId"`
	MeasuredAt   time.Time                    `json:"measuredAt"`
	Observations []processBoundaryObservation `json:"observations"`
}

func validControlOutcome(outcome string) bool {
	return outcome == "allowed" || outcome == "permission_denied"
}

func encodeBoundaryReport(report processBoundaryReport) ([]byte, error) {
	if report.Version != 1 || !digestPattern.MatchString(report.ImageDigest) || !boundaryBootIDPattern.MatchString(report.BootID) || report.MeasuredAt.IsZero() || report.MeasuredAt.Location() != time.UTC || len(report.Observations) != 2 {
		return nil, fail("process_boundary_report")
	}
	for i, name := range []string{"api", "judger"} {
		role, _ := boundaryRole(name)
		observation := report.Observations[i]
		if observation.Role != name || observation.UID != role.uid || observation.PID <= 1 || observation.StartTicks == 0 || !observation.Denied || !validControlOutcome(observation.ControlMem) || !validControlOutcome(observation.ControlVMRead) || !validControlOutcome(observation.ControlPtrace) {
			return nil, fail("process_boundary_report")
		}
	}
	if report.Observations[0].PID == report.Observations[1].PID {
		return nil, fail("process_boundary_report")
	}
	body, err := json.Marshal(report)
	if err != nil || len(body) > 4096 {
		return nil, fail("process_boundary_report")
	}
	return body, nil
}

type processBoundaryRole struct {
	uid    uint32
	binary string
	fds    []int
}

func boundaryRole(role string) (processBoundaryRole, bool) {
	switch role {
	case "api":
		return processBoundaryRole{APIUID, APIBinary, []int{1, 2}}, true
	case "judger":
		return processBoundaryRole{JudgerUID, JudgerBinary, []int{1, 2, 3}}, true
	default:
		return processBoundaryRole{}, false
	}
}

func (r processBoundaryRequest) valid() bool {
	if r.Version != 1 {
		return false
	}
	if r.Kind == "control" {
		return r.Role == "" && r.PID == 0 && r.StartTicks == 0
	}
	_, ok := boundaryRole(r.Role)
	return r.Kind == "probe" && ok && r.PID > 1 && r.StartTicks > 0
}

// Requiring our exact generated encoding also rejects duplicate JSON keys,
// alternate field spellings, unknown fields, and appended messages.
func decodeBoundaryMessage(body []byte, destination any) error {
	if len(body) == 0 || len(body) > processBoundaryLimit {
		return fail("process_boundary_protocol")
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(destination) != nil {
		return fail("process_boundary_protocol")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return fail("process_boundary_protocol")
	}
	expected, err := json.Marshal(destination)
	if err != nil || !bytes.Equal(bytes.TrimSpace(body), expected) {
		return fail("process_boundary_protocol")
	}
	return nil
}

func boundaryPermissionDenied(err error) bool {
	return errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM)
}

func boundaryControlOutcome(err error) (string, bool) {
	if err == nil {
		return "allowed", true
	}
	if boundaryPermissionDenied(err) {
		return "permission_denied", true
	}
	return "", false
}

// /proc/PID/stat's comm may itself contain spaces or closing parentheses.
func boundaryStat(body []byte, pid int) (uint64, error) {
	text := string(body)
	opening := strings.Index(text, " (")
	closing := strings.LastIndex(text, ") ")
	if opening < 1 || closing <= opening {
		return 0, fail("process_boundary_identity")
	}
	actual, err := strconv.Atoi(text[:opening])
	fields := strings.Fields(text[closing+2:])
	if err != nil || actual != pid || len(fields) < 20 || len(fields[0]) != 1 || !strings.Contains("RSDTtIWPK", fields[0]) {
		return 0, fail("process_boundary_identity")
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 {
		return 0, fail("process_boundary_identity")
	}
	return start, nil
}

func boundaryCredentials(body []byte, uid uint32) error {
	seen := map[string]bool{}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || (fields[0] != "Uid:" && fields[0] != "Gid:") {
			continue
		}
		if seen[fields[0]] || len(fields) != 5 {
			return fail("process_boundary_identity")
		}
		seen[fields[0]] = true
		for _, value := range fields[1:] {
			actual, err := strconv.ParseUint(value, 10, 32)
			if err != nil || actual != uint64(uid) {
				return fail("process_boundary_identity")
			}
		}
	}
	if !seen["Uid:"] || !seen["Gid:"] {
		return fail("process_boundary_identity")
	}
	return nil
}
