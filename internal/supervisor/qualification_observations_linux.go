//go:build linux

package supervisor

import (
	"bytes"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const IsolationObservationsPath = "/run/startrack-supervisor/runtime-isolation-observations.json"

// Supplemental evidence records only the fixed synthetic probe's facts. Bnd
// is observed, not assumed zero: mature upstream drops effective, permitted,
// inheritable and ambient capabilities while retaining its namespace Bnd.
func writeProbeObservations(s settings, pid int, observations []probeObservation, resources []qualificationResourceObservation, cleanup qualificationCleanupObservation) error {
	if len(observations) < 1 || len(observations) > 2 || len(resources) > 6 {
		return fail("qualification_observations")
	}
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	end := bytes.LastIndexByte(stat, ')')
	if err != nil || end < 0 {
		return fail("qualification_observations_identity")
	}
	fields := strings.Fields(string(stat[end+1:]))
	boot, bootErr := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if len(fields) < 20 || fields[0] == "Z" || bootErr != nil {
		return fail("qualification_observations_identity")
	}
	report := struct {
		Version           int                                `json:"version"`
		WorkerImageDigest string                             `json:"workerImageDigest"`
		PID               int                                `json:"pid"`
		StartTicks        string                             `json:"startTicks"`
		BootID            string                             `json:"bootId"`
		MeasuredAt        time.Time                          `json:"measuredAt"`
		Observations      []probeObservation                 `json:"observations"`
		Resources         []qualificationResourceObservation `json:"resourceFixtures"`
		Cleanup           qualificationCleanupObservation    `json:"cleanupObservations"`
	}{1, s.imageDigest, pid, fields[19], strings.TrimSpace(string(boot)), time.Now().UTC(), observations, resources, cleanup}
	data, err := json.Marshal(report)
	if err != nil || len(data) > 8192 {
		return fail("qualification_observations_size")
	}
	return writeStructuralReport(IsolationObservationsPath, data)
}

func writeStructuralReport(path string, data []byte) error {
	temporary := path + ".tmp"
	defer os.Remove(temporary)
	f, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0644)
	if err != nil {
		return fail("qualification_report_write")
	}
	err = f.Chmod(0644)
	if err == nil {
		_, err = f.Write(append(data, '\n'))
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil || os.Rename(temporary, path) != nil {
		return fail("qualification_report_write")
	}
	return nil
}
