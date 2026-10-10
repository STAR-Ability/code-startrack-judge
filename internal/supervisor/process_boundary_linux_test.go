//go:build linux

package supervisor

import (
	"bytes"
	"os"
	"testing"
)

func TestBoundaryOutputCannotGrowPastProtocolLimit(t *testing.T) {
	output := &boundaryOutput{}
	for _, body := range [][]byte{bytes.Repeat([]byte{'a'}, 700), bytes.Repeat([]byte{'b'}, 700), []byte("still drained")} {
		if n, err := output.Write(body); n != len(body) || err != nil {
			t.Fatal("bounded output must continue draining the child")
		}
	}
	if !output.overflow || len(output.body) != processBoundaryLimit {
		t.Fatal("child output exceeded the protocol memory bound")
	}
}

func TestBoundaryProcessRejectsChangedStartTicksAndMissingDescriptor(t *testing.T) {
	pid, uid := os.Getpid(), uint32(os.Geteuid())
	cmdline, err := readBoundaryProc(pid, "cmdline", 512)
	if err != nil {
		t.Fatal(err)
	}
	start, err := inspectBoundaryProcess(pid, uid, string(cmdline), 0, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inspectBoundaryProcess(pid, uid, string(cmdline), start+1, false, nil); err == nil {
		t.Fatal("changed process start ticks accepted")
	}
	if _, err := inspectBoundaryProcess(pid, uid, string(cmdline), start, true, []int{1 << 20}); err == nil {
		t.Fatal("nonexistent descriptor accepted")
	}
	if _, err := inspectBoundaryProcess(pid, uid, "different\x00", start, false, nil); err == nil {
		t.Fatal("different executable argv accepted")
	}
}
