//go:build linux

package supervisor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateLogRejectsUnsafeFileBeforeMutation(t *testing.T) {
	for _, mode := range []os.FileMode{0644, 0600} {
		t.Run(mode.String(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private.log")
			body := []byte("private synthetic canary")
			if err := os.WriteFile(path, body, mode); err != nil {
				t.Fatal(err)
			}
			if mode == 0600 {
				if err := os.Link(path, path+".alias"); err != nil {
					t.Fatal(err)
				}
			}
			if f, err := openPrivateLog(path, uint32(os.Geteuid())); err == nil {
				f.Close()
				t.Fatal("unsafe diagnostic file accepted")
			}
			actual, err := os.ReadFile(path)
			if err != nil || string(actual) != string(body) {
				t.Fatal("rejected file mutated")
			}
		})
	}
	path := filepath.Join(t.TempDir(), "private.log")
	f, err := openPrivateLog(path, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
}
