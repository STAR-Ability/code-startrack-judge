package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOfflineCommandCannotInferAuthorityFromReceiptOrEnvironment(t *testing.T) {
	if os.Geteuid() != 0 {
		if err := run([]string{"license-review", "-config", "/arbitrary", "-review", "/arbitrary"}); !errors.Is(err, errAuthority) {
			t.Fatal("unprivileged caller reached operator configuration")
		}
	}
	var c operatorConfig
	for _, raw := range []string{`{"authority":"ADMIN","authority":"ADMIN"}`, `{"authority":"ADMIN","reviewedBy":"caller"}`, `{"authority":"ADMIN"} {}`} {
		if strictDecode([]byte(raw), &c) == nil {
			t.Fatal("ambiguous/unknown private operator fields accepted")
		}
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "operator.json")
	if os.WriteFile(file, []byte(`{}`), 0600) != nil {
		t.Fatal("fixture write failed")
	}
	if read, err := readTrusted(file, 1024, 0); err == nil || read != nil {
		t.Fatal("untrusted directory ancestry accepted")
	}
	if migrateConfig("postgres://judge_runtime:credential@localhost/judge?sslmode=disable") == nil {
		t.Fatal("runtime credential accepted as reviewer authority")
	}
}
