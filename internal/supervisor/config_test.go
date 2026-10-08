package supervisor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testSettings(t *testing.T) settings {
	t.Helper()
	values := map[string]string{"database-url": "postgres://judge:synthetic-only@127.0.0.1/judge?sslmode=disable"}
	for i, name := range []string{"backend-judge-token", "judge-backend-token", "runtime-token", "scheduler-token", "catalog-cursor-key"} {
		values[name] = strings.Repeat(string(rune('A'+i)), 48)
	}
	s, err := loadSettings(func(k string) string {
		if k == "JUDGE_WORKER_IMAGE_DIGEST" {
			return "sha256:" + strings.Repeat("a", 64)
		}
		if k == "JUDGE_CHECKER_SHA256" {
			return strings.Repeat("b", 64)
		}
		if k == "JUDGE_MATURE_BRIDGE_SHA256" {
			return strings.Repeat("c", 64)
		}
		return ""
	}, func(k string) (string, error) { return values[k], nil })
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCredentialScopes(t *testing.T) {
	s := testSettings(t)
	for role, environment := range map[string][]string{"api": s.apiEnvironment(), "judger": s.judgerEnvironment(), "runtime": s.runtimeEnvironment(), "capacity": s.capacityEnvironment()} {
		joined := strings.Join(environment, "\n")
		for _, secret := range []struct {
			value string
			roles string
		}{
			{s.databaseURL, "api capacity"}, {s.incomingToken, "api"}, {s.outgoingToken, "api"}, {s.cursorKey, "api"},
			{s.schedulerToken, "api judger capacity"}, {s.runtimeToken, "judger runtime"},
		} {
			if strings.Contains(joined, secret.value) != strings.Contains(secret.roles, role) {
				t.Fatalf("%s credential scope violated", role)
			}
		}
		if strings.Contains(joined, "INHERITED_CANARY") {
			t.Fatal("inherited environment")
		}
	}
	if strings.Contains(fmt.Sprintf("%v %#v", s, s), s.runtimeToken) {
		t.Fatal("credential formatting leak")
	}
	if !strings.Contains(strings.Join(s.runtimeEnvironment(), "\n"), "ES_NO_FALLBACK=true") {
		t.Fatal("fallback allowed")
	}
}

func TestRootAmbientCredentialNamesRejected(t *testing.T) {
	for _, name := range []string{"AWS_SESSION_TOKEN", "ES_AUTH_TOKEN", "UNRELATED_PASSWORD", "SMTP_SECRET", "STORAGE_ACCESS_KEY", "DATABASE_URL"} {
		if err := validateRootEnvironment([]string{name + "=synthetic-canary"}); err == nil || strings.Contains(err.Error(), "synthetic-canary") {
			t.Fatal("ambient credential accepted or leaked")
		}
	}
	if validateRootEnvironment([]string{"JUDGE_WORKER_IMAGE_DIGEST=sha256:abc", "JUDGE_MATURE_BRIDGE_SHA256=abc", "JUDGE_ACQUISITION_PROXY=http://proxy:8080"}) != nil {
		t.Fatal("non-secret identity/proxy settings rejected")
	}
}

func TestRootCredentialEnvironmentRejectedBeforeRead(t *testing.T) {
	for _, name := range []string{"JUDGE_DATABASE_URL", "BACKEND_JUDGE_TOKEN", "JUDGE_BACKEND_TOKEN", "JUDGE_RUNTIME_TOKEN", "JUDGE_SCHEDULER_TOKEN", "JUDGE_CATALOG_CURSOR_KEY"} {
		_, err := loadSettings(func(k string) string {
			if k == name {
				return "INHERITED_CANARY"
			}
			return ""
		}, func(string) (string, error) {
			t.Fatal("secret facility read after root credential violation")
			return "", nil
		})
		if err == nil || strings.Contains(err.Error(), "INHERITED_CANARY") {
			t.Fatal("root credential setting accepted or leaked")
		}
	}
}

func TestSecretFileBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	write := func(value string, mode os.FileMode) {
		t.Helper()
		os.Remove(path)
		if os.WriteFile(path, []byte(value), mode) != nil {
			t.Fatal("fixture write")
		}
		// Keep each permission fixture exact even under a restrictive caller umask.
		if os.Chmod(path, mode) != nil {
			t.Fatal("fixture permissions")
		}
	}
	write("synthetic-token", 0400)
	if value, err := readSecretFile(path, uint32(os.Geteuid())); err != nil || value != "synthetic-token" {
		t.Fatal("valid facility rejected")
	}
	for _, fixture := range []struct {
		value string
		mode  os.FileMode
	}{{"", 0400}, {"secret\n", 0400}, {strings.Repeat("x", 4097), 0400}, {"secret", 0444}, {"secret", 0600}} {
		write(fixture.value, fixture.mode)
		if _, err := readSecretFile(path, uint32(os.Geteuid())); err == nil {
			t.Fatal("unsafe secret file accepted")
		}
	}
	write("secret", 0400)
	alias := path + "-alias"
	if os.Link(path, alias) != nil {
		t.Fatal("hardlink fixture")
	}
	if _, err := readSecretFile(path, uint32(os.Geteuid())); err == nil {
		t.Fatal("hardlinked secret accepted")
	}
	os.Remove(alias)
	if os.Symlink(path, alias) != nil {
		t.Fatal("symlink fixture")
	}
	if _, err := readSecretFile(alias, uint32(os.Geteuid())); err == nil {
		t.Fatal("symlink secret accepted")
	}
	if _, err := readSecretFile(path, uint32(os.Geteuid()+1)); err == nil {
		t.Fatal("wrong owner accepted")
	}
}
