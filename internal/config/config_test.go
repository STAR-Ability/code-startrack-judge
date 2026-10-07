package config

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func settings() map[string]string {
	return map[string]string{"JUDGE_DATABASE_URL": "postgres://judge:synthetic-db-password@127.0.0.1:15432/judge?sslmode=disable", "JUDGE_PRIVATE_STORAGE_DIR": "/tmp/startrack-private-test", "BACKEND_JUDGE_TOKEN": strings.Repeat("a", 32), "JUDGE_BACKEND_TOKEN": strings.Repeat("b", 32)}
}
func TestLoadAndSecretRedaction(t *testing.T) {
	v := settings()
	c, e := Load(func(k string) string { return v[k] })
	if e != nil {
		t.Fatal(e)
	}
	if c.ListenAddr != "0.0.0.0:8082" || c.DatabaseURL() != v["JUDGE_DATABASE_URL"] || c.BackendJudgeToken() != v["BACKEND_JUDGE_TOKEN"] || c.JudgeBackendToken() != v["JUDGE_BACKEND_TOKEN"] {
		t.Fatal("config values lost")
	}
	b, _ := json.Marshal(c)
	for _, formatted := range []string{fmt.Sprint(c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c), string(b)} {
		for _, secret := range []string{"synthetic-db-password", v["BACKEND_JUDGE_TOKEN"], v["JUDGE_BACKEND_TOKEN"]} {
			if strings.Contains(formatted, secret) {
				t.Fatal("config formatting leaked credential")
			}
		}
	}
	v["JUDGE_CALLBACK_URL"] = "http://attacker/"
	if _, e := Load(func(k string) string { return v[k] }); e != nil {
		t.Fatal(e)
	}
	if BackendCallbackURL != "http://backend:8081/internal/v2/events/judge" {
		t.Fatal("callback destination changed")
	}
}
func TestInvalidConfigurationIsRedacted(t *testing.T) {
	tests := map[string]struct{ key, value string }{
		"missing db": {"JUDGE_DATABASE_URL", ""}, "db parse": {"JUDGE_DATABASE_URL", "postgres://judge:secret@%%%/judge"}, "missing password": {"JUDGE_DATABASE_URL", "postgres://judge@localhost/judge?sslmode=disable"},
		"remote no TLS": {"JUDGE_DATABASE_URL", "postgres://judge:secret@db/judge?sslmode=disable"}, "TLS unspecified": {"JUDGE_DATABASE_URL", "postgres://judge:secret@db/judge"}, "duplicate TLS": {"JUDGE_DATABASE_URL", "postgres://judge:secret@db/judge?sslmode=require&sslmode=disable"},
		"host override": {"JUDGE_DATABASE_URL", "postgres://judge:secret@localhost/judge?sslmode=disable&host=remote.example"}, "port override": {"JUDGE_DATABASE_URL", "postgres://judge:secret@localhost/judge?sslmode=disable&port=5432"}, "user override": {"JUDGE_DATABASE_URL", "postgres://judge:secret@localhost/judge?sslmode=disable&user=owner"}, "database override": {"JUDGE_DATABASE_URL", "postgres://judge:secret@localhost/judge?sslmode=disable&dbname=backend"}, "service override": {"JUDGE_DATABASE_URL", "postgres://judge:secret@localhost/judge?sslmode=disable&service=alternate"}, "remote encrypt only": {"JUDGE_DATABASE_URL", "postgres://judge:secret@db/judge?sslmode=require"}, "remote no host verification": {"JUDGE_DATABASE_URL", "postgres://judge:secret@db/judge?sslmode=verify-ca"},
		"relative storage": {"JUDGE_PRIVATE_STORAGE_DIR", "private"}, "root storage": {"JUDGE_PRIVATE_STORAGE_DIR", "/"}, "unclean storage": {"JUDGE_PRIVATE_STORAGE_DIR", "/tmp/../private"}, "invalid listen": {"JUDGE_LISTEN_ADDR", "public:8082"},
		"short token": {"BACKEND_JUDGE_TOKEN", "secret"}, "token placeholder": {"BACKEND_JUDGE_TOKEN", "REPLACE_" + strings.Repeat("x", 32)}, "token whitespace": {"BACKEND_JUDGE_TOKEN", strings.Repeat("x", 32) + "\n"}, "same credentials": {"JUDGE_BACKEND_TOKEN", strings.Repeat("a", 32)},
	}
	for name, x := range tests {
		t.Run(name, func(t *testing.T) {
			v := settings()
			v[x.key] = x.value
			_, e := Load(func(k string) string { return v[k] })
			if e == nil {
				t.Fatal("invalid setting accepted")
			}
			if strings.Contains(e.Error(), "secret") || strings.Contains(e.Error(), "postgres://") || strings.Contains(e.Error(), strings.Repeat("a", 32)) {
				t.Fatal("configuration error leaked a secret")
			}
		})
	}
	v := settings()
	v["JUDGE_DATABASE_URL"] = "postgres://judge:secret@db:5432/judge?sslmode=verify-full"
	if _, e := Load(func(k string) string { return v[k] }); e != nil {
		t.Fatal("remote TLS config rejected", e)
	}
}
