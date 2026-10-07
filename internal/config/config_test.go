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

func TestOptionalCapabilitySecretsRemainIndependent(t *testing.T) {
	values := settings()
	values["JUDGE_SCHEDULER_TOKEN"] = strings.Repeat("c", 32)
	values["JUDGE_CATALOG_CURSOR_KEY"] = strings.Repeat("d", 32)
	c, e := Load(func(k string) string { return values[k] })
	if e != nil {
		t.Fatal(e)
	}
	if c.SchedulerToken() != values["JUDGE_SCHEDULER_TOKEN"] || string(c.CatalogCursorKey()) != values["JUDGE_CATALOG_CURSOR_KEY"] {
		t.Fatal("capability credential missing")
	}
	for _, secret := range []string{c.SchedulerToken(), string(c.CatalogCursorKey())} {
		if strings.Contains(fmt.Sprintf("%#v", c), secret) {
			t.Fatal("capability credential leaked")
		}
	}
	for _, name := range []string{"JUDGE_SCHEDULER_TOKEN", "JUDGE_CATALOG_CURSOR_KEY"} {
		original := values[name]
		values[name] = values["BACKEND_JUDGE_TOKEN"]
		if _, e := Load(func(k string) string { return values[k] }); e == nil {
			t.Fatalf("%s reused service credential", name)
		}
		values[name] = "short"
		if _, e := Load(func(k string) string { return values[k] }); e == nil {
			t.Fatalf("%s accepted weak key", name)
		}
		values[name] = original
	}
	values["JUDGE_CATALOG_CURSOR_KEY"] = strings.Repeat("d", 1025)
	if _, e := Load(func(k string) string { return values[k] }); e == nil {
		t.Fatal("cursor authority accepted an unsupported key size")
	}
}

func TestAcquisitionProxyIsOptionalPrivateOperatorTransport(t *testing.T) {
	values := settings()
	values["HTTPS_PROXY"] = "http://ambient-proxy.invalid:8080"
	values["ALL_PROXY"] = "socks5://ambient-proxy.invalid:1080"
	c, err := Load(func(key string) string { return values[key] })
	if err != nil || c.AcquisitionProxyURL() != "" {
		t.Fatal("direct acquisition default changed or inherited ambient proxy")
	}
	for _, proxy := range []string{"http://operator-proxy.invalid:8080", "https://operator-proxy.invalid/", "socks5://127.0.0.1:1080", "http://[::1]:8080"} {
		values["JUDGE_ACQUISITION_PROXY"] = proxy
		c, err := Load(func(key string) string { return values[key] })
		if err != nil || c.AcquisitionProxyURL() != proxy {
			t.Fatal("valid explicit acquisition transport rejected")
		}
		encoded, err := json.Marshal(c)
		if err != nil {
			t.Fatal("cannot encode redacted configuration")
		}
		for _, formatted := range []string{fmt.Sprint(c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c), string(encoded)} {
			if strings.Contains(formatted, proxy) {
				t.Fatal("configuration formatting exposed private acquisition address")
			}
		}
	}
}

func TestInvalidAcquisitionProxyIsRedacted(t *testing.T) {
	for _, proxy := range []string{
		"http://proxy-user:proxy-secret@proxy.invalid:8080",
		"http://proxy-user@proxy.invalid:8080", "http://@proxy.invalid:8080",
		"http://proxy.invalid?secret=value", "http://proxy.invalid?", "http://proxy.invalid#private", "http://proxy.invalid#",
		"http://proxy.invalid/private", "http:proxy.invalid", "//proxy.invalid:8080",
		"file:///private", "ftp://proxy.invalid", "socks5h://proxy.invalid:1080",
		"http://", "http://proxy.invalid:0", "http://proxy.invalid:65536", "http://proxy.invalid:",
		"http://proxy.invalid:wrong", "http://proxy.invalid\n", "http://proxy.invalid/\xff",
		"http://" + strings.Repeat("p", 2048),
	} {
		values := settings()
		values["JUDGE_ACQUISITION_PROXY"] = proxy
		_, err := Load(func(key string) string { return values[key] })
		if err == nil {
			t.Fatal("invalid acquisition transport accepted")
		}
		if err.Error() != "invalid or missing setting JUDGE_ACQUISITION_PROXY" {
			t.Fatal("invalid transport did not produce bounded setting error")
		}
	}
}
