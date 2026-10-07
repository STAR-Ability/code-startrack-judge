// Package config validates deployment-owned settings without revealing secrets.
package config

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const BackendCallbackURL = "http://backend:8081/internal/v2/events/judge"

// Config keeps credential-bearing settings private so ordinary formatting and
// JSON logging cannot accidentally expose them. Accessors are for trusted adapters.
type Config struct {
	ListenAddr        string
	PrivateStorageDir string
	databaseURL       string
	backendJudgeToken string
	judgeBackendToken string
	schedulerToken    string
	catalogCursorKey  string
	acquisitionProxy  string
}

func (c Config) DatabaseURL() string         { return c.databaseURL }
func (c Config) BackendJudgeToken() string   { return c.backendJudgeToken }
func (c Config) JudgeBackendToken() string   { return c.judgeBackendToken }
func (c Config) SchedulerToken() string      { return c.schedulerToken }
func (c Config) CatalogCursorKey() []byte    { return []byte(c.catalogCursorKey) }
func (c Config) AcquisitionProxyURL() string { return c.acquisitionProxy }
func (c Config) String() string              { return "judge configuration [credentials and paths redacted]" }
func (c Config) GoString() string            { return c.String() }

// Load consumes only this package's documented settings. Callback destinations,
// language templates, source filenames and shell commands are not configurable
// caller inputs. Dependency access and isolation are checked by readiness later.
func Load(getenv func(string) string) (Config, error) {
	if getenv == nil {
		return Config{}, errors.New("configuration source is required")
	}
	c := Config{ListenAddr: getenv("JUDGE_LISTEN_ADDR"), PrivateStorageDir: getenv("JUDGE_PRIVATE_STORAGE_DIR"), databaseURL: getenv("JUDGE_DATABASE_URL"), backendJudgeToken: getenv("BACKEND_JUDGE_TOKEN"), judgeBackendToken: getenv("JUDGE_BACKEND_TOKEN"), schedulerToken: getenv("JUDGE_SCHEDULER_TOKEN"), catalogCursorKey: getenv("JUDGE_CATALOG_CURSOR_KEY"), acquisitionProxy: getenv("JUDGE_ACQUISITION_PROXY")}
	if c.ListenAddr == "" {
		c.ListenAddr = "0.0.0.0:8082"
	}
	if e := validateListen(c.ListenAddr); e != nil {
		return Config{}, settingError("JUDGE_LISTEN_ADDR")
	}
	if e := validateDatabase(c.databaseURL); e != nil {
		return Config{}, settingError("JUDGE_DATABASE_URL")
	}
	if !filepath.IsAbs(c.PrivateStorageDir) || filepath.Clean(c.PrivateStorageDir) != c.PrivateStorageDir || c.PrivateStorageDir == string(filepath.Separator) || strings.IndexFunc(c.PrivateStorageDir, unicode.IsControl) >= 0 || !utf8.ValidString(c.PrivateStorageDir) {
		return Config{}, settingError("JUDGE_PRIVATE_STORAGE_DIR")
	}
	if !ValidServiceToken(c.backendJudgeToken) {
		return Config{}, settingError("BACKEND_JUDGE_TOKEN")
	}
	if !ValidServiceToken(c.judgeBackendToken) {
		return Config{}, settingError("JUDGE_BACKEND_TOKEN")
	}
	if subtle.ConstantTimeCompare([]byte(c.backendJudgeToken), []byte(c.judgeBackendToken)) == 1 {
		return Config{}, errors.New("incoming and outgoing service credentials must be independent")
	}
	// Optional capability settings permit historical reads while execution or
	// snapshot service initialization is unavailable. Provided keys must be valid
	// and independent; omission never grants a capability or substitutes a secret.
	for _, setting := range []struct{ name, value string }{{"JUDGE_SCHEDULER_TOKEN", c.schedulerToken}, {"JUDGE_CATALOG_CURSOR_KEY", c.catalogCursorKey}} {
		if setting.value != "" && !ValidServiceToken(setting.value) {
			return Config{}, settingError(setting.name)
		}
	}
	if len(c.catalogCursorKey) > 1024 {
		return Config{}, settingError("JUDGE_CATALOG_CURSOR_KEY")
	}
	if err := ValidateAcquisitionProxyURL(c.acquisitionProxy); err != nil {
		return Config{}, err
	}
	secrets := []string{c.backendJudgeToken, c.judgeBackendToken, c.schedulerToken, c.catalogCursorKey}
	for i, value := range secrets {
		if value == "" {
			continue
		}
		for _, other := range secrets[i+1:] {
			if other != "" && subtle.ConstantTimeCompare([]byte(value), []byte(other)) == 1 {
				return Config{}, errors.New("service credentials and cursor key must be independent")
			}
		}
	}
	return c, nil
}
func settingError(name string) error { return fmt.Errorf("invalid or missing setting %s", name) }
func ValidServiceToken(token string) bool {
	upper := strings.ToUpper(token)
	if len(token) < 32 || len(token) > 4096 || !utf8.ValidString(token) {
		return false
	}
	for _, p := range []string{"GENERATED_", "REPLACE_", "EXAMPLE_", "PLACEHOLDER", "<"} {
		if strings.HasPrefix(upper, p) {
			return false
		}
	}
	for _, b := range []byte(token) {
		if b < 0x21 || b > 0x7e {
			return false
		}
	}
	return true
}
func validateListen(addr string) error {
	host, port, e := net.SplitHostPort(addr)
	if e != nil {
		return e
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 {
		return errors.New("port")
	}
	if net.ParseIP(host) == nil {
		return errors.New("IP literal required")
	}
	return nil
}

// ValidateAcquisitionProxyURL validates the shared API/supervisor transport
// policy. Empty means direct acquisition; errors reveal no address or credential.
func ValidateAcquisitionProxyURL(raw string) error {
	if err := validateAcquisitionProxy(raw); err != nil {
		return settingError("JUDGE_ACQUISITION_PROXY")
	}
	return nil
}

// An acquisition proxy is a trusted transport setting for the fixed upstream
// repository. It carries no credentials and is never supplied by an API caller.
func validateAcquisitionProxy(raw string) error {
	if raw == "" {
		return nil
	}
	if len(raw) > 2048 || !utf8.ValidString(raw) || strings.IndexFunc(raw, unicode.IsControl) >= 0 || strings.Contains(raw, "#") {
		return errors.New("acquisition proxy")
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5") || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("acquisition proxy")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return errors.New("acquisition proxy")
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return errors.New("acquisition proxy")
	}
	return nil
}

// ValidateDatabaseURL enforces the shared runtime/migration transport policy.
// Errors identify no credential, connection URL or filesystem path.
func ValidateDatabaseURL(raw string) error {
	if err := validateDatabase(raw); err != nil {
		return settingError("database URL")
	}
	return nil
}

func validateDatabase(raw string) error {
	u, e := url.Parse(raw)
	if e != nil || u == nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.User == nil || u.User.Username() == "" || u.Hostname() == "" || u.Fragment != "" || u.Opaque != "" {
		return errors.New("database URL")
	}
	pw, ok := u.User.Password()
	if !ok || pw == "" {
		return errors.New("database credential")
	}
	if u.Path == "" || u.Path == "/" || strings.Count(u.Path, "/") != 1 || strings.ContainsAny(u.Path, "\x00\r\n") {
		return errors.New("database name")
	}
	if port := u.Port(); port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return errors.New("database port")
		}
	}
	q, e := url.ParseQuery(u.RawQuery)
	if e != nil {
		return e
	}
	allowed := map[string]bool{"sslmode": true, "sslrootcert": true, "sslcert": true, "sslkey": true, "connect_timeout": true, "application_name": true}
	for name, v := range q {
		if !allowed[name] || len(v) != 1 {
			return errors.New("invalid database option")
		}
	}
	loopback := u.Hostname() == "localhost"
	if ip := net.ParseIP(u.Hostname()); ip != nil {
		loopback = ip.IsLoopback()
	}
	switch q.Get("sslmode") {
	case "verify-full":
	case "disable", "require", "verify-ca":
		if !loopback {
			return errors.New("remote database identity verification required")
		}
	default:
		return errors.New("explicit database TLS policy required")
	}
	if value := q.Get("connect_timeout"); value != "" {
		n, e := strconv.Atoi(value)
		if e != nil || n < 1 || n > 30 {
			return errors.New("database connection timeout")
		}
	}
	for _, name := range []string{"sslrootcert", "sslcert", "sslkey"} {
		if value := q.Get(name); value != "" && !filepath.IsAbs(value) {
			return errors.New("database certificate path")
		}
	}
	return nil
}
