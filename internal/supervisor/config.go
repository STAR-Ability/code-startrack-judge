// Package supervisor launches only the reviewed service-owned processes.
// Linux isolation of submitted programs remains the pinned go-judge's job.
package supervisor

import (
	"crypto/subtle"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"syscall"

	"github.com/STAR-Ability/code-startrack-judge/internal/config"
)

const (
	APIUID                = 20000
	JudgerUID             = 20001
	SchedulingGID         = 20002
	RuntimeHostUID        = 30000
	SecretsDirectory      = "/run/secrets/startrack"
	QualificationPath     = "/run/startrack-supervisor/runtime-measurement.json"
	PrivateDirectory      = "/var/lib/startrack/private"
	RuntimeDirectory      = "/run/startrack-runtime/roots"
	RuntimeCacheDirectory = "/run/startrack-runtime/cache"
	SocketDirectory       = "/run/startrack"
	SchedulingSocket      = "/run/startrack/judger.sock"
	RuntimeBinary         = "/usr/local/libexec/startrack/go-judge"
	RuntimeInitBinary     = "/usr/local/libexec/startrack/runtime-init"
	APIBinary             = "/usr/local/libexec/startrack/judge-service"
	JudgerBinary          = "/usr/local/libexec/startrack/startrack-judger"
	MountProfile          = "/opt/startrack/mount.yaml"
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type settings struct {
	databaseURL, incomingToken, outgoingToken, runtimeToken, schedulerToken, cursorKey string
	imageDigest, checkerDigest, bridgeDigest, acquisitionProxy                         string
	qualificationOnly                                                                  bool
	capacityPhase                                                                      string
}

func (settings) String() string     { return "supervisor settings [credentials redacted]" }
func (s settings) GoString() string { return s.String() }

type failure struct{ code string }

func (e failure) Error() string { return "supervisor " + e.code + " failure" }
func fail(code string) error    { return failure{code: code} }

func loadSettings(getenv func(string) string, read func(string) (string, error)) (settings, error) {
	for _, name := range []string{"JUDGE_DATABASE_URL", "BACKEND_JUDGE_TOKEN", "JUDGE_BACKEND_TOKEN", "JUDGE_RUNTIME_TOKEN", "JUDGE_SCHEDULER_TOKEN", "JUDGE_CATALOG_CURSOR_KEY"} {
		if getenv(name) != "" {
			return settings{}, fail("root_business_environment")
		}
	}
	s := settings{imageDigest: getenv("JUDGE_WORKER_IMAGE_DIGEST"), checkerDigest: getenv("JUDGE_CHECKER_SHA256"), bridgeDigest: getenv("JUDGE_MATURE_BRIDGE_SHA256"), acquisitionProxy: getenv("JUDGE_ACQUISITION_PROXY"), qualificationOnly: getenv("JUDGE_QUALIFICATION_ONLY") == "true"}
	s.capacityPhase = getenv("JUDGE_QUALIFICATION_CAPACITY_PHASE")
	if s.capacityPhase != "" && (!s.qualificationOnly || (s.capacityPhase != "reject" && s.capacityPhase != "validate")) {
		return settings{}, fail("qualification_capacity_phase")
	}
	if !digestPattern.MatchString(s.imageDigest) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(s.checkerDigest) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(s.bridgeDigest) {
		return settings{}, fail("image_identity")
	}
	if config.ValidateAcquisitionProxyURL(s.acquisitionProxy) != nil {
		return settings{}, fail("acquisition_proxy")
	}
	values := []*string{&s.databaseURL, &s.incomingToken, &s.outgoingToken, &s.runtimeToken, &s.schedulerToken, &s.cursorKey}
	for i, name := range []string{"database-url", "backend-judge-token", "judge-backend-token", "runtime-token", "scheduler-token", "catalog-cursor-key"} {
		value, err := read(name)
		if err != nil {
			return settings{}, err
		}
		*values[i] = value
	}
	if config.ValidateDatabaseURL(s.databaseURL) != nil {
		return settings{}, fail("database_configuration")
	}
	tokens := []string{s.incomingToken, s.outgoingToken, s.runtimeToken, s.schedulerToken, s.cursorKey}
	for i, token := range tokens {
		if !config.ValidServiceToken(token) {
			return settings{}, fail("credential_configuration")
		}
		for _, previous := range tokens[:i] {
			if subtle.ConstantTimeCompare([]byte(token), []byte(previous)) == 1 {
				return settings{}, fail("credential_independence")
			}
		}
	}
	return s, nil
}

// Secret files are an operator-owned facility, not caller paths. No root
// process receives business credentials through its environment or argv.
func readSecretFile(path string, owner uint32) (string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", fail("secret_file")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0400 || info.Size() < 1 || info.Size() > 4096 {
		return "", fail("secret_file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != owner || stat.Nlink != 1 {
		return "", fail("secret_file")
	}
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(b) != int(info.Size()) || len(b) > 4096 || strings.ContainsAny(string(b), "\x00\r\n") {
		return "", fail("secret_file")
	}
	return string(b), nil
}

func (s settings) apiEnvironment() []string {
	return []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8", "TZ=UTC", "HOME=/nonexistent", "TMPDIR=/run/startrack-api/tmp", "JUDGE_LISTEN_ADDR=0.0.0.0:8082", "JUDGE_PRIVATE_STORAGE_DIR=" + PrivateDirectory, "JUDGE_DATABASE_URL=" + s.databaseURL, "BACKEND_JUDGE_TOKEN=" + s.incomingToken, "JUDGE_BACKEND_TOKEN=" + s.outgoingToken, "JUDGE_SCHEDULER_TOKEN=" + s.schedulerToken, "JUDGE_CATALOG_CURSOR_KEY=" + s.cursorKey, "JUDGE_WORKER_IMAGE_DIGEST=" + s.imageDigest, "JUDGE_CHECKER_SHA256=" + s.checkerDigest, "JUDGE_MATURE_BRIDGE_SHA256=" + s.bridgeDigest, "JUDGE_ACQUISITION_PROXY=" + s.acquisitionProxy}
}

func (s settings) judgerEnvironment() []string {
	return []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8", "TZ=UTC", "HOME=/nonexistent", "TMPDIR=/run/startrack-judger/tmp", "JUDGE_RUNTIME_TOKEN=" + s.runtimeToken, "JUDGE_SCHEDULER_TOKEN=" + s.schedulerToken, "JUDGE_SCHEDULER_FD=3", "JUDGE_WORKER_IMAGE_DIGEST=" + s.imageDigest, "JUDGE_CHECKER_SHA256=" + s.checkerDigest, "JUDGE_MATURE_BRIDGE_SHA256=" + s.bridgeDigest}
}

func (s settings) capacityEnvironment() []string {
	return []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8", "TZ=UTC", "HOME=/nonexistent", "TMPDIR=/run/startrack-api/tmp", "JUDGE_QUALIFICATION_ONLY=true", "JUDGE_PRIVATE_STORAGE_DIR=" + PrivateDirectory, "JUDGE_DATABASE_URL=" + s.databaseURL, "JUDGE_SCHEDULER_TOKEN=" + s.schedulerToken}
}

func (s settings) runtimeEnvironment() []string {
	return []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8", "TZ=UTC", "HOME=/nonexistent", "TMPDIR=" + RuntimeDirectory, "ES_AUTH_TOKEN=" + s.runtimeToken, "ES_HTTP_ADDR=127.0.0.1:5050", "ES_ENABLE_GRPC=false", "ES_ENABLE_METRICS=false", "ES_ENABLE_DEBUG=false", "ES_NO_FALLBACK=true", "ES_NO_SECCOMP=false", "ES_NET_SHARE=false", "ES_CONTAINER_CRED_START=1000", "ES_PARALLELISM=2", "ES_PRE_FORK=2", "ES_MOUNT_CONF=" + MountProfile, "ES_DIR=" + RuntimeCacheDirectory, "ES_FILE_TIMEOUT=5m", "ES_RELEASE=true"}
}

func validateRootEnvironment(environment []string) error {
	for _, entry := range environment {
		name, value, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(name)
		// The immutable official Python base records its public release signing
		// key fingerprint as GPG_KEY; it is provenance, not an injected secret.
		if upper == "GPG_KEY" && value == "A035C8C19219BA821ECEA86B64E628F8D684696D" {
			continue
		}
		if value != "" && (strings.HasPrefix(upper, "AWS_") || strings.HasPrefix(upper, "ES_") || strings.Contains(upper, "TOKEN") || strings.Contains(upper, "PASSWORD") || strings.Contains(upper, "SECRET") || strings.Contains(upper, "DATABASE") || strings.HasSuffix(upper, "_KEY")) {
			return fail("root_business_environment")
		}
	}
	return nil
}

func roleLabel(name string, pid int) string {
	return fmt.Sprintf("supervisor child [%s pid=%d]", name, pid)
}
