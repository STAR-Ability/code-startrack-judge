//go:build linux

package supervisor

import (
	"strings"
	"testing"
)

func TestCapacityReportRejectsUnscopedEvidence(t *testing.T) {
	valid := `{"schemaVersion":1,"scope":"DISPOSABLE_SYNTHETIC_API_IMPORT_CAPACITY","syntheticFixture":true,"phase":"reject","passed":true,"code":"IMPORT_CAPACITY_PASSED","uid":20000,"cgroup":"/service","declaredLimits":"fixed","cases":[{"name":"MEMBER_PAYLOAD","status":"FAILED","noPublication":true},{"name":"SAMPLE_SUPPORTED","status":"FAILED","noPublication":true},{"name":"SAMPLE_HEAVY","status":"FAILED","noPublication":true}]}`
	if _, err := decodeCapacityOutcome([]byte(valid), "reject"); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{
		strings.Replace(valid, `"uid":20000`, `"uid":0`, 1),
		strings.Replace(valid, `"phase":"reject"`, `"phase":"validate"`, 1),
		strings.Replace(valid, `"cgroup":"/service"`, `"cgroup":"/"`, 1),
		strings.Replace(valid, `"noPublication":true`, `"noPublication":false`, 1),
		strings.Replace(valid, `"declaredLimits":"fixed"`, `"databaseUrl":"private-canary"`, 1),
		strings.Replace(valid, `"name":"MEMBER_PAYLOAD"`, `"name":"MEMBER_PAYLOAD","rawLog":"private-canary"`, 1),
		valid + `{}`,
	} {
		if _, err := decodeCapacityOutcome([]byte(mutation), "reject"); err == nil {
			t.Fatal("unscoped evidence accepted")
		}
	}
}
