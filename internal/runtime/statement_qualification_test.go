// SPDX-License-Identifier: Apache-2.0
package runtime

import (
	"strings"
	"testing"
)

func TestStatementArtifactReportRequiresOriginalArtifactAndParentDenial(t *testing.T) {
	const digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	valid := `{"ok":true,"errors":0,"warnings":0,"parentProcessDenied":true,"artifacts":{"kind":"HTML","manifestSha256":"` + digest + `","fileCount":2,"fileBytes":101,"primarySha256":"` + digest + `","primaryBytes":100,"mathElements":1}}`
	if artifact, e := statementArtifactReport([]byte(valid), "HTML"); e != nil || artifact.MathElements != 1 {
		t.Fatal("valid original artifact evidence rejected")
	}
	for _, raw := range []string{
		strings.Replace(valid, `"parentProcessDenied":true`, `"parentProcessDenied":false`, 1),
		strings.Replace(valid, `"parentProcessDenied":true,`, ``, 1),
		strings.Replace(valid, `"errors":0`, `"errors":1`, 1),
		strings.Replace(valid, `"warnings":0`, `"warnings":null`, 1),
		strings.Replace(valid, `"primaryBytes":100`, `"primaryBytes":102`, 1),
		strings.Replace(valid, `"mathElements":1`, `"mathElements":null`, 1),
		strings.Replace(valid, `"kind":"HTML"`, `"kind":"PDF"`, 1),
		strings.Replace(valid, `"fileCount":2`, `"fileCount":4097`, 1),
		strings.Replace(valid, `"fileBytes":101`, `"fileBytes":268435457`, 1),
		strings.Replace(valid, `"ok":true`, `"ok":true,"ok":true`, 1),
		strings.Replace(valid, `"kind":"HTML"`, `"kind":"HTML","filename":"private-path"`, 1),
	} {
		if _, e := statementArtifactReport([]byte(raw), "HTML"); e == nil {
			t.Fatal("invalid private helper evidence accepted")
		}
	}
	pdf := strings.Replace(strings.Replace(valid, `"kind":"HTML"`, `"kind":"PDF"`, 1), `"mathElements":1`, `"mathElements":0`, 1)
	if _, e := statementArtifactReport([]byte(pdf), "PDF"); e != nil {
		t.Fatal("valid original sanitized PDF evidence rejected")
	}
}

func TestStatementQualificationRequiresMeasuredPublicWorkspace(t *testing.T) {
	digest := strings.Repeat("a", 64)
	raw := `{"ok":true,"errors":0,"warnings":0,"parentProcessDenied":true,"artifacts":{"kind":"PDF","manifestSha256":"` + digest + `","fileCount":1,"fileBytes":100,"primarySha256":"` + digest + `","primaryBytes":100,"mathElements":0},"workspace":{"transportBytes":10240,"regularBytes":4096,"regularFiles":6,"totalBytes":2147483648,"totalInodes":262144,"peakObservedUsedBytes":16384,"peakObservedUsedInodes":12}}`
	if artifact, facts, e := statementQualificationReport([]byte(raw), "PDF"); e != nil || artifact.Kind != "PDF" || facts.RegularFiles != 6 {
		t.Fatal("actual bounded public workspace evidence rejected")
	}
	for _, invalid := range []string{
		strings.Replace(raw, `"totalInodes":262144`, `"totalInodes":262143`, 1),
		strings.Replace(raw, `"peakObservedUsedBytes":16384`, `"peakObservedUsedBytes":14335`, 1),
		strings.Replace(raw, `"peakObservedUsedInodes":12`, `"peakObservedUsedInodes":5`, 1),
		strings.Replace(raw, `"regularFiles":6`, `"regularFiles":65537`, 1),
		strings.Replace(raw, `"regularBytes":4096`, `"regularBytes":536870913`, 1),
		strings.Replace(raw, `"transportBytes":10240`, `"transportBytes":805306369`, 1),
		strings.Replace(raw, `"totalBytes":2147483648`, `"totalBytes":2147483649`, 1),
		strings.Replace(raw, `"totalBytes":2147483648,`, "", 1),
		strings.Replace(raw, `"totalBytes":2147483648`, `"totalBytes":null`, 1),
		strings.Replace(raw, `"totalBytes":2147483648`, `"totalBytes":2147483648,"totalBytes":2147483648`, 1),
		strings.Replace(raw, `"totalBytes":2147483648`, `"totalBytes":2147483648,"privatePath":"canary"`, 1),
	} {
		if _, _, e := statementQualificationReport([]byte(invalid), "PDF"); e == nil {
			t.Fatal("incomplete, unbounded or insufficient public workspace evidence accepted")
		}
	}
}
