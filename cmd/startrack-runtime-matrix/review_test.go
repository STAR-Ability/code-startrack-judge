// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
	"github.com/STAR-Ability/code-startrack-judge/internal/runtime/restclient"
)

func TestReviewMatrixControlRejectsCommandPathsUnknownFieldsAndAmbiguousJSON(t *testing.T) {
	valid := `{"token":"PRIVATE_CONTROL_CANARY","workerImageDigest":"sha256:` + strings.Repeat("a", 64) + `","checkerDigest":"` + strings.Repeat("b", 64) + `","bridgeDigest":"` + strings.Repeat("c", 64) + `"}`
	for _, raw := range []string{
		strings.Replace(valid, `"token":`, `"command":"/bin/sh","token":`, 1),
		strings.Replace(valid, `"token":`, `"path":"/etc/passwd","token":`, 1),
		strings.Replace(valid, `"token":`, `"url":"https://caller.example","token":`, 1),
		strings.Replace(valid, `"token":`, `"token":"SECOND_PRIVATE_CANARY","token":`, 1),
		valid + `{}`,
		strings.Repeat(" ", 4097) + valid,
	} {
		t.Run(fmt.Sprintf("bytes-%d", len(raw)), func(t *testing.T) {
			file, err := os.CreateTemp(t.TempDir(), "control")
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			if _, err := file.WriteString(raw); err != nil {
				t.Fatal(err)
			}
			if _, err := file.Seek(0, 0); err != nil {
				t.Fatal(err)
			}
			original := os.Stdin
			os.Stdin = file
			defer func() { os.Stdin = original }()
			if _, err := readControl(); err == nil || strings.Contains(err.Error(), "PRIVATE_") {
				t.Fatal("unsafe matrix control accepted or private bytes entered ordinary diagnostic")
			}
		})
	}
	control := matrixControl{Token: "PRIVATE_CONTROL_CANARY"}
	if strings.Contains(fmt.Sprintf("%+v %#v", control, control), control.Token) {
		t.Fatal("matrix control credential entered ordinary formatting")
	}
	report := matrixReport{Mature: []matureEvidence{{PrivateLog: privateLogEvidence{SHA256: strings.Repeat("a", 64), Bytes: 100, RetainedSHA256: strings.Repeat("b", 64), RetainedBytes: 50, Truncated: true}}}}
	raw, err := json.Marshal(report)
	if err != nil || strings.Contains(string(raw), control.Token) || strings.Contains(string(raw), "rawLog") || strings.Contains(string(raw), "token") {
		t.Fatal("matrix structural report contains private credential/log fields")
	}
}

type reviewClosingSession struct{ failed bool }

func (*reviewClosingSession) Upload(context.Context, []byte) (restclient.FileID, error) {
	panic("unexpected review upload")
}
func (*reviewClosingSession) Run(context.Context, restclient.Request) ([]restclient.Result, error) {
	panic("unexpected review execution")
}
func (*reviewClosingSession) Download(context.Context, restclient.FileID, int64) ([]byte, error) {
	panic("unexpected review download")
}
func (s *reviewClosingSession) Close() error {
	if !s.failed {
		s.failed = true
		return errors.New("synthetic cleanup failure")
	}
	return nil
}

var _ judgeruntime.Session = (*reviewClosingSession)(nil)

func TestReviewMatrixSessionCleanupIsCountedOnlyOnceAfterSuccess(t *testing.T) {
	factory := &matrixFactory{}
	session := &matrixSession{Session: &reviewClosingSession{}, factory: factory}
	if session.Close() == nil || factory.cleaned.Load() != 0 {
		t.Fatal("failed session cleanup was counted as successful evidence")
	}
	if session.Close() != nil || session.Close() != nil || factory.cleaned.Load() != 1 {
		t.Fatal("successful cleanup was missed or counted more than once")
	}
}
