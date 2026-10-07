package problems

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
)

func TestReviewAlternateProfileAuditRetainedWithoutChangingSelectedQualification(t *testing.T) {
	f := makeImmutableFixture(t)
	artifact := f.qualified(t)
	selected, err := f.repository.LoadArtifact(context.Background(), artifact.ID)
	if err != nil || selected.ValidationRunID == nil {
		t.Fatal("synthetic original qualification missing")
	}
	id, err := contract.NewUUID()
	if err != nil {
		t.Fatal("cannot allocate synthetic audit identity")
	}
	auditContext := f.spec.ValidationContext
	auditContext.ImageDigest = "sha256:" + strings.Repeat("e", 64)
	auditContext.ToolchainVersion = "synthetic-alternate-audit-toolchain"
	auditContext.ConfigSHA256 = strings.Repeat("f", 64)
	audit := ValidationRun{ID: id, PackageArtifactID: artifact.ID, Status: "PASSED", Context: auditContext, Results: checkpointResults(true), Errors: []contract.TaskError{}, Adaptations: json.RawMessage(`[]`), StartedAt: time.Now().Add(-time.Second), FinishedAt: time.Now()}
	// Q-005 permits audit evidence under a different toolchain/profile for the
	// same source/content. Only qualification selection needs exact context.
	if err := f.repository.WithTx(context.Background(), nil, func(tx *Tx) error { return tx.AppendValidation(audit) }); err != nil {
		t.Fatal("same-content alternate-profile audit was not retained")
	}
	loaded, err := f.repository.LoadValidation(context.Background(), id)
	if err != nil || loaded.Context != auditContext || loaded.PackageArtifactID != artifact.ID {
		t.Fatal("retained audit lost its actual context or artifact identity")
	}
	if err := f.repository.WithTx(context.Background(), nil, func(tx *Tx) error { return tx.SelectValidation(artifact.ID, id) }); !errors.Is(err, ErrIntegrity) {
		t.Fatal("alternate-profile audit replaced the frozen qualification")
	}
	after, err := f.repository.LoadArtifact(context.Background(), artifact.ID)
	if err != nil || after.ValidationRunID == nil || *after.ValidationRunID != *selected.ValidationRunID || after.Spec.ValidationContext != selected.Spec.ValidationContext {
		t.Fatal("audit rewrote the historical qualifying run or context")
	}
	borrowed := audit
	borrowed.ID, _ = contract.NewUUID()
	borrowed.Context.SourceSHA256 = strings.Repeat("0", 64)
	if err := f.repository.WithTx(context.Background(), nil, func(tx *Tx) error { return tx.AppendValidation(borrowed) }); !errors.Is(err, ErrIntegrity) {
		t.Fatal("alternate-profile audit borrowed a different package source")
	}
}
