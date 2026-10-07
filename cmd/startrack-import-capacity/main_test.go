// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"bytes"
	"context"
	"testing"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/packages"
	"github.com/STAR-Ability/code-startrack-judge/internal/storage"
	"github.com/STAR-Ability/code-startrack-judge/internal/testutil/importcapacity"
)

func TestOperatorInterfaceRejectsCallerSelectedOperations(t *testing.T) {
	for _, args := range [][]string{nil, {"validate"}, {"--phase", "publish"}, {"--phase", "validate", "--source", "/tmp/package"}, {"--phase=reject"}, {"--phase", "validate;id"}} {
		if _, err := phaseArgument(args); err == nil {
			t.Fatal("unfixed operator command accepted")
		}
	}
	for _, phase := range []string{"reject", "validate"} {
		if got, err := phaseArgument([]string{"--phase", phase}); err != nil || got != phase {
			t.Fatal("fixed phase rejected")
		}
	}
}

func TestCredentialScopeAndDisposableDatabaseCannotExpand(t *testing.T) {
	base := []string{"JUDGE_QUALIFICATION_ONLY=true", "JUDGE_DATABASE_URL=private", "JUDGE_SCHEDULER_TOKEN=private", "JUDGE_PRIVATE_STORAGE_DIR=" + privateDirectory, "PATH=/usr/bin:/bin", "LANG=C", "TZ=UTC", "HOME=/nonexistent", "TMPDIR=/run/startrack-api/tmp"}
	if !validEnvironment(base) {
		t.Fatal("fixed role environment rejected")
	}
	for _, extra := range []string{"JUDGE_RUNTIME_TOKEN=private", "JUDGE_LICENSE_REVIEW_DATABASE_URL=private", "BACKEND_JUDGE_TOKEN=private", "JUDGE_BACKEND_TOKEN=private", "PGPASSWORD=private", "HTTPS_PROXY=http://untrusted", "JUDGE_DATABASE_URL=second", "malformed"} {
		if validEnvironment(append(append([]string(nil), base...), extra)) {
			t.Fatal("ambient credential, transport, or duplicate key accepted")
		}
	}
	for _, dsn := range []string{"postgres://judge_runtime:private@127.0.0.1/judge_capacity_qualification?sslmode=disable", "postgres://judge_runtime:private@postgres.invalid/judge_capacity_qualification?sslmode=verify-full"} {
		if !disposableDSN(dsn) {
			t.Fatal("fixed disposable runtime database rejected")
		}
	}
	for _, dsn := range []string{"postgres://judge_runtime:private@127.0.0.1/judge?sslmode=disable", "postgres://judge_migration:private@127.0.0.1/judge_capacity_qualification?sslmode=disable", "postgres://judge_license_reviewer:private@127.0.0.1/judge_capacity_qualification?sslmode=disable", "postgres://judge_runtime:private@postgres.invalid/judge_capacity_qualification?sslmode=disable", "postgres://judge_runtime:private@127.0.0.1/judge_capacity_qualification?sslmode=disable&sslkey=/run/secrets/key", "postgres://judge_runtime:private@127.0.0.1/judge_capacity_qualification?sslmode=disable&options=-crole=judge_migration"} {
		if disposableDSN(dsn) {
			t.Fatal("broader database scope accepted")
		}
	}
}

func TestSyntheticAcquisitionRejectsUnknownInputsBeforeAllocating(t *testing.T) {
	source := &fixedSource{facts: make(map[string]acquisitionFact)}
	for _, input := range []struct{ revision, path string }{{"other", "problems/synthetic-api-sample-heavy"}, {packages.PinnedRevision, "problems/arbitrary"}, {packages.PinnedRevision, "../../outside"}} {
		if _, err := source.Acquire(context.Background(), input.revision, input.path); err == nil || len(source.facts) != 0 {
			t.Fatal("source seam acquired an unfixed package")
		}
	}
}

func TestOversizeQualificationCannotMaskRightsOrTechnicalFailure(t *testing.T) {
	path, _ := importcapacity.Path(importcapacity.SampleHeavy)
	item := contract.ImportItem{PackagePath: path, Status: "REJECTED", LicenseStatus: "VERIFIED", ValidationStatus: "FAILED", Errors: contract.Array[contract.TaskError]{{Code: "PACKAGE_UNSUPPORTED", Message: "bounded rejection", Retryable: false}}}
	job := contract.ImportJob{Status: contract.ImportFailed, Items: contract.Array[contract.ImportItem]{item}}
	if !expectedOversizeOutcome(job) {
		t.Fatal("approved structured oversized rejection rejected")
	}
	mutations := []func(*contract.ImportJob){
		func(job *contract.ImportJob) { job.Status = contract.ImportSucceeded },
		func(job *contract.ImportJob) { job.Items = nil },
		func(job *contract.ImportJob) { job.Items = append(job.Items, item) },
		func(job *contract.ImportJob) { job.Items[0].PackagePath = "problems/arbitrary" },
		func(job *contract.ImportJob) { job.Items[0].Status = "VALIDATED" },
		func(job *contract.ImportJob) { job.Items[0].LicenseStatus = "REVIEW_REQUIRED" },
		func(job *contract.ImportJob) { job.Items[0].ValidationStatus = "PENDING" },
		func(job *contract.ImportJob) { id := contract.ID("1"); job.Items[0].ProblemID = &id },
		func(job *contract.ImportJob) {
			id := contract.UUID("00000000-0000-4000-8000-000000000001")
			job.Items[0].ProblemVersionID = &id
		},
		func(job *contract.ImportJob) { job.Items[0].Errors[0].Code = "PACKAGE_VALIDATION_FAILED" },
		func(job *contract.ImportJob) { job.Items[0].Errors[0].Retryable = true },
		func(job *contract.ImportJob) {
			job.Items[0].Errors = append(job.Items[0].Errors, contract.TaskError{Code: "PACKAGE_INVALID"})
		},
	}
	for _, mutate := range mutations {
		changed := job
		changed.Items = append(contract.Array[contract.ImportItem]{}, job.Items...)
		changed.Items[0].Errors = append(contract.Array[contract.TaskError]{}, item.Errors...)
		mutate(&changed)
		if expectedOversizeOutcome(changed) {
			t.Fatal("a different failure or registered problem qualified as expected oversized rejection")
		}
	}
}

func TestArchiveEvidenceBindsActualMemberCountBytesAndHash(t *testing.T) {
	files := []packages.File{{Path: "a", Data: []byte("abc")}, {Path: "empty", Data: []byte{}}, {Path: "nested/b", Data: []byte("five!")}}
	raw, err := packages.BuildArchive(files)
	if err != nil {
		t.Fatal(err)
	}
	object, err := storage.Blob(canonical.HashBytes(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	facts, err := scanArchive(context.Background(), bytes.NewReader(raw), object, false)
	if err != nil || facts.files != 3 || facts.regularBytes != 8 {
		t.Fatal("actual retained archive count or regular bytes omitted")
	}
	for _, mutation := range []struct {
		raw []byte
		obj storage.Object
	}{{raw[:len(raw)-1], object}, {append(append([]byte(nil), raw...), 0), object}, {raw, storage.Object{Key: object.Key, SHA256: object.SHA256, SizeBytes: object.SizeBytes + 1}}, {raw, storage.Object{Key: object.Key, SHA256: object.SHA256, SizeBytes: object.SizeBytes - 1}}} {
		if _, err := scanArchive(context.Background(), bytes.NewReader(mutation.raw), mutation.obj, false); err == nil {
			t.Fatal("archive size mismatch qualified")
		}
	}
	corrupt := append([]byte(nil), raw...)
	corrupt[512] ^= 1
	if _, err := scanArchive(context.Background(), bytes.NewReader(corrupt), object, false); err == nil {
		t.Fatal("byte corruption qualified")
	}
	if _, err := scanArchive(context.Background(), bytes.NewReader(raw), object, true); err == nil {
		t.Fatal("normalized archive without sealed manifest qualified")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := scanArchive(ctx, bytes.NewReader(raw), object, false); err == nil {
		t.Fatal("cancelled evidence scan continued")
	}
}

func TestArchiveEvidenceRejectsLinksAndDuplicateMembers(t *testing.T) {
	for _, headers := range [][]*tar.Header{
		{{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/outside", Format: tar.FormatUSTAR}},
		{{Name: "same", Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}, {Name: "same", Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}},
	} {
		var raw bytes.Buffer
		writer := tar.NewWriter(&raw)
		for _, header := range headers {
			if writer.WriteHeader(header) != nil {
				t.Fatal("adversarial archive construction failed")
			}
		}
		if writer.Close() != nil {
			t.Fatal("adversarial archive sealing failed")
		}
		object, _ := storage.Blob(canonical.HashBytes(raw.Bytes()), int64(raw.Len()))
		if _, err := scanArchive(context.Background(), bytes.NewReader(raw.Bytes()), object, false); err == nil {
			t.Fatal("link or duplicate member qualified")
		}
	}
}
