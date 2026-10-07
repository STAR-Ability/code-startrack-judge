// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"testing"

	"github.com/STAR-Ability/code-startrack-judge/internal/packages"
)

func TestSyntheticMatureFixtureHasSealedRolesAndFrozenLimits(t *testing.T) {
	blobs := &matrixBlobs{files: map[string][]byte{}}
	m, e := matureMatrixManifest(blobs, inputValidatorProgram, sumProgram)
	if e != nil || packages.ValidateManifest(m) != nil || m.Limits.TimeLimitMS != 500 || m.Limits.WallLimitMS != 1000 || m.TestCount != 2 || len(m.InputValidators) != 1 {
		t.Fatal("qualification fixture does not preserve frozen profile")
	}
	roles := map[string]int{}
	for _, reference := range m.ReferenceSolutions {
		roles[reference.Role]++
	}
	if roles["ACCEPTED"] != 2 || roles["WRONG_ANSWER"] != 1 || roles["TIME_LIMIT"] != 1 || roles["RUNTIME_ERROR"] != 1 {
		t.Fatal("qualification fixture does not exercise every reference role")
	}
	for _, file := range m.Files {
		if _, e := blobs.ReadBlob(context.Background(), file.NormalizedSHA256, file.NormalizedSizeBytes, packages.MaxFileBytes); e != nil {
			t.Fatal("qualification file is not bound to its frozen bytes")
		}
	}
}

func TestLargestStatementFixtureUsesExactManifestBudgets(t *testing.T) {
	blobs := &matrixBlobs{files: map[string][]byte{}}
	m, e := matureMatrixManifest(blobs, inputValidatorProgram, sumProgram)
	if e != nil {
		t.Fatal(e)
	}
	m, e = largestStatementManifest(blobs, m)
	if e != nil || packages.ValidateManifest(m) != nil || len(m.Files) != packages.MaxFiles {
		t.Fatal("largest qualification manifest is invalid")
	}
	var total int64
	for _, file := range m.Files {
		total += file.NormalizedSizeBytes
	}
	if total != packages.MaxTotalBytes {
		t.Fatal("largest qualification manifest does not use exact byte budget")
	}
	if _, e := m.CanonicalJSON(); e != nil {
		t.Fatal("largest qualification manifest cannot be sealed")
	}
}
