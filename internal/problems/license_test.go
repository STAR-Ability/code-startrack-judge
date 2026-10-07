package problems

import (
	"archive/tar"
	"bytes"
	"strings"
	"testing"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
)

func licenseReceipt() LicenseApproval {
	text := "Synthetic package license.\n"
	return LicenseApproval{EvidenceID: "00000000-0000-0000-0000-000000000001", RejectedEvidenceID: "00000000-0000-0000-0000-000000000002", RepositoryURL: contract.PackageRepository, SourceRevision: strings.Repeat("a", 40), PackagePath: "problems/alpha", SourceSHA256: strings.Repeat("a", 64), Scope: "PACKAGE", Notice: "Synthetic fixture rights", SourceURL: contract.PackageRepository + "/tree/" + strings.Repeat("a", 40) + "/problems/alpha", LicenseFiles: []LicenseFile{{Path: "LICENSE", SHA256: canonical.HashBytes([]byte(text))}}, Coverage: "All package files examined", ThirdPartyReview: "Examined each file and attribution", ApprovalEvidence: "Synthetic human review fixture"}
}
func tarLicense(t *testing.T, name, text string, typ byte) []byte {
	t.Helper()
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	header := &tar.Header{Name: name, Mode: 0644, Size: int64(len(text)), Typeflag: typ}
	if typ != tar.TypeReg {
		header.Size = 0
	}
	if writer.WriteHeader(header) != nil {
		t.Fatal("tar fixture write failed")
	}
	if typ == tar.TypeReg {
		if _, err := writer.Write([]byte(text)); err != nil {
			t.Fatal("tar fixture write failed")
		}
	}
	if writer.Close() != nil {
		t.Fatal("tar fixture close failed")
	}
	return archive.Bytes()
}
func TestHumanReceiptRequiresScopeAndRealLicenseBytes(t *testing.T) {
	a := licenseReceipt()
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	if a.SPDXID != nil {
		t.Fatal("non-SPDX fixture unexpectedly tagged")
	}
	text := "Synthetic package license.\n"
	archive := tarLicense(t, "LICENSE", text, tar.TypeReg)
	texts, err := reviewLicenseTexts(archive, a)
	if err != nil || texts["LICENSE"] != text {
		t.Fatal("valid non-SPDX license bytes failed")
	}
	bad := a
	bad.ThirdPartyReview = ""
	if bad.Validate() == nil {
		t.Fatal("unreviewed third-party content accepted")
	}
	bad = a
	bad.LicenseFiles = nil
	if bad.Validate() == nil {
		t.Fatal("missing license files accepted")
	}
	bad = a
	bad.LicenseFiles = append([]LicenseFile{}, a.LicenseFiles...)
	bad.LicenseFiles[0].SHA256 = strings.Repeat("b", 64)
	if _, err := reviewLicenseTexts(archive, bad); err == nil {
		t.Fatal("forged license checksum accepted")
	}
	if _, err := reviewLicenseTexts(tarLicense(t, "LICENSE", "", tar.TypeSymlink), a); err == nil {
		t.Fatal("archive link accepted")
	}
	inherited := a
	inherited.Scope = "REPOSITORY_INHERITED"
	inherited.RepositoryLicenseTexts = map[string]string{"LICENSE": text}
	if _, err := reviewLicenseTexts(tarLicense(t, "statement.md", "Statement", tar.TypeReg), inherited); err != nil {
		t.Fatal("root inheritance evidence failed")
	}
	inherited.RepositoryLicenseTexts["LICENSE"] = "Different rights"
	if _, err := reviewLicenseTexts(tarLicense(t, "statement.md", "Statement", tar.TypeReg), inherited); err == nil {
		t.Fatal("mismatched root-license bytes accepted")
	}
}
