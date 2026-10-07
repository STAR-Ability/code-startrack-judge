// SPDX-License-Identifier: Apache-2.0
// Package importcapacity contains fixed, authored offline qualification inputs.
// It supplies no production acquisition implementation or upstream provenance.
package importcapacity

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/STAR-Ability/code-startrack-judge/internal/packages"
	"strconv"
	"strings"
)

const (
	MemberPayload        = "MEMBER_PAYLOAD"
	SampleHeavy          = "SAMPLE_HEAVY"
	SampleSupported      = "SAMPLE_SUPPORTED"
	SampleBytes          = 32 << 20
	SupportedSampleBytes = 15 << 20
	LicenseText          = "Authored synthetic qualification fixture; no downloaded package or upstream provenance.\nLicensed under the Apache License, Version 2.0.\nhttps://www.apache.org/licenses/LICENSE-2.0\n"
)

var ErrFixture = errors.New("fixed synthetic import capacity fixture unavailable")

type Fixture struct {
	Name                           string
	PackagePath                    string
	Files                          []packages.File
	SourceRegularBytes             int64
	ExpectedNormalizedArchiveFiles int
	ExpectedNormalizedRegularBytes int64
}

func (Fixture) String() string     { return "authored private capacity fixture [bytes redacted]" }
func (f Fixture) GoString() string { return f.String() }

func Names() []string { return []string{MemberPayload, SampleSupported, SampleHeavy} }

func Path(name string) (string, error) {
	switch name {
	case MemberPayload:
		return "problems/synthetic-api-member-payload", nil
	case SampleHeavy:
		return "problems/synthetic-api-sample-heavy", nil
	case SampleSupported:
		return "problems/synthetic-api-sample-supported", nil
	default:
		return "", ErrFixture
	}
}

func baseFiles() []packages.File {
	return []packages.File{
		{Path: "LICENSE", Data: []byte(LicenseText)},
		{Path: "problem.yaml", Data: []byte("name: Authored API capacity qualification\nlimits:\n  memory: 256\n  output: 8\n")},
		{Path: ".timelimit", Data: []byte("2.000\n")},
		{Path: "problem_statement/problem.en.md", Data: []byte("Compute the sum of two positive integers, each at most 99. Whitespace may follow the two input integers or the output integer.\n")},
		{Path: "data/sample/1.in", Data: []byte("2 3\n")},
		{Path: "data/sample/1.ans", Data: []byte("5\n")},
		{Path: "data/secret/2.in", Data: []byte("8 5\n")},
		{Path: "data/secret/2.ans", Data: []byte("13\n")},
		{Path: "input_validators/main.cpp", Data: []byte(validatorProgram)},
		{Path: "submissions/accepted/main.cpp", Data: []byte(sumProgram)},
		{Path: "submissions/accepted/python.py", Data: []byte("import sys\na,b=map(int,sys.stdin.buffer.read().split())\nprint(a+b)\n")},
		{Path: "submissions/wrong_answer/main.cpp", Data: []byte("#include <cstdio>\nint main(){std::puts(\"6\");}\n")},
		{Path: "submissions/time_limit_exceeded/main.cpp", Data: []byte("int main(){volatile unsigned long long x=0;for(;;){x=x+1;}}\n")},
		{Path: "submissions/run_time_error/main.cpp", Data: []byte("#include <csignal>\nint main(){std::raise(SIGSEGV);}\n")},
	}
}

func sumBytes(files []packages.File) int64 {
	var result int64
	for _, file := range files {
		result += int64(len(file.Data))
	}
	return result
}

func paddingPath(index int) string {
	return fmt.Sprintf("problem_statement/qualification/asset-%06d.bin", index)
}

// memberPayloadSize measures the real adapter's metadata with empty assets.
// Only fixed-width SHA strings and decimal asset sizes change when filling
// those assets. The final real pipeline independently verifies actual archives,
// manifests and bytes; this sizing calculation supplies no qualification proof.
func memberPayloadSize(ctx context.Context, files []packages.File, packagePath string) (int64, error) {
	baseline, err := packages.Adapt(packages.PinnedSource(packagePath), files)
	if err != nil || baseline == nil || !baseline.ManifestReady || baseline.Manifest == nil {
		return 0, ErrFixture
	}
	normalizedBase := sumBytes(baseline.NormalizedFiles)
	manifestBase := int64(len(baseline.ManifestJSON))
	payload := packages.MaxTotalBytes - normalizedBase - manifestBase
	for iteration := 0; iteration < 8; iteration++ {
		if ctx.Err() != nil || payload < 0 {
			return 0, ErrFixture
		}
		remaining := payload
		var sizeDelta int64
		for remaining > 0 {
			part := min(remaining, packages.MaxFileBytes)
			// The empty baseline has decimal 0 in both sourceSizeBytes and
			// normalizedSizeBytes. SHA identities remain exactly 64 bytes.
			// Count only changed decimal widths; do not repeatedly serialize
			// the full 65k inventory merely to measure this bounded delta.
			sizeDelta += 2 * int64(len(strconv.FormatInt(part, 10))-1)
			remaining -= part
		}
		corrected := packages.MaxTotalBytes - normalizedBase - manifestBase - sizeDelta
		if corrected == payload {
			return payload, nil
		}
		payload = corrected
	}
	return 0, ErrFixture
}

// Build accepts only the three fixed authored cases. The member fixture uses
// distinct touched asset buffers, so acquisition and storage do not rely on
// aliasing or checksum deduplication to fit their actual qualification budgets.
func Build(ctx context.Context, name string) (Fixture, error) {
	packagePath, err := Path(name)
	if err != nil || ctx == nil || ctx.Err() != nil {
		return Fixture{}, ErrFixture
	}
	files := baseFiles()
	if name == SampleHeavy || name == SampleSupported {
		sampleBytes := SampleBytes
		if name == SampleSupported {
			sampleBytes = SupportedSampleBytes
		}
		for _, sample := range []struct{ path, prefix string }{
			{"data/sample/10.in", "2 3\n"}, {"data/sample/10.ans", "5\n"},
		} {
			data := bytes.Repeat([]byte{' '}, sampleBytes)
			copy(data, sample.prefix)
			data[len(data)-1] = '\n'
			files = append(files, packages.File{Path: sample.path, Data: data})
		}
		return Fixture{Name: name, PackagePath: packagePath, Files: files, SourceRegularBytes: sumBytes(files), ExpectedNormalizedArchiveFiles: len(files) + 2}, nil
	}
	for index := 0; len(files) < packages.MaxFiles-2; index++ {
		files = append(files, packages.File{Path: paddingPath(index), Data: []byte{}})
	}
	extra, err := memberPayloadSize(ctx, files, packagePath)
	if err != nil {
		return Fixture{}, err
	}
	remaining, asset := extra, 0
	for index := range files {
		if !strings.HasPrefix(files[index].Path, "problem_statement/qualification/") || remaining == 0 {
			continue
		}
		if ctx.Err() != nil {
			return Fixture{}, ErrFixture
		}
		size := min(remaining, packages.MaxFileBytes)
		data := make([]byte, int(size))
		// Commit each page and give every large asset a distinct identity.
		for page := 0; page < len(data); page += 4096 {
			data[page] = byte(asset + 1)
		}
		files[index].Data = data
		remaining -= size
		asset++
	}
	if remaining != 0 || sumBytes(files) > packages.MaxTotalBytes {
		return Fixture{}, ErrFixture
	}
	return Fixture{Name: name, PackagePath: packagePath, Files: files, SourceRegularBytes: sumBytes(files), ExpectedNormalizedArchiveFiles: packages.MaxFiles, ExpectedNormalizedRegularBytes: packages.MaxTotalBytes}, nil
}

const validatorProgram = "#include <iostream>\n#include <cctype>\nint main(){std::ios::sync_with_stdio(false);std::cin.tie(nullptr);long long a,b;if(!(std::cin>>a>>b)||a<1||a>99||b<1||b>99)return 43;for(int c;(c=std::cin.get())!=EOF;)if(!std::isspace(static_cast<unsigned char>(c)))return 43;return 42;}\n"
const sumProgram = "#include <cstdio>\nint main(){int a,b;if(std::scanf(\"%d %d\",&a,&b)!=2)return 1;std::printf(\"%d\\n\",a+b);}\n"

// DeclaredLimits documents source-authored fixture limits, without modifying
// the adapter's frozen execution profiles or any admitted manifest.
func DeclaredLimits() string { return "2s/256MiB" }
