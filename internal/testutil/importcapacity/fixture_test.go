// SPDX-License-Identifier: Apache-2.0
package importcapacity

import (
	"context"
	"testing"

	"github.com/STAR-Ability/code-startrack-judge/internal/packages"
)

func TestUnknownAndCancelledFixtureNeverAcquire(t *testing.T) {
	for _, name := range []string{"", "arbitrary/path", "MEMBER_PAYLOAD/command"} {
		if _, err := Build(context.Background(), name); err == nil {
			t.Fatal("caller-controlled fixture selection accepted")
		}
	}
	ctx, stop := context.WithCancel(context.Background())
	stop()
	if _, err := Build(ctx, MemberPayload); err == nil {
		t.Fatal("cancelled acquisition continued")
	}
}

func TestLargeSampleSourceActuallyAdaptsWithoutChangingDeclaredLimits(t *testing.T) {
	for _, name := range []string{SampleSupported, SampleHeavy} {
		t.Run(name, func(t *testing.T) {
			f, err := Build(context.Background(), name)
			if err != nil {
				t.Fatal(err)
			}
			candidate, err := packages.Adapt(packages.PinnedSource(f.PackagePath), f.Files)
			if err != nil || candidate == nil || !candidate.ManifestReady || candidate.Manifest == nil {
				t.Fatal("authored sample source did not produce an accepted sealed candidate")
			}
			if len(candidate.NormalizedFiles)+1 != f.ExpectedNormalizedArchiveFiles || len(candidate.Samples) != 2 || candidate.Manifest.Limits.TimeLimitMS != 2000 || candidate.Manifest.Limits.MemoryLimitBytes != 256<<20 {
				t.Fatal("sample fixture count or source-authored frozen limits changed")
			}
			large := 0
			sampleBytes := int64(SampleBytes)
			if name == SampleSupported {
				sampleBytes = SupportedSampleBytes
			}
			for _, sample := range candidate.Manifest.Tests {
				if sample.Visibility == "SAMPLE" && sample.Input.SizeBytes == sampleBytes && sample.Answer.SizeBytes == sampleBytes {
					large++
				}
			}
			if large != 1 {
				t.Fatal("large sample was omitted from the frozen public-role manifest")
			}
		})
	}
}
