package runtime

import (
	"bytes"
	"time"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
	"github.com/STAR-Ability/code-startrack-judge/internal/packages"
)

func checkerFromManifest(c packages.CheckerConfig) CheckerConfig {
	clone := func(v *string) *string {
		if v == nil {
			return nil
		}
		s := *v
		return &s
	}
	return CheckerConfig{Implementation: CheckerImplementation, SourceSHA256: c.Implementation.SourceSHA256, CaseSensitive: c.CaseSensitive, SpaceChangeSensitive: c.SpaceChangeSensitive, FloatAbsoluteTolerance: clone(c.FloatAbsoluteTolerance), FloatRelativeTolerance: clone(c.FloatRelativeTolerance)}
}
func limitsFromManifest(l packages.ExecutionLimits) Limits {
	return Limits{CPUTimeNS: uint64(l.TimeLimitMS) * uint64(time.Millisecond), WallTimeNS: uint64(l.WallLimitMS) * uint64(time.Millisecond), MemoryBytes: uint64(l.MemoryLimitBytes), OutputBytes: uint64(l.OutputLimitBytes), Processes: uint64(l.ProcessLimit)}
}
func refFromManifest(r packages.FileRef) BlobRef {
	return BlobRef{SHA256: r.SHA256, SizeBytes: r.SizeBytes}
}

// TaskFromManifest validates the complete sealed manifest before projecting
// execution inputs. Persistence supplies case IDs from this exact artifact;
// normalized source paths are intentionally absent from the execution protocol.
func TaskFromManifest(taskID, token contract.UUID, identity FrozenIdentity, source []byte, m packages.Manifest, caseIDs []contract.UUID) (TaskInput, error) {
	if packages.ValidateManifest(m) != nil || len(caseIDs) != len(m.Tests) {
		return TaskInput{}, failure("FROZEN_MANIFEST_INVALID", false)
	}
	t := TaskInput{TaskID: taskID, FencingToken: token, LanguageID: LanguageID, Identity: identity, Source: bytes.Clone(source), SourceSHA256: canonical.HashBytes(source), Limits: limitsFromManifest(m.Limits), Cases: make([]Case, len(m.Tests))}
	for i, c := range m.Tests {
		t.Cases[i] = Case{TestCaseID: caseIDs[i], Ordinal: c.Ordinal, Input: refFromManifest(c.Input), Answer: refFromManifest(c.Answer), Checker: checkerFromManifest(c.Checker)}
	}
	return t, nil
}

func ValidationFromManifest(jobID, itemID, token contract.UUID, identity FrozenIdentity, m packages.Manifest) (ValidationInput, error) {
	if packages.ValidateManifest(m) != nil {
		return ValidationInput{}, failure("FROZEN_MANIFEST_INVALID", false)
	}
	v := ValidationInput{JobID: jobID, ItemID: itemID, FencingToken: token, Identity: identity, Limits: limitsFromManifest(m.Limits), Cases: make([]Case, len(m.Tests)), InputValidators: []Program{}, AcceptedReferences: []Program{}}
	for i, c := range m.Tests {
		v.Cases[i] = Case{Ordinal: c.Ordinal, Input: refFromManifest(c.Input), Answer: refFromManifest(c.Answer), Checker: checkerFromManifest(c.Checker)}
	}
	for _, p := range m.InputValidators {
		v.InputValidators = append(v.InputValidators, Program{File: refFromManifest(p.File), LanguageID: p.LanguageID})
	}
	for _, p := range m.ReferenceSolutions {
		if p.Role == "ACCEPTED" {
			v.AcceptedReferences = append(v.AcceptedReferences, Program{File: refFromManifest(p.File), LanguageID: p.LanguageID})
		}
	}
	return v, nil
}
