// SPDX-License-Identifier: Apache-2.0

// Package responsebudget protects public projections against the owned HTTP
// encoder's response ceiling. This is an implementation eligibility policy,
// not an additional limit in the published problem-detail contract.
package responsebudget

import (
	"unicode/utf8"

	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
)

const envelopeUUID contract.UUID = "ffffffff-ffff-ffff-ffff-ffffffffffff"

// ProblemDetailFits reserves the longest mutable public identity, status and
// timestamp representations. A later publication, withdrawal or catalog update
// therefore cannot make an accepted immutable detail exceed the same ceiling.
// Strings are counted using encoding/json's default escaping without allocating
// another content-sized buffer. Callers retain the complete original content.
func ProblemDetailFits(detail contract.PlatformProblemDetail) bool {
	detail.ProblemRef.ProblemID = "9223372036854775807"
	detail.ProblemRef.ProblemVersionID = envelopeUUID
	detail.CatalogVersion = "9223372036854775807"
	detail.Status = contract.ProblemWithdrawn
	detail.UpdatedAt = "9999-12-31T23:59:59.999999999Z"
	return problemDetailSize(detail, contract.MaxResultBytes) <= contract.MaxResultBytes
}

type counter struct{ size, limit int64 }

func (c *counter) add(n int64) {
	if c.size > c.limit || n > c.limit-c.size {
		c.size = c.limit + 1
		return
	}
	c.size += n
}

func (c *counter) text(s string) {
	c.add(2) // JSON string quotes.
	for i := 0; i < len(s) && c.size <= c.limit; {
		b := s[i]
		if b < utf8.RuneSelf {
			switch b {
			case '"', '\\', '\b', '\f', '\n', '\r', '\t':
				c.add(2)
			case '<', '>', '&':
				c.add(6)
			default:
				if b < 0x20 {
					c.add(6)
				} else {
					c.add(1)
				}
			}
			i++
			continue
		}
		r, width := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && width == 1 || r == '\u2028' || r == '\u2029' {
			c.add(6)
		} else {
			c.add(int64(width))
		}
		i += width
	}
}

func (c *counter) optional(s *string) {
	if s == nil {
		c.add(4)
	} else {
		c.text(*s)
	}
}

func (c *counter) integer(n contract.SafeInt) {
	if n < 0 {
		c.add(1)
		n = -n
	}
	c.add(1)
	for n >= 10 {
		c.add(1)
		n /= 10
	}
}

func (c *counter) strings(values []string) {
	c.add(2)
	for i, value := range values {
		if c.size > c.limit {
			return
		}
		if i != 0 {
			c.add(1)
		}
		c.text(value)
	}
}

// Count every field in the full ApiResponse[PlatformProblemDetail], including
// explicit nulls and empty arrays. Encoder parity tests cover this projection.
func problemDetailSize(d contract.PlatformProblemDetail, limit int64) int64 {
	c := counter{limit: limit}
	c.add(int64(len(`{"data":{"problemRef":{"source":`)))
	c.text(string(d.ProblemRef.Source))
	c.add(int64(len(`,"platform":`)))
	c.text(string(d.ProblemRef.Platform))
	c.add(int64(len(`,"problemId":`)))
	c.text(string(d.ProblemRef.ProblemID))
	c.add(int64(len(`,"problemVersionId":`)))
	c.text(string(d.ProblemRef.ProblemVersionID))
	c.add(int64(len(`},"title":`)))
	c.optional(d.Title)
	c.add(int64(len(`,"difficulty":`)))
	if d.Difficulty == nil {
		c.add(4)
	} else {
		c.integer(*d.Difficulty)
	}
	c.add(int64(len(`,"difficultyScale":`)))
	c.text(string(d.DifficultyScale))
	c.add(int64(len(`,"tags":`)))
	c.strings(d.Tags)
	c.add(int64(len(`,"url":`)))
	c.optional(d.URL)
	c.add(int64(len(`,"status":`)))
	c.text(string(d.Status))
	c.add(int64(len(`,"catalogVersion":`)))
	c.text(string(d.CatalogVersion))
	c.add(int64(len(`,"timeLimitMs":`)))
	c.integer(d.TimeLimitMs)
	c.add(int64(len(`,"memoryLimitBytes":`)))
	c.integer(d.MemoryLimitBytes)
	c.add(int64(len(`,"languageIds":`)))
	c.strings(d.LanguageIDs)
	c.add(int64(len(`,"updatedAt":`)))
	c.text(string(d.UpdatedAt))
	c.add(int64(len(`,"statement":{"format":`)))
	c.text(d.Statement.Format)
	c.add(int64(len(`,"content":`)))
	c.text(d.Statement.Content)
	c.add(int64(len(`,"input":`)))
	c.optional(d.Statement.Input)
	c.add(int64(len(`,"output":`)))
	c.optional(d.Statement.Output)
	c.add(int64(len(`},"samples":[`)))
	for i, sample := range d.Samples {
		if c.size > c.limit {
			return c.size
		}
		if i != 0 {
			c.add(1)
		}
		c.add(int64(len(`{"input":`)))
		c.text(sample.Input)
		c.add(int64(len(`,"output":`)))
		c.text(sample.Output)
		c.add(1)
	}
	c.add(int64(len(`],"license":{"spdxId":`)))
	c.optional(d.License.SPDXID)
	c.add(int64(len(`,"notice":`)))
	c.text(d.License.Notice)
	c.add(int64(len(`,"sourceUrl":`)))
	c.text(d.License.SourceURL)
	c.add(int64(len(`}},"requestId":`)))
	c.text(string(envelopeUUID))
	c.add(1)
	return c.size
}
