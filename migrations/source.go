// Package migrations supplies only reviewed files embedded in the release.
package migrations

import "embed"

// Files embeds this directory without accepting runtime SQL paths or URLs.
// Load ignores non-SQL policy and Go source files.
//
//go:embed *.up.sql
var Files embed.FS
