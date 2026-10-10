package main

import (
	"errors"
	"net/url"

	"github.com/STAR-Ability/code-startrack-judge/internal/config"
)

func migrateConfig(dsn string) error {
	if config.ValidateDatabaseURL(dsn) != nil {
		return errors.New("invalid private license reviewer connection configuration")
	}
	parsed, err := url.Parse(dsn)
	if err != nil || parsed.User == nil || parsed.User.Username() != "judge_license_reviewer" {
		return errAuthority
	}
	return nil
}
