package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

func TestInvalidMigrationFlagsKeepPrivateArgumentsOutOfDiagnostics(t *testing.T) {
	canary := "PRIVATE_MIGRATION_ARGUMENT_CANARY"
	for _, args := range [][]string{{"judge-migrate", "up", "-ceiling", canary}, {"judge-migrate", "status", "-" + canary}} {
		func() {
			originalArgs, originalStderr := os.Args, os.Stderr
			read, write, err := os.Pipe()
			if err != nil {
				t.Fatal("diagnostic capture unavailable")
			}
			defer read.Close()
			defer func() { os.Args, os.Stderr = originalArgs, originalStderr }()
			os.Args, os.Stderr = args, write
			err = run()
			write.Close()
			os.Args, os.Stderr = originalArgs, originalStderr
			output, readErr := io.ReadAll(read)
			if err == nil || readErr != nil || strings.Contains(err.Error(), canary) || len(output) != 0 {
				t.Fatal("invalid flag exposed private arguments or was accepted")
			}
		}()
	}
}
