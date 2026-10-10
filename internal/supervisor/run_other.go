//go:build !linux

package supervisor

import "context"

func Run(context.Context) error { return fail("linux_platform") }
