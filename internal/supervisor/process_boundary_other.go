//go:build !linux

package supervisor

import "context"

func VerifyServiceProcessBoundary(context.Context, int, int) error {
	return fail("process_boundary_platform")
}

func ProcessBoundaryPeer() error { return fail("process_boundary_platform") }
