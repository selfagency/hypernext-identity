// Command hypernext-identity is the Hypernext identity and data server.
//
// A single multi-tenant binary serving Solid Pod, remoteStorage, atproto PDS,
// IPFS pinning, WebFinger, OIDC/OAuth2 + IndieAuth, and an ActivityPub actor.
package main

import (
	"fmt"
	"os"
)

func main() {
	os.Exit(runMain(os.Args[1:]))
}

// runFn is a package-level hook so tests can exercise runMain's error path.
var runFn = run

// runMain runs the CLI and returns a process exit code.
func runMain(args []string) int {
	if err := runFn(args); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

func run(args []string) error {
	// Phase 1: skeleton only. CLI wiring (serve, migrate, admin, export)
	// lands in a later phase.
	_ = args
	return nil
}
