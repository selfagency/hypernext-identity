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
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	// Phase 1: skeleton only. CLI wiring (serve, migrate, admin, export)
	// lands in a later phase.
	_ = args
	return fmt.Errorf("not yet implemented")
}
