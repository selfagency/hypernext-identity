// Package atproto implements the atproto PDS (Personal Data Server) core:
// DID/handle resolution, repo commit signing, XRPC, and blob storage. It is
// built on Bluesky's indigo packages.
package atproto

import (
	"context"
	"fmt"

	"github.com/bluesky-social/indigo/atproto/identity"
	"github.com/bluesky-social/indigo/atproto/syntax"
)

// Directory resolves DIDs and handles to identities.
type Directory struct {
	dir identity.Directory
}

// NewDirectory builds a directory with the default PLC + handle resolution.
func NewDirectory() *Directory {
	return &Directory{dir: identity.DefaultDirectory()}
}

// NewDirectoryWithBase builds a directory from a custom BaseDirectory.
func NewDirectoryWithBase(base *identity.BaseDirectory) *Directory {
	return &Directory{dir: base}
}

// ResolveDID resolves a DID (did:plc or did:web) to an identity.
func (d *Directory) ResolveDID(ctx context.Context, didStr string) (*identity.Identity, error) {
	did, err := syntax.ParseDID(didStr)
	if err != nil {
		return nil, fmt.Errorf("parse did: %w", err)
	}
	return d.dir.LookupDID(ctx, did)
}

// ResolveHandle resolves a handle to an identity (verifies handle↔DID).
func (d *Directory) ResolveHandle(ctx context.Context, handleStr string) (*identity.Identity, error) {
	handle, err := syntax.ParseHandle(handleStr)
	if err != nil {
		return nil, fmt.Errorf("parse handle: %w", err)
	}
	return d.dir.LookupHandle(ctx, handle)
}

// ResolveHandleToDID resolves a handle to just its DID (no verification).
func (d *Directory) ResolveHandleToDID(ctx context.Context, handleStr string) (string, error) {
	handle, err := syntax.ParseHandle(handleStr)
	if err != nil {
		return "", fmt.Errorf("parse handle: %w", err)
	}
	ident, err := d.dir.LookupHandle(ctx, handle)
	if err != nil {
		return "", err
	}
	return ident.DID.String(), nil
}

// PDSEndpoint returns the PDS endpoint for an identity, or "" if none.
func PDSEndpoint(ident *identity.Identity) string {
	return ident.PDSEndpoint()
}
