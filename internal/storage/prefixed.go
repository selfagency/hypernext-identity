package storage

import (
	"context"
	"io"
	"path"
)

// Prefixed wraps a Backend and prefixes every key with a namespace. This is
// how multi-tenant isolation is enforced on a shared backend: each tenant's
// keys live under "<prefix>/", so tenants cannot read or write each other's
// data (IDOR boundary). It works for both FS (subdirectory) and S3 (key
// prefix) backends.
type Prefixed struct {
	Backend Backend
	Prefix  string
}

func (p *Prefixed) key(key string) string {
	return path.Join(p.Prefix, key)
}

// Put stores r under the prefixed key.
func (p *Prefixed) Put(ctx context.Context, key string, r io.Reader, contentType string) (Blob, error) {
	return p.Backend.Put(ctx, p.key(key), r, contentType)
}

// Get returns the stored object for the prefixed key.
func (p *Prefixed) Get(ctx context.Context, key string) (io.ReadCloser, Blob, error) {
	return p.Backend.Get(ctx, p.key(key))
}

// Delete removes the stored object for the prefixed key.
func (p *Prefixed) Delete(ctx context.Context, key string) error {
	return p.Backend.Delete(ctx, p.key(key))
}

// List returns all stored objects under the prefixed key.
func (p *Prefixed) List(ctx context.Context, prefix string) ([]Blob, error) {
	return p.Backend.List(ctx, p.key(prefix))
}

var _ Backend = (*Prefixed)(nil)
