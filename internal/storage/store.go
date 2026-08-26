// Package storage provides a pluggable blob backend used by every protocol
// module (Solid, remoteStorage, atproto blobs, IPFS pinning payloads).
//
// Backends: local filesystem (fs) and any S3-compatible endpoint (s3).
// All backends must pass the shared contract test suite in contract_test.go.
package storage

import (
	"context"
	"io"
)

// Blob is metadata about a stored object.
type Blob struct {
	Key         string
	ContentType string
	Size        int64
}

// Backend is the storage contract every protocol module depends on.
type Backend interface {
	Put(ctx context.Context, key string, r io.Reader, contentType string) (Blob, error)
	Get(ctx context.Context, key string) (io.ReadCloser, Blob, error)
	Delete(ctx context.Context, key string) error
	List(ctx context.Context, prefix string) ([]Blob, error)
}
