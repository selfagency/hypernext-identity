package atproto

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"

	"github.com/selfagency/sovereign/internal/storage"
)

// BlobStore stores atproto blobs (images, files) in the shared storage
// backend, keyed by their SHA-256 content hash (the atproto blob CID).
type BlobStore struct {
	backend storage.Backend
}

// NewBlobStore builds a blob store over a storage backend.
func NewBlobStore(backend storage.Backend) *BlobStore {
	return &BlobStore{backend: backend}
}

// Put stores a blob and returns its content hash (the atproto blob CID).
func (b *BlobStore) Put(ctx context.Context, r io.Reader) (string, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	key := hex.EncodeToString(sum[:])
	if _, err := b.backend.Put(ctx, "blobs/"+key, bytes.NewReader(data), "application/octet-stream"); err != nil {
		return "", err
	}
	return key, nil
}

// Get retrieves a blob by its content hash.
func (b *BlobStore) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	rc, _, err := b.backend.Get(ctx, "blobs/"+key)
	if err != nil {
		return nil, err
	}
	return rc, nil
}

// Delete removes a blob by its content hash.
func (b *BlobStore) Delete(ctx context.Context, key string) error {
	return b.backend.Delete(ctx, "blobs/"+key)
}
