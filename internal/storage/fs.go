package storage

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// FS is a local-filesystem Backend. Keys map to paths under Root.
// Safe for concurrent use: each operation opens its own file handle.
type FS struct {
	Root string
}

// ErrNotFound is returned when a key does not exist.
var ErrNotFound = errors.New("storage: not found")

func (f *FS) path(key string) string {
	// Prevent path traversal: reject keys escaping Root.
	clean := filepath.Clean("/" + key)
	return filepath.Join(f.Root, clean)
}

// Put stores r under key, persisting contentType in a sidecar file.
func (f *FS) Put(ctx context.Context, key string, r io.Reader, contentType string) (Blob, error) {
	p := f.path(key)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return Blob{}, err
	}
	fh, err := os.Create(p)
	if err != nil {
		return Blob{}, err
	}
	n, err := io.Copy(fh, r)
	if cerr := fh.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return Blob{}, err
	}
	// Persist content type in a sidecar file so Get can return it.
	if err := os.WriteFile(p+".meta", []byte(contentType), 0o600); err != nil {
		return Blob{}, err
	}
	return Blob{Key: key, ContentType: contentType, Size: n}, nil
}

// Get returns the stored object for key.
func (f *FS) Get(ctx context.Context, key string) (io.ReadCloser, Blob, error) {
	p := f.path(key)
	fh, err := os.Open(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, Blob{}, ErrNotFound
		}
		return nil, Blob{}, err
	}
	st, err := fh.Stat()
	if err != nil {
		_ = fh.Close()
		return nil, Blob{}, err
	}
	ct, _ := os.ReadFile(p + ".meta")
	return fh, Blob{Key: key, ContentType: string(ct), Size: st.Size()}, nil
}

// Delete removes the stored object for key.
func (f *FS) Delete(ctx context.Context, key string) error {
	p := f.path(key)
	err := os.Remove(p)
	if os.IsNotExist(err) {
		return ErrNotFound
	}
	// Best-effort removal of the sidecar metadata file.
	_ = os.Remove(p + ".meta")
	return err
}

// List returns all stored objects under prefix.
func (f *FS) List(ctx context.Context, prefix string) ([]Blob, error) {
	dir := filepath.Join(f.Root, filepath.Clean("/"+prefix))
	var out []Blob
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil // empty prefix
			}
			return err
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(p, ".meta") {
			return nil // skip content-type sidecar
		}
		rel, err := filepath.Rel(f.Root, p)
		if err != nil {
			return err
		}
		out = append(out, Blob{Key: filepath.ToSlash(rel), Size: info.Size()})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

var _ Backend = (*FS)(nil)
