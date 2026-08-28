package atproto

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atcrypto"

	"github.com/selfagency/sovereign/internal/storage"
)

// testRepoFactory returns a RepoFactory wired to a temp blockstore.
func testRepoFactory(t *testing.T) func(ctx context.Context, did string) (*Repo, error) {
	t.Helper()
	sk, err := atcrypto.GeneratePrivateKeyP256()
	if err != nil {
		t.Fatal(err)
	}
	return func(ctx context.Context, did string) (*Repo, error) {
		return NewRepo(ctx, did, sk, filepath.Join(t.TempDir(), "repo.db"))
	}
}

// TestCreateRecordNoFactory proves createRecord errors when RepoFactory is nil.
func TestCreateRecordNoFactory(t *testing.T) {
	x := &XRPCServer{}
	body := `{"repo":"did:plc:abc","collection":"app.bsky.feed.post","record":{"text":"hi"}}`
	req := httptest.NewRequest(http.MethodPost, "/xrpc/com.atproto.repo.createRecord", strings.NewReader(body))
	rec := httptest.NewRecorder()
	x.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// TestCreateRecordBadBody proves a malformed JSON body errors.
func TestCreateRecordBadBody(t *testing.T) {
	x := &XRPCServer{RepoFactory: testRepoFactory(t)}
	req := httptest.NewRequest(http.MethodPost, "/xrpc/com.atproto.repo.createRecord", strings.NewReader("not json"))
	rec := httptest.NewRecorder()
	x.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestCreateRecordMissingFields proves missing repo/collection/record errors.
func TestCreateRecordMissingFields(t *testing.T) {
	x := &XRPCServer{RepoFactory: testRepoFactory(t)}
	req := httptest.NewRequest(http.MethodPost, "/xrpc/com.atproto.repo.createRecord", strings.NewReader(`{"repo":"did:plc:abc"}`))
	rec := httptest.NewRecorder()
	x.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestCreateRecordHappyPath proves a valid createRecord writes and commits.
func TestCreateRecordHappyPath(t *testing.T) {
	x := &XRPCServer{RepoFactory: testRepoFactory(t)}
	body := `{"repo":"did:plc:abc","collection":"app.bsky.feed.post","record":{"text":"hi"}}`
	req := httptest.NewRequest(http.MethodPost, "/xrpc/com.atproto.repo.createRecord", strings.NewReader(body))
	rec := httptest.NewRecorder()
	x.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	var out struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.HasPrefix(out.URI, "at://did:plc:abc/app.bsky.feed.post/") {
		t.Fatalf("uri = %q", out.URI)
	}
}

// TestGetRecordNoFactory proves getRecord errors when RepoFactory is nil.
func TestGetRecordNoFactory(t *testing.T) {
	x := &XRPCServer{}
	req := httptest.NewRequest(http.MethodGet, "/xrpc/com.atproto.repo.getRecord?repo=did:plc:abc&collection=app.bsky.feed.post&rkey=1", http.NoBody)
	rec := httptest.NewRecorder()
	x.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// TestGetRecordMissingParams proves missing repo/collection/rkey errors.
func TestGetRecordMissingParams(t *testing.T) {
	x := &XRPCServer{RepoFactory: testRepoFactory(t)}
	req := httptest.NewRequest(http.MethodGet, "/xrpc/com.atproto.repo.getRecord?repo=did:plc:abc", http.NoBody)
	rec := httptest.NewRecorder()
	x.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestGetRecordNotFound proves a missing record returns 404.
func TestGetRecordNotFound(t *testing.T) {
	x := &XRPCServer{RepoFactory: testRepoFactory(t)}
	req := httptest.NewRequest(http.MethodGet, "/xrpc/com.atproto.repo.getRecord?repo=did:plc:abc&collection=app.bsky.feed.post&rkey=missing", http.NoBody)
	rec := httptest.NewRecorder()
	x.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestUploadBlobNoBackend proves uploadBlob errors when Backend is nil.
func TestUploadBlobNoBackend(t *testing.T) {
	x := &XRPCServer{}
	req := httptest.NewRequest(http.MethodPost, "/xrpc/com.atproto.repo.uploadBlob", bytes.NewReader([]byte("x")))
	rec := httptest.NewRecorder()
	x.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// TestGetBlobNoBackend proves getBlob errors when Backend is nil.
func TestGetBlobNoBackend(t *testing.T) {
	x := &XRPCServer{}
	req := httptest.NewRequest(http.MethodGet, "/xrpc/com.atproto.sync.getBlob?cid=abc", http.NoBody)
	rec := httptest.NewRecorder()
	x.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// TestGetBlobMissingCID proves getBlob without a cid errors.
func TestGetBlobMissingCID(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	x := &XRPCServer{Backend: func(string) storage.Backend { return fs }}
	req := httptest.NewRequest(http.MethodGet, "/xrpc/com.atproto.sync.getBlob", http.NoBody)
	rec := httptest.NewRecorder()
	x.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestGetBlobNotFound proves a missing blob returns 404.
func TestGetBlobNotFound(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	x := &XRPCServer{Backend: func(string) storage.Backend { return fs }}
	req := httptest.NewRequest(http.MethodGet, "/xrpc/com.atproto.sync.getBlob?cid=deadbeef", http.NoBody)
	rec := httptest.NewRecorder()
	x.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestGetRepoNoFactory proves getRepo errors when RepoFactory is nil.
func TestGetRepoNoFactory(t *testing.T) {
	x := &XRPCServer{}
	req := httptest.NewRequest(http.MethodGet, "/xrpc/com.atproto.sync.getRepo?did=did:plc:abc", http.NoBody)
	rec := httptest.NewRecorder()
	x.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// TestGetRepoMissingDID proves getRepo without a did errors.
func TestGetRepoMissingDID(t *testing.T) {
	x := &XRPCServer{RepoFactory: testRepoFactory(t)}
	req := httptest.NewRequest(http.MethodGet, "/xrpc/com.atproto.sync.getRepo", http.NoBody)
	rec := httptest.NewRecorder()
	x.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestGetRepoEmptyRepo proves getRepo on an uncommitted repo returns 404.
func TestGetRepoEmptyRepo(t *testing.T) {
	x := &XRPCServer{RepoFactory: testRepoFactory(t)}
	req := httptest.NewRequest(http.MethodGet, "/xrpc/com.atproto.sync.getRepo?did=did:plc:abc", http.NoBody)
	rec := httptest.NewRecorder()
	x.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body %q)", rec.Code, rec.Body.String())
	}
}
