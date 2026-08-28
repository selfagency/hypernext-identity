package atproto

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atcrypto"

	"github.com/selfagency/sovereign/internal/storage"
)

// TestSyncGetRepoExportsCAR proves sync.getRepo returns a CAR of the repo.
func TestSyncGetRepoExportsCAR(t *testing.T) {
	s := newTestStore(t)
	fs := &storage.FS{Root: t.TempDir()}
	dir := t.TempDir()
	x := &XRPCServer{
		Store:   s,
		Backend: func(string) storage.Backend { return fs },
		RepoFactory: func(ctx context.Context, did string) (*Repo, error) {
			sk, _ := atcrypto.GeneratePrivateKeyP256()
			return NewRepo(ctx, did, sk, filepath.Join(dir, did+".db"))
		},
	}

	// Create a record so the repo has content.
	did := "did:plc:abc123"
	body := `{"repo":"` + did + `","collection":"app.bsky.feed.post","record":{"text":"hello"}}`
	req := httptest.NewRequest(http.MethodPost, "/xrpc/com.atproto.repo.createRecord", bytes.NewReader([]byte(body)))
	rec := httptest.NewRecorder()
	x.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("createRecord = %d, want 200", rec.Code)
	}

	// sync.getRepo returns a CAR.
	getReq := httptest.NewRequest(http.MethodGet, "/xrpc/com.atproto.sync.getRepo?did="+did, http.NoBody)
	getRec := httptest.NewRecorder()
	x.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("getRepo = %d, want 200 (body %q)", getRec.Code, getRec.Body.String())
	}
	// CAR v1 header is a DAG-CBOR map with a "roots" key. The header length
	// varies with the root CID, so check for the roots marker rather than
	// fixed magic bytes.
	car := getRec.Body.Bytes()
	if len(car) < 4 || !bytes.Contains(car, []byte("roots")) {
		t.Fatalf("getRepo body is not a CAR: %x", car[:minInt(20, len(car))])
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
