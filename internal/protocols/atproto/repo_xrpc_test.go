package atproto

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atcrypto"

	"github.com/selfagency/sovereign/internal/storage"
)

// newRepoFactory builds a RepoFactory that creates a durable repo for a DID
// (stable blockstore path per DID) with a fresh signing key.
func newRepoFactory(t *testing.T) func(ctx context.Context, did string) (*Repo, error) {
	t.Helper()
	dir := t.TempDir()
	return func(ctx context.Context, did string) (*Repo, error) {
		sk, err := atcrypto.GeneratePrivateKeyP256()
		if err != nil {
			return nil, err
		}
		return NewRepo(ctx, did, sk, filepath.Join(dir, did+".db"))
	}
}

// TestCreateRecordGetRecordRoundTrip proves createRecord writes a record and
// getRecord reads it back.
func TestCreateRecordGetRecordRoundTrip(t *testing.T) {
	s := newTestStore(t)
	fs := &storage.FS{Root: t.TempDir()}
	x := &XRPCServer{
		Store:       s,
		Backend:     func(string) storage.Backend { return fs },
		RepoFactory: newRepoFactory(t),
	}

	did := "did:plc:abc123"
	body := `{"repo":"` + did + `","collection":"app.bsky.feed.post","record":{"text":"hello"}}`
	req := httptest.NewRequest(http.MethodPost, "/xrpc/com.atproto.repo.createRecord", bytes.NewReader([]byte(body)))
	rec := httptest.NewRecorder()
	x.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("createRecord = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	var created struct {
		URI string `json:"uri"`
		CID string `json:"cid"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode createRecord: %v", err)
	}
	if created.URI == "" || created.CID == "" {
		t.Fatalf("createRecord missing uri/cid: %+v", created)
	}

	// getRecord reads it back.
	getReq := httptest.NewRequest(http.MethodGet, "/xrpc/com.atproto.repo.getRecord?repo="+did+"&collection=app.bsky.feed.post&rkey="+rkeyFromURI(created.URI), http.NoBody)
	getRec := httptest.NewRecorder()
	x.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("getRecord = %d, want 200 (body %q)", getRec.Code, getRec.Body.String())
	}
	if !bytes.Contains(getRec.Body.Bytes(), []byte("hello")) {
		t.Fatalf("getRecord body missing record text: %q", getRec.Body.String())
	}
}

// rkeyFromURI extracts the record key from an at:// URI (at://did/collection/rkey).
func rkeyFromURI(uri string) string {
	parts := bytes.Split([]byte(uri), []byte("/"))
	if len(parts) == 0 {
		return ""
	}
	return string(parts[len(parts)-1])
}
