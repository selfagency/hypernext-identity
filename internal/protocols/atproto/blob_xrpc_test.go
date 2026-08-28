package atproto

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/selfagency/sovereign/internal/storage"
)

// TestUploadBlobGetBlobRoundTrip proves uploadBlob stores a blob and
// sync.getBlob reads it back.
func TestUploadBlobGetBlobRoundTrip(t *testing.T) {
	s := newTestStore(t)
	fs := &storage.FS{Root: t.TempDir()}
	x := &XRPCServer{
		Store:   s,
		Backend: func(string) storage.Backend { return fs },
	}

	// uploadBlob.
	body := []byte("hello blob")
	req := httptest.NewRequest(http.MethodPost, "/xrpc/com.atproto.repo.uploadBlob", bytes.NewReader(body))
	req.Header.Set("Content-Type", "image/png")
	rec := httptest.NewRecorder()
	x.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("uploadBlob = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	var up struct {
		Blob struct {
			Ref struct {
				Link string `json:"$link"`
			} `json:"ref"`
			Size int `json:"size"`
		} `json:"blob"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &up); err != nil {
		t.Fatalf("decode uploadBlob: %v", err)
	}
	if up.Blob.Ref.Link == "" {
		t.Fatalf("uploadBlob missing blob ref: %+v", up)
	}

	// sync.getBlob reads it back.
	getReq := httptest.NewRequest(http.MethodGet, "/xrpc/com.atproto.sync.getBlob?did=did:plc:abc&cid="+up.Blob.Ref.Link, http.NoBody)
	getRec := httptest.NewRecorder()
	x.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("getBlob = %d, want 200 (body %q)", getRec.Code, getRec.Body.String())
	}
	if !bytes.Equal(getRec.Body.Bytes(), body) {
		t.Fatalf("getBlob body = %q, want %q", getRec.Body.Bytes(), body)
	}
}
