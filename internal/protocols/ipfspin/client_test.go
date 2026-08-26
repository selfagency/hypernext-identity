package ipfspin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cid "github.com/ipfs/go-cid"
)

// testCID returns a valid CID for testing.
func testCID(t *testing.T) cid.Cid {
	t.Helper()
	c, err := cid.Decode("bafkreibm6jg3ux5qumhcn2b3flc3tyu6dmlb4xa7u5bf44yegnrjhc4yeq")
	if err != nil {
		t.Fatalf("decode cid: %v", err)
	}
	return c
}

// mockKuboServer simulates a Kubo RPC API.
func mockKuboServer(t *testing.T) *httptest.Server {
	t.Helper()
	pinned := map[string]bool{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v0/pin/add", func(w http.ResponseWriter, r *http.Request) {
		arg := r.URL.Query().Get("arg")
		if arg == "" {
			http.Error(w, "missing arg", http.StatusBadRequest)
			return
		}
		pinned[arg] = true
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"Pins":["` + arg + `"]}`))
	})
	mux.HandleFunc("/api/v0/pin/rm", func(w http.ResponseWriter, r *http.Request) {
		arg := r.URL.Query().Get("arg")
		delete(pinned, arg)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"Pins":["` + arg + `"]}`))
	})
	mux.HandleFunc("/api/v0/pin/ls", func(w http.ResponseWriter, r *http.Request) {
		arg := r.URL.Query().Get("arg")
		if !pinned[arg] {
			http.Error(w, "not pinned", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"Keys":{}}`))
	})
	return httptest.NewServer(mux)
}

// TestKuboPinUnpinStatus verifies the Kubo RPC client lifecycle.
func TestKuboPinUnpinStatus(t *testing.T) {
	srv := mockKuboServer(t)
	defer srv.Close()
	k := NewKuboRPC(srv.URL)
	ctx := context.Background()
	c := testCID(t)

	if err := k.Pin(ctx, c); err != nil {
		t.Fatalf("Pin: %v", err)
	}
	status, err := k.Status(ctx, c)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status != "pinned" {
		t.Fatalf("status = %q, want pinned", status)
	}
	if err := k.Unpin(ctx, c); err != nil {
		t.Fatalf("Unpin: %v", err)
	}
	if _, err := k.Status(ctx, c); err == nil {
		t.Fatal("expected error after unpin")
	}
}

// TestKuboError verifies Kubo RPC error handling.
func TestKuboError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	k := NewKuboRPC(srv.URL)
	ctx := context.Background()
	c := testCID(t)

	if err := k.Pin(ctx, c); err == nil {
		t.Fatal("expected error on 500")
	}
	if err := k.Unpin(ctx, c); err == nil {
		t.Fatal("expected error on 500")
	}
	if _, err := k.Status(ctx, c); err == nil {
		t.Fatal("expected error on 500")
	}
}

// mockPSAServer simulates a pinning-services-api-spec provider.
func mockPSAServer(t *testing.T) *httptest.Server {
	t.Helper()
	pinned := map[string]string{}
	mux := http.NewServeMux()
	mux.HandleFunc("/pins", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			CID string `json:"cid"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		pinned[req.CID] = "pinned"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"requestid":"r1","status":"queued"}`))
	})
	mux.HandleFunc("/pins/", func(w http.ResponseWriter, r *http.Request) {
		c := strings.TrimPrefix(r.URL.Path, "/pins/")
		switch r.Method {
		case http.MethodDelete:
			delete(pinned, c)
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			status, ok := pinned[c]
			if !ok {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"requestid":"r1","status":"` + status + `"}`))
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	return httptest.NewServer(mux)
}

// TestPSAPinUnpinStatus verifies the PSA-spec client lifecycle.
func TestPSAPinUnpinStatus(t *testing.T) {
	srv := mockPSAServer(t)
	defer srv.Close()
	p := NewPSAClient(srv.URL, "token-1")
	ctx := context.Background()
	c := testCID(t)

	if err := p.Pin(ctx, c); err != nil {
		t.Fatalf("Pin: %v", err)
	}
	status, err := p.Status(ctx, c)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status != "pinned" {
		t.Fatalf("status = %q, want pinned", status)
	}
	if err := p.Unpin(ctx, c); err != nil {
		t.Fatalf("Unpin: %v", err)
	}
	if _, err := p.Status(ctx, c); err == nil {
		t.Fatal("expected error after unpin")
	}
}

// TestPSAError verifies PSA-spec error handling.
func TestPSAError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	p := NewPSAClient(srv.URL, "token-1")
	ctx := context.Background()
	c := testCID(t)

	if err := p.Pin(ctx, c); err == nil {
		t.Fatal("expected error on 500")
	}
	if err := p.Unpin(ctx, c); err == nil {
		t.Fatal("expected error on 500")
	}
	if _, err := p.Status(ctx, c); err == nil {
		t.Fatal("expected error on 500")
	}
}

// TestErrNoBackend verifies the no-backend sentinel.
func TestErrNoBackend(t *testing.T) {
	if ErrNoBackend.Error() != "no IPFS backend configured" {
		t.Fatalf("ErrNoBackend = %q", ErrNoBackend.Error())
	}
}
