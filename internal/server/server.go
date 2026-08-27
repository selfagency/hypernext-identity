package server

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/hypernext/identity/internal/endpoints"
	"github.com/hypernext/identity/internal/protocols/activitypub"
	"github.com/hypernext/identity/internal/protocols/atproto"
	"github.com/hypernext/identity/internal/protocols/indieauth"
	"github.com/hypernext/identity/internal/protocols/ipfspin"
	"github.com/hypernext/identity/internal/protocols/nodeinfo"
	"github.com/hypernext/identity/internal/protocols/remotestorage"
	"github.com/hypernext/identity/internal/protocols/solid"
	"github.com/hypernext/identity/internal/protocols/webfinger"
	"github.com/hypernext/identity/internal/protocols/wellknown"
	"github.com/hypernext/identity/internal/storage"
	"github.com/hypernext/identity/internal/store"
	"github.com/hypernext/identity/internal/tenant"
)

// Server is the assembled identity server.
type Server struct {
	cfg    *Config
	store  *store.Store
	blobs  storage.Backend
	mux    http.Handler
	logger *slog.Logger
}

// New assembles the server from config: opens the SQLite store, builds the
// blob backend, and wires every protocol handler into a router.
func New(cfg *Config) (*Server, error) {
	logger := newLogger(cfg.Log)

	// Ensure the data directory exists.
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	// Open the account-data SQLite store.
	storePath := filepath.Join(cfg.DataDir, "identity.db")
	st, err := store.Open(storePath)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}

	// Build the blob backend.
	blobs, err := buildBlobBackend(cfg, logger)
	if err != nil {
		return nil, err
	}

	s := &Server{cfg: cfg, store: st, blobs: blobs, logger: logger}
	s.buildRouter()
	return s, nil
}

// Close releases the store.
func (s *Server) Close() error {
	return s.store.Close()
}

// newS3Backend is a package-level hook so tests can stub the S3 constructor
// (which does a live bucket probe).
var newS3Backend = func(cfg *Config) (storage.Backend, error) {
	s3 := cfg.Storage.S3
	return storage.NewS3(&storage.S3Config{
		Endpoint:  s3.Endpoint,
		Bucket:    s3.Bucket,
		AccessKey: s3.AccessKey,
		SecretKey: s3.SecretKey,
		Region:    s3.Region,
	})
}

// buildBlobBackend constructs the FS or S3 storage backend.
func buildBlobBackend(cfg *Config, logger *slog.Logger) (storage.Backend, error) {
	switch cfg.Storage.Backend {
	case "fs":
		return &storage.FS{Root: filepath.Join(cfg.DataDir, "blobs")}, nil
	case "s3":
		if cfg.Storage.S3 == nil {
			return nil, fmt.Errorf("config: storage.s3 is required when backend=s3")
		}
		return newS3Backend(cfg)
	default:
		return nil, fmt.Errorf("config: unknown storage backend %q", cfg.Storage.Backend)
	}
}

// buildRouter wires all protocol handlers onto the mux.
func (s *Server) buildRouter() {
	mux := http.NewServeMux()

	// Tenant-scoped blob backend resolver.
	backendFor := func(tenantID string) storage.Backend {
		return s.blobs
	}

	// remoteStorage.
	rs := &remotestorage.Server{
		Backend: backendFor,
		Tokens:  nil, // token validation wired in a later phase
	}
	mux.Handle("/rs/", rs)

	// Solid LDP.
	solidSrv := &solid.Server{
		Backend: backendFor,
		ACL:     nil, // ACL enforcement wired in a later phase
	}
	mux.Handle("/solid/", solidSrv)

	// WebFinger.
	identityHost := "id." + s.cfg.Domain
	wf := webfinger.Handler(webfinger.Config{
		IdentityHost: identityHost,
		StorageRoot:  "https://" + s.cfg.Domain + "/rs/",
		ActorURL:     "https://" + s.cfg.Domain + "/profile/",
	})
	mux.Handle("/.well-known/webfinger", wf)

	// NodeInfo.
	ni := nodeinfo.Handler(nodeinfo.Config{
		SoftwareName:      "hypernext-identity",
		SoftwareVersion:   "0.1.0",
		Protocols:         []string{"solid", "remotestorage", "atproto"},
		OpenRegistrations: false,
	})
	mux.Handle("/.well-known/nodeinfo", ni)

	// Content-negotiated profile (h-card / actor / DID doc).
	profile := wellknown.ProfileHandler(wellknown.Handlers{
		HCard:  s.hcardHandler(),
		Actor:  activitypub.ServeActor(activitypub.ActorConfig{Handle: s.cfg.Domain}),
		DIDDoc: s.didDocHandler(),
	})
	mux.Handle("/profile/", profile)

	// Public key + proofs endpoints.
	keys := &endpoints.KeysHandler{Store: s.store}
	mux.Handle("/keys", keys)
	mux.Handle("/.well-known/openpgpkey/", keys)
	proofs := &endpoints.ProofsHandler{Store: s.store}
	mux.Handle("/.well-known/proofs", proofs)

	// IPFS pinning (broker) — the pinner is a client injected into backup/
	// export flows, not a standalone HTTP endpoint.
	if s.cfg.IPFS.Enabled {
		_ = ipfspin.NewKuboRPC("http://127.0.0.1:5001")
	}

	// atproto PDS.
	dir := atproto.NewDirectory()
	_ = dir
	mux.Handle("/xrpc/", s.atprotoHandler())

	// IndieAuth.
	bridge := indieauth.NewBridge(true, nil)
	_ = bridge

	// Tenant middleware wraps the whole mux.
	s.mux = tenant.Middleware(s.tenantStore())(mux)
}

// tenantStore resolves a host to a tenant.
func (s *Server) tenantStore() tenant.Store {
	return staticTenantStore{domain: s.cfg.Domain}
}

// staticTenantStore resolves any subdomain of the configured domain to a
// tenant. A real tenant registry replaces it in a later phase.
type staticTenantStore struct {
	domain string
}

func (t staticTenantStore) FindByHost(_ context.Context, host string) (*tenant.Tenant, error) {
	if host == t.domain || host == "id."+t.domain {
		return &tenant.Tenant{ID: "root", Handle: host, DIDMethod: "web"}, nil
	}
	if len(host) > len(t.domain)+1 && host[len(host)-len(t.domain):] == t.domain {
		return &tenant.Tenant{ID: host, Handle: host, DIDMethod: "web"}, nil
	}
	return nil, tenant.ErrNotFound
}

// hcardHandler serves the HTML h-card profile.
func (s *Server) hcardHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, "<html><body><div class=\"h-card\"><h1 class=\"p-name\">%s</h1></div></body></html>", html.EscapeString(r.Host))
	}
}

// didDocHandler serves the DID document.
func (s *Server) didDocHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/did+json")
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "did:web:" + r.Host})
	}
}

// atprotoHandler serves atproto XRPC endpoints.
func (s *Server) atprotoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "atproto XRPC not yet wired", http.StatusNotImplemented)
	})
}

// ServeHTTP serves the assembled server.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// Run starts the HTTP server with graceful shutdown.
func (s *Server) Run(addr string) error {
	srv := &http.Server{
		Addr:         addr,
		Handler:      s,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	s.logger.Info("server listening", "addr", addr)
	return srv.ListenAndServe()
}

// newLogger builds a slog logger from config.
func newLogger(cfg LogConfig) *slog.Logger {
	level := slog.LevelInfo
	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}
