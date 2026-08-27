package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/selfagency/sovereign/internal/auth"
	"github.com/selfagency/sovereign/internal/authstore"
	"github.com/selfagency/sovereign/internal/endpoints"
	"github.com/selfagency/sovereign/internal/protocols/activitypub"
	"github.com/selfagency/sovereign/internal/protocols/atproto"
	"github.com/selfagency/sovereign/internal/protocols/indieauth"
	"github.com/selfagency/sovereign/internal/protocols/ipfspin"
	"github.com/selfagency/sovereign/internal/protocols/nodeinfo"
	"github.com/selfagency/sovereign/internal/protocols/remotestorage"
	"github.com/selfagency/sovereign/internal/protocols/solid"
	"github.com/selfagency/sovereign/internal/protocols/webfinger"
	"github.com/selfagency/sovereign/internal/protocols/wellknown"
	"github.com/selfagency/sovereign/internal/storage"
	"github.com/selfagency/sovereign/internal/store"
	"github.com/selfagency/sovereign/internal/tenant"
	"github.com/selfagency/sovereign/internal/wiring"
)

// Server is the assembled identity server.
type Server struct {
	cfg       *Config
	store     *store.Store
	authStore *authstore.Store
	blobs     storage.Backend
	mux       http.Handler
	logger    *slog.Logger
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

	// Build the auth store (persists the OIDC signing key + refresh tokens).
	mem, err := auth.NewMemoryStore()
	if err != nil {
		return nil, fmt.Errorf("new auth store: %w", err)
	}
	authStore, err := authstore.New(context.Background(), mem, st)
	if err != nil {
		return nil, fmt.Errorf("open auth store: %w", err)
	}

	// Build the blob backend.
	blobs, err := buildBlobBackend(cfg, logger)
	if err != nil {
		return nil, err
	}

	s := &Server{cfg: cfg, store: st, authStore: authStore, blobs: blobs, logger: logger}
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

	// Tenant-scoped blob backend resolver. Each tenant's keys are prefixed
	// with the tenant ID on the shared backend, so tenants cannot read or
	// write each other's data (IDOR boundary). Works for both FS and S3.
	backendFor := func(tenantID string) storage.Backend {
		return &storage.Prefixed{Backend: s.blobs, Prefix: tenantID}
	}

	// remoteStorage.
	rs := &remotestorage.Server{
		Backend: backendFor,
		Tokens:  &wiring.TokenValidator{Key: s.authStore.SigningKey()},
	}
	mux.Handle("/rs/", rs)

	// Solid LDP.
	solidSrv := &solid.Server{
		Backend: backendFor,
		ACL:     &wiring.ACLChecker{Store: s.store},
		Tokens:  &wiring.SubjectValidator{Key: s.authStore.SigningKey()},
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
		SoftwareName:      "sovereign",
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
	xrpc := &atproto.XRPCServer{Store: s.store}
	mux.Handle("/xrpc/", xrpc)

	// IndieAuth.
	bridge := indieauth.NewBridge(true, nil)
	_ = bridge

	// Tenant middleware wraps the whole mux.
	s.mux = tenant.Middleware(s.tenantStore())(mux)
}

// tenantStore resolves a host to a tenant from the SQLite store.
func (s *Server) tenantStore() tenant.Store {
	return sqliteTenantStore{store: s.store}
}

// sqliteTenantStore resolves hosts to tenants via the SQLite store.
type sqliteTenantStore struct {
	store *store.Store
}

func (t sqliteTenantStore) FindByHost(ctx context.Context, host string) (*tenant.Tenant, error) {
	tn, err := t.store.GetTenantByHandle(ctx, host)
	if err != nil {
		return nil, tenant.ErrNotFound
	}
	return &tenant.Tenant{
		ID:        tn.ID,
		Handle:    tn.Handle,
		DIDMethod: tn.DIDMethod,
		DID:       tn.DID,
	}, nil
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

// ServeHTTP serves the assembled server.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// Run starts the HTTP server on addr with graceful shutdown. It blocks until
// the server exits or ctx is cancelled (SIGINT/SIGTERM), then shuts down.
func (s *Server) Run(ctx context.Context, addr string) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	return s.Serve(ctx, ln)
}

// Serve serves on an existing listener with graceful shutdown. It blocks
// until the server exits or ctx is cancelled, then shuts down cleanly.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:      s,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	s.logger.Info("server listening", "addr", ln.Addr().String())

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ln)
	}()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		// Graceful shutdown with a timeout.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
	}
	return nil
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
