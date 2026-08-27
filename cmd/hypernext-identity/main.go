// Command hypernext-identity is the Hypernext identity and data server.
//
// A single multi-tenant binary serving Solid Pod, remoteStorage, atproto PDS,
// IPFS pinning, WebFinger, OIDC/OAuth2 + IndieAuth, and an ActivityPub actor.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hypernext/identity/internal/server"
)

func main() {
	os.Exit(runMain(os.Args[1:]))
}

// runFn is a package-level hook so tests can exercise runMain's error path.
var runFn = run

// runMain runs the CLI and returns a process exit code.
func runMain(args []string) int {
	if err := runFn(args); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

func run(args []string) error {
	// Parse flags: --config <path> (default config.yml), --addr <host:port>.
	configPath := "config.yml"
	addr := ":8080"
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--config":
			if i+1 < len(args) {
				configPath = args[i+1]
				i++
			}
		case "--addr":
			if i+1 < len(args) {
				addr = args[i+1]
				i++
			}
		case "--help", "-h":
			fmt.Println("usage: hypernext-identity [--config config.yml] [--addr :8080]")
			return nil
		}
	}

	cfg, err := server.LoadConfig(configPath)
	if err != nil {
		return err
	}

	srv, err := server.New(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = srv.Close() }()

	// Graceful shutdown on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	httpSrv := &http.Server{
		Addr:         addr,
		Handler:      srv,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- httpSrv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		// Shutdown with a timeout.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
	}
	return nil
}
