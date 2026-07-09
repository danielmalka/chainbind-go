// Command chainbind-api runs the thin HTTP shell over pkg/chainbind
// (TECHSPEC-001 §5, AGENTS.local.md — "the library is the product").
//
// It wires config, a structured logger, the Vault Transit signer, the
// X25519 key wrapper, the HTTP intent authority, a Keycloak JWKS
// authorizer, and the static audience roster into a runnable net/http
// server, and shuts it down gracefully on SIGINT/SIGTERM.
//
// There is no decrypt endpoint here, and this binary never calls
// chainbind.Open — opening a segment happens only in the recipient's own
// process, via the library or cmd/chainbind open (D-002).
package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/danielmalka/chainbind-go/internal/adapters/auth/keycloak"
	stdhttp "github.com/danielmalka/chainbind-go/internal/adapters/http"
	intenthttp "github.com/danielmalka/chainbind-go/internal/adapters/intent/http"
	"github.com/danielmalka/chainbind-go/internal/adapters/keywrap/x25519"
	"github.com/danielmalka/chainbind-go/internal/adapters/signer/vault"
	"github.com/danielmalka/chainbind-go/internal/platform/config"
	"github.com/danielmalka/chainbind-go/internal/platform/logger"
)

// startupTimeout bounds every one-shot network call main makes while
// wiring dependencies (fetching Vault's key metadata). It is not the
// per-request timeout the adapters apply on their own calls.
const startupTimeout = 10 * time.Second

// readHeaderTimeout bounds the time a client may spend sending request
// headers. A server without one is a slowloris target: a client that
// opens a connection and trickles headers one byte at a time ties up a
// goroutine indefinitely.
const readHeaderTimeout = 5 * time.Second

// shutdownGrace bounds how long a graceful shutdown waits for in-flight
// requests to finish before main returns anyway.
const shutdownGrace = 10 * time.Second

func main() {
	log := logger.New(os.Stdout, slog.LevelInfo)

	if err := run(log); err != nil {
		log.Error("chainbind-api: exiting", "error", err)
		os.Exit(1)
	}
}

// run does the real work; main's only job is to turn its error into an
// exit code. Nothing below main ever calls os.Exit or panics outside
// init (AGENTS.local.md conventions).
func run(log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log.Info("chainbind-api: configuration loaded", "config", cfg)

	ctx, cancel := context.WithTimeout(context.Background(), startupTimeout)
	defer cancel()

	signer, err := vault.New(ctx, cfg.VaultAddr, cfg.VaultToken, cfg.VaultTransitKey, nil, startupTimeout)
	if err != nil {
		return err
	}
	issuerKid, err := signer.Kid(ctx)
	if err != nil {
		return err
	}
	issuerPub := signer.PublicKey()

	intentVerifier := intenthttp.New(cfg.IntentAuthorityURL, nil, startupTimeout)
	authz := keycloak.New(cfg.KeycloakJWKSURL, cfg.KeycloakIssuer, cfg.KeycloakAudience, nil)

	audiences, err := stdhttp.LoadAudiences(cfg.AudiencesFile)
	if err != nil {
		return err
	}

	handler := stdhttp.NewHandler(stdhttp.HandlerConfig{
		IssuerID:       cfg.IssuerID,
		Authorizer:     authz,
		Signer:         signer,
		KeyWrapper:     x25519.Wrapper{},
		Audiences:      audiences,
		IntentVerifier: intentVerifier,
		IssuerKey: func(_, kid string) (ed25519.PublicKey, bool) {
			if kid != issuerKid {
				return nil, false
			}
			return issuerPub, true
		},
		VaultProber:     signer,
		AuthorityProber: intentVerifier,
	})

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	return serveUntilSignal(srv, log)
}

// serveUntilSignal runs srv until SIGINT/SIGTERM, then shuts it down
// within shutdownGrace.
func serveUntilSignal(srv *http.Server, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() {
		log.Info("chainbind-api: listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		log.Info("chainbind-api: shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return <-serveErr
	}
}
