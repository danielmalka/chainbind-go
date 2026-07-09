// Command mock-authority is a thin HTTP wrapper over the in-process
// internal/adapters/intent/mock verifier, serving exactly the wire shape
// internal/adapters/intent/http.Verifier speaks (TASK-001-14 decision block).
//
// The shell's cmd/chainbind-api talks only HTTP to its intent authority
// (intenthttp.New(cfg.IntentAuthorityURL, ...)); mock.Verifier is an
// in-process Go type that serves no HTTP. This binary bridges the two so the
// compose stack exercises the real HTTP intent adapter end to end against a
// server, rather than reconfiguring the adapter away.
//
// Wire shape (must match internal/adapters/intent/http/verifier.go):
//
//	POST {base}/v1/intents/{ref}/check
//	  body:     {"projection": <any>}
//	  200 body: {"allowed": bool, "reason": string}
//	GET  {base}/v1/intents/{ref}/constraints-hash
//	  200 body: {"constraints_hash": string}
//	GET  {base}/v1/health -> 200
//
// A mock error is a 5xx, never a fabricated allow or empty hash (D-005,
// AGENTS.local.md invariant 6): the adapter treats any non-2xx as an error
// and never mistakes it for an allow.
//
// main may os.Exit; nothing below main panics or exits.
package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/danielmalka/chainbind-go/internal/adapters/intent/mock"
)

const (
	defaultAddr    = ":9000"
	defaultSeedDir = "/seed"

	// readHeaderTimeout bounds header read time (slowloris defence), matching
	// cmd/chainbind-api's own server.
	readHeaderTimeout = 5 * time.Second
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	addr := envOr("AUTHORITY_ADDR", defaultAddr)
	seedDir := envOr("AUTHORITY_SEED_DIR", defaultSeedDir)

	verifier, err := mock.New(seedDir)
	if err != nil {
		log.Error("mock-authority: load seed dir", "error", err)
		os.Exit(1)
	}
	log.Info("mock-authority: seed loaded", "seed_dir", seedDir)

	srv := &http.Server{
		Addr:              addr,
		Handler:           newHandler(verifier, log),
		ReadHeaderTimeout: readHeaderTimeout,
	}

	log.Info("mock-authority: listening", "addr", addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Error("mock-authority: server stopped", "error", err)
		os.Exit(1)
	}
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// newHandler builds the three-route mux over verifier.
func newHandler(verifier *mock.Verifier, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /v1/intents/{ref}/check", func(w http.ResponseWriter, r *http.Request) {
		ref := r.PathValue("ref")

		var body struct {
			Projection any `json:"projection"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "malformed request body", http.StatusBadRequest)
			return
		}

		decision, err := verifier.Check(r.Context(), ref, body.Projection)
		if err != nil {
			// Never a fabricated allow: a lookup miss or evaluation failure
			// is a 5xx the adapter surfaces as an error (invariant 6).
			log.Warn("mock-authority: check failed", "ref", ref, "error", err)
			http.Error(w, "intent check failed", http.StatusInternalServerError)
			return
		}

		writeJSON(w, log, map[string]any{"allowed": decision.Allowed, "reason": decision.Reason})
	})

	mux.HandleFunc("GET /v1/intents/{ref}/constraints-hash", func(w http.ResponseWriter, r *http.Request) {
		ref := r.PathValue("ref")

		hash, err := verifier.ConstraintsHash(r.Context(), ref)
		if err != nil {
			log.Warn("mock-authority: constraints-hash failed", "ref", ref, "error", err)
			http.Error(w, "constraints hash failed", http.StatusInternalServerError)
			return
		}

		writeJSON(w, log, map[string]string{"constraints_hash": hash})
	})

	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, r *http.Request) {
		if err := verifier.Ping(r.Context()); err != nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, log, map[string]string{"status": "ok"})
	})

	return mux
}

// writeJSON encodes v as a 200 JSON response. An encode failure is logged;
// the header is already committed so nothing more can be done for the client.
func writeJSON(w http.ResponseWriter, log *slog.Logger, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Error("mock-authority: encode response", "error", err)
	}
}
