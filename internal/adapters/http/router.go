package http

import (
	"crypto/ed25519"
	"net/http"

	"github.com/danielmalka/chainbind-go/pkg/chainbind"
)

// HandlerConfig is everything NewHandler needs to wire the shell's four
// routes. Every field is required except where noted; NewHandler does not
// validate them — the caller (cmd/chainbind-api/main.go) owns startup
// wiring and its own error handling.
type HandlerConfig struct {
	// Authorizer gates POST /v1/packages/seal (Bearer + role_issuer_admin,
	// TECHSPEC-001 §7 "Role bypass on the shell").
	Authorizer Authorizer

	// Signer, KeyWrapper and Audiences feed the seal route's
	// chainbind.SealRequest. Audiences is the static roster loaded from
	// the seed file (TECHSPEC-001 §10 open question 1) — never taken from
	// the request body.
	Signer     chainbind.Signer
	KeyWrapper chainbind.KeyWrapper
	Audiences  []chainbind.Audience

	// IssuerID is stamped into issuer.iss. It is the operator's configured
	// identity, never the request body's: the shell holds the signing key,
	// so it is the issuer, and the caller may not choose that name.
	IssuerID string

	// IntentVerifier is asked at Seal (before any ciphertext exists) and
	// again at Verify's Level 2. The same instance backs both routes.
	IntentVerifier chainbind.IntentVerifier

	// IssuerKey resolves the one issuer key this deployment trusts (PRD
	// assumption A4), for the verify route's Level 1 signature check.
	IssuerKey func(iss, kid string) (ed25519.PublicKey, bool)

	// VaultProber and AuthorityProber back /ready. Both are required:
	// /ready reports 503 if either is down (PRD Story 6 AC-2).
	VaultProber     Prober
	AuthorityProber Prober
}

// NewHandler builds the shell's complete route table — exactly the four
// routes TECHSPEC-001 §5 names, no more. There is no decrypt endpoint and
// none is ever added (D-002, architecture invariant 1).
func NewHandler(cfg HandlerConfig) http.Handler {
	mux := http.NewServeMux()

	seal := sealHandler(sealDeps{
		signer:     cfg.Signer,
		keyWrapper: cfg.KeyWrapper,
		intent:     cfg.IntentVerifier,
		audiences:  cfg.Audiences,
		issuerID:   cfg.IssuerID,
	})
	mux.HandleFunc("POST /v1/packages/seal", requireIssuerAdmin(cfg.Authorizer, seal))

	mux.HandleFunc("POST /v1/packages/verify", verifyHandler(verifyOpts{
		issuerKey: cfg.IssuerKey,
		intent:    cfg.IntentVerifier,
	}))

	mux.HandleFunc("GET /health", healthHandler)

	mux.HandleFunc("GET /ready", readyHandler([]namedProber{
		{name: "vault", prober: cfg.VaultProber},
		{name: "intent-authority", prober: cfg.AuthorityProber},
	}))

	return mux
}
