package http

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/danielmalka/chainbind-go/pkg/chainbind"
	"github.com/danielmalka/chainbind-go/pkg/chainbind/profile/agenticcheckout"
)

// maxSealRequestBody caps the seal request body before any JSON decoding
// happens (TECHSPEC-001 §7 DoS "huge payload"). 1 MiB comfortably covers
// an agentic-checkout payload; a legitimate deployment with larger
// payloads would raise this deliberately, not discover the absence of a
// cap by being the first to hit it.
const maxSealRequestBody = 1 << 20 // 1 MiB

// sealDeps is everything the seal handler needs, wired once at startup by
// NewHandler. It never touches chainbind.Open — there is no decrypt path
// on this route (D-002).
type sealDeps struct {
	signer     chainbind.Signer
	keyWrapper chainbind.KeyWrapper
	intent     chainbind.IntentVerifier
	audiences  []chainbind.Audience
	// issuerID is the issuer identity stamped into issuer.iss. It comes
	// from the operator's configuration, never from the request body: the
	// shell *is* the issuer (it holds the signing key and seals — D-002),
	// so the caller does not get to name who sealed on the operator's
	// behalf. A request-supplied issuer would put an attacker-chosen string
	// inside the signed view, over the operator's Vault key.
	issuerID string
}

// sealHandler decodes an agentic-checkout payload, splits and projects it
// via the profile, seals it against the shell's configured signer, key
// wrapper, intent authority and audience roster, and returns the signed
// Package. TECHSPEC-001 §5: 400 invalid payload, 422 intent denied (the
// authority's own reason), 502 authority unreachable.
func sealHandler(deps sealDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !hasJSONContentType(r) {
			writeProblem(w, http.StatusUnsupportedMediaType, typeUnsupportedMedia, "unsupported media type", "Content-Type must be application/json")
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxSealRequestBody)

		var payload agenticcheckout.Payload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeProblem(w, http.StatusBadRequest, typeMalformedRequest, "malformed request", "invalid or oversized payload")
			return
		}

		segments, err := agenticcheckout.Profile{}.Split(payload)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, typeMalformedRequest, "malformed request", "payload does not match the agentic-checkout shape")
			return
		}
		projection, err := agenticcheckout.Profile{}.Project(payload)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, typeMalformedRequest, "malformed request", "payload does not match the agentic-checkout shape")
			return
		}

		req := chainbind.SealRequest{
			Segments:     segments,
			SegmentOrder: agenticcheckout.SegmentOrder(),
			Audiences:    deps.audiences,
			IntentRef:    payload.Intent.IntentRef,
			Authority:    payload.Intent.Authority,
			Projection:   projection,
			Issuer:       deps.issuerID,
			IssuedAt:     time.Now().UTC(),
			TenantID:     payload.RequestContext.TenantID,
			Environment:  payload.RequestContext.Environment,
			Profile:      agenticcheckout.Name,
			BindingSpecs: agenticcheckout.BindingSpecs(),
		}

		pkg, err := chainbind.Seal(r.Context(), req, deps.signer, deps.keyWrapper, deps.intent)
		if err != nil {
			writeSealError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, pkg)
	}
}

// writeSealError maps a chainbind.Seal error to its HTTP status.
//
// The only two outcomes TECHSPEC-001 §5 draws here are a denial (422,
// carrying the authority's own reason verbatim — PRD Story 2 AC-2) and
// everything else Seal can fail on: an unreachable or erroring intent
// authority, a signer failure, a key-wrap failure (502). Seal fails closed
// on every one of these (architecture invariant 6) — there is no
// unverified fallback to distinguish a 502 from a 200 for.
func writeSealError(w http.ResponseWriter, err error) {
	if errors.Is(err, chainbind.ErrIntentDenied) {
		writeProblem(w, http.StatusUnprocessableEntity, typeIntentDenied, "intent denied", intentDeniedReason(err))
		return
	}
	writeProblem(w, http.StatusBadGateway, typeAuthorityDown, "authority unreachable", "the intent authority could not be reached")
}

// intentDeniedReason extracts the authority's own reason from a
// chainbind.ErrIntentDenied-wrapping error, by taking the wrapped error's
// message after the sentinel's own text — never inventing a new string
// (the brief for this task is explicit: this is the caller's own
// authorization data, and it must be surfaced exactly as chainbind
// recorded it, not reworded).
func intentDeniedReason(err error) string {
	sentinel := chainbind.ErrIntentDenied.Error()
	msg := err.Error()
	idx := strings.Index(msg, sentinel)
	if idx < 0 {
		return ""
	}
	return strings.TrimPrefix(msg[idx+len(sentinel):], ": ")
}

// issuerKeyResolver builds a chainbind.VerifyOptions.IssuerKey that trusts
// exactly one issuer key: the shell's own signer, identified by the kid it
// pins at construction (PRD assumption A4 — single issuer, single trust
// list of one). iss is accepted unconditionally; only kid is checked,
// since the cryptographic guarantee comes entirely from which key
// resolve returns, not from string-matching an attacker-controlled iss
// claim.
func issuerKeyResolver(expectedKid string, pub ed25519.PublicKey) func(iss, kid string) (ed25519.PublicKey, bool) {
	return func(_, kid string) (ed25519.PublicKey, bool) {
		if kid != expectedKid {
			return nil, false
		}
		return pub, true
	}
}

// hasJSONContentType reports whether r declares an application/json
// Content-Type (parameters such as charset are ignored).
func hasJSONContentType(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.TrimSpace(ct) == "application/json"
}
