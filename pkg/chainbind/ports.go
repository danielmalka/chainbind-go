package chainbind

import "context"

// Signer produces the issuer signature over the canonical signing view. It
// is the only place a private key touches the sealing path; verification of
// the resulting signature needs only the issuer's public key and does not
// require this port (TECHSPEC-001 §6.4, decision 3).
type Signer interface {
	// Sign signs message and returns the signature together with the kid
	// that identifies the key used (e.g. a Vault key version).
	Sign(ctx context.Context, message []byte) (signature []byte, kid string, err error)
}

// KeyWrapper wraps a per-segment data-encryption key to a recipient's public
// key at Seal, and unwraps it with the recipient's private key at Open. Open
// depends on KeyWrapper alone: no signer, no authority, no network.
type KeyWrapper interface {
	Wrap(ctx context.Context, recipientPub, dek []byte) (wrapped, epk []byte, err error)
	Unwrap(ctx context.Context, priv, epk, wrapped []byte) (dek []byte, err error)
}

// IntentDecision is the authority's verdict on whether an execution falls
// within the authorization it claims. Reason carries the authority's own
// words, to be surfaced verbatim when Allowed is false (PRD Story 2 AC-2).
type IntentDecision struct {
	Allowed bool
	Reason  string
}

// IntentVerifier is the boundary to the external intent authority (D-005).
// The two methods answer different questions at different times, and the
// distinction is load-bearing.
//
// Check asks, at Seal, whether an execution is permitted. A non-nil error
// means the authority could not be reached: Seal fails closed rather than
// minting an unverifiable claim (PRD Story 2 AC-3).
//
// ConstraintsHash asks, at Verify, for the authoritative immutable,
// versioned snapshot of the authorization (D-012), never live mutable
// state. It is the oracle against which intent_commitment is recomputed;
// the value embedded in the package is only the issuer's claim, and
// recomputing from it would be circular (D-011). An unreachable authority
// leaves the intent level unevaluated — indeterminate, never verified.
type IntentVerifier interface {
	Check(ctx context.Context, intentRef string, projection any) (IntentDecision, error)
	ConstraintsHash(ctx context.Context, intentRef string) (constraintsHash string, err error)
}

// Profile turns a domain payload into per-audience plaintext segments. The
// core calls it from Seal; SealRequest.Profile may be nil for core-only use
// with a caller-supplied payload already shaped as segments (PRD Story 5
// AC-4). A profile owns every domain-specific name (D-004) — the core never
// sees one.
//
// Project builds the projection sent to the intent authority: only the
// fields policy needs, never the payload (D-009). Which fields those are is
// domain knowledge, so only a profile can answer.
type Profile interface {
	Split(payload any) (segments map[string][]byte, err error)
	Project(payload any) (projection any, err error)
}
