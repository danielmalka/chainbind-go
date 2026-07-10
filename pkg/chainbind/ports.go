package chainbind

import "context"

// Signer produces the issuer signature over the canonical signing view. It
// is the only place a private key touches the sealing path; verification of
// the resulting signature needs only the issuer's public key and does not
// require this port.
type Signer interface {
	// Kid identifies the key Sign will use (e.g. a Vault Transit key
	// name and version). It is separate from Sign because issuer.kid is
	// itself inside the signed view: the kid must be known before the
	// bytes that commit to it exist. Without this, the
	// only way to learn the kid is to sign something — and a Signer must
	// never be asked to sign anything but the thing being signed.
	Kid(ctx context.Context) (string, error)

	// Sign signs message with the key Kid names.
	Sign(ctx context.Context, message []byte) (signature []byte, err error)
}

// KeyWrapper wraps a per-segment data-encryption key to a recipient's public
// key at Seal, and unwraps it with the recipient's private key at Open. Open
// depends on KeyWrapper alone: no signer, no authority, no network.
// Thumbprint returns the RFC 7638 JWK thumbprint of recipientPub, the value
// recorded in cnf[a].jkt. It belongs on this port rather than being supplied
// by the caller: cnf must be *derived* from the very public key the data key
// was wrapped to, by the component that understands that key's format. A
// caller-supplied thumbprint would make cnf an assertion by the issuer
// rather than a confirmation, and Open — which matches a recipient's key
// against cnf — would then be matching against the issuer's claim instead of
// against the key the segment was actually sealed to.
type KeyWrapper interface {
	Wrap(ctx context.Context, recipientPub, dek []byte) (wrapped, epk []byte, err error)
	Unwrap(ctx context.Context, priv, epk, wrapped []byte) (dek []byte, err error)
	Thumbprint(recipientPub []byte) (jkt string, err error)

	// PublicKey derives the public half of priv. Open needs it to learn
	// which audience the caller is, by thumbprinting it and matching
	// against cnf. It belongs here because the wrapper owns the curve.
	//
	// This is what keeps Open from taking a segment name. A caller that
	// could name its segment would turn a cryptographic match into an
	// access-control decision, and an access-control decision is a thing
	// that can be got wrong.
	PublicKey(priv []byte) (pub []byte, err error)
}

// IntentDecision is the authority's verdict on whether an execution falls
// within the authorization it claims. Reason carries the authority's own
// words, to be surfaced verbatim when Allowed is false.
type IntentDecision struct {
	Allowed bool
	Reason  string
}

// IntentVerifier is the boundary to the external intent authority. The two
// methods answer different questions at different times, and the
// distinction is load-bearing.
//
// Check asks, at Seal, whether an execution is permitted. A non-nil error
// means the authority could not be reached: Seal fails closed rather than
// minting an unverifiable claim.
//
// ConstraintsHash asks, at Verify, for the authoritative immutable,
// versioned snapshot of the authorization, never live mutable state. It is
// the oracle against which intent_commitment is recomputed; the value
// embedded in the package is only the issuer's claim, and recomputing from
// it would be circular. An unreachable authority leaves the intent level
// unevaluated — indeterminate, never verified.
type IntentVerifier interface {
	Check(ctx context.Context, intentRef string, projection any) (IntentDecision, error)
	ConstraintsHash(ctx context.Context, intentRef string) (constraintsHash string, err error)
}

// Profile turns a domain payload into per-audience plaintext segments. The
// core calls it from Seal; SealRequest.Profile may be nil for core-only use
// with a caller-supplied payload already shaped as segments. A profile owns
// every domain-specific name — the core never sees one.
//
// Project builds the projection sent to the intent authority: only the
// fields policy needs, never the payload. Which fields those are is domain
// knowledge, so only a profile can answer.
type Profile interface {
	Split(payload any) (segments map[string][]byte, err error)
	Project(payload any) (projection any, err error)
}
