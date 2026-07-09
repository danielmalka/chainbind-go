// Package local implements chainbind.Signer in-process with
// crypto/ed25519, so a library user can sign a package without a Vault
// deployment (TECHSPEC-001 §6.6 decision 3). It never reads a key from
// disk or the environment; the caller supplies one. The Vault Transit
// adapter is a separate, deployed implementation of the same port
// (TASK-001-11), not a variant of this one.
package local

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
)

// ErrKeySize is returned by New when the supplied private key is not a
// valid Ed25519 private key length. The message names only the expected
// and actual byte counts, never key material.
var ErrKeySize = errors.New("chainbind/signer/local: invalid private key size")

// Signer signs messages with an in-process Ed25519 private key. It
// implements chainbind.Signer.
type Signer struct {
	priv ed25519.PrivateKey
	kid  string
}

// New returns a Signer over priv, identified to callers as kid (echoed
// back from Sign so the caller can stamp it into signature.kid). priv must
// be ed25519.PrivateKeySize bytes.
func New(priv ed25519.PrivateKey, kid string) (*Signer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: got %d bytes, want %d", ErrKeySize, len(priv), ed25519.PrivateKeySize)
	}
	return &Signer{priv: priv, kid: kid}, nil
}

// Kid returns the configured key identifier. It never signs anything: a
// caller that needs the kid before it can build the bytes to be signed —
// which Seal does, since issuer.kid is inside the signing view — must be
// able to ask.
func (s *Signer) Kid(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("chainbind/signer/local: %w", err)
	}
	return s.kid, nil
}

// Sign signs message with the Ed25519 private key. It does not block and
// ignores ctx beyond the standard cancellation check, since Ed25519
// signing here is in-process and does not itself make a network call.
func (s *Signer) Sign(ctx context.Context, message []byte) (signature []byte, err error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("chainbind/signer/local: %w", err)
	}
	return ed25519.Sign(s.priv, message), nil
}

// Verify reports whether sig is a valid Ed25519 signature over message
// under pub. It is a plain function, not a Signer method: verification
// needs only a public key, never the signer or its private key
// (TECHSPEC-001 §6.4 — "verification ... does not require this port").
//
// The length guards are not defensive noise. crypto/ed25519.Verify panics
// on a public key of the wrong size, and this function sits on the
// verification path, where every input is attacker-controlled by
// definition: the issuer key is resolved from issuer.iss and issuer.kid
// carried inside the very package being verified. A panic there is a
// denial of service on the one operation that exists to process hostile
// artifacts. A malformed key is not a valid signature, so it returns false.
func Verify(pub ed25519.PublicKey, message, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, message, sig)
}
