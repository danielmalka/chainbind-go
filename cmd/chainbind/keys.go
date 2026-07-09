package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Key file format (design decision A): one key per file, base64url
// unpadded, no PEM, no headers. A trailing newline is tolerated. Every
// length-mismatch error below names only the *expected* length, never the
// file's contents or its actual decoded length — a length is still a fact
// about key material an attacker could use to distinguish key types
// (AGENTS.local.md invariant 10).
var (
	// errIssuerSigningKeyLength is returned when --signing-key does not
	// decode to a 32-byte Ed25519 seed.
	errIssuerSigningKeyLength = errors.New("chainbind: issuer signing key must decode to 32 bytes (an Ed25519 seed)")

	// errIssuerPublicKeyLength is returned when --issuer-key does not
	// decode to a 32-byte Ed25519 public key.
	errIssuerPublicKeyLength = errors.New("chainbind: issuer public key must decode to 32 bytes")

	// errRecipientKeyLength is returned when --key does not decode to a
	// 32-byte X25519 private key.
	errRecipientKeyLength = errors.New("chainbind: recipient private key must decode to 32 bytes (an X25519 private key)")

	// errAudiencePublicKeyLength is returned when an audiences.json entry's
	// public_key does not decode to a 32-byte X25519 public key.
	errAudiencePublicKeyLength = errors.New("chainbind: audience public key must decode to 32 bytes (an X25519 public key)")
)

// readKeyBytes reads path, trims surrounding whitespace (a trailing newline
// is tolerated by design), and base64url(unpadded)-decodes the result. It
// never echoes the file's contents in an error: a bad decode names only
// that the file failed to decode, nothing about what it contained.
func readKeyBytes(path string) ([]byte, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // path is an operator-supplied CLI flag, not untrusted input
	if err != nil {
		return nil, fmt.Errorf("read key file %q: %w", path, err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("decode key file %q as base64url: %w", path, err)
	}
	return decoded, nil
}

// loadIssuerSigningKey reads a 32-byte Ed25519 seed from path and derives
// the private key ed25519.NewKeyFromSeed produces. Used by seal, never by
// verify or open — signing is the only operation that ever touches an
// issuer's private key.
func loadIssuerSigningKey(path string) (ed25519.PrivateKey, error) {
	b, err := readKeyBytes(path)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.SeedSize {
		return nil, errIssuerSigningKeyLength
	}
	return ed25519.NewKeyFromSeed(b), nil
}

// loadIssuerPublicKey reads a 32-byte Ed25519 public key from path. Used by
// verify and open as the trust-store stand-in described in the -h text.
func loadIssuerPublicKey(path string) (ed25519.PublicKey, error) {
	b, err := readKeyBytes(path)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, errIssuerPublicKeyLength
	}
	return ed25519.PublicKey(b), nil
}

// loadRecipientPrivateKey reads a 32-byte X25519 private key from path. Used
// only by open — this CLI is the one place outside the library where such a
// key is ever read from disk (D-002).
func loadRecipientPrivateKey(path string) ([]byte, error) {
	b, err := readKeyBytes(path)
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, errRecipientKeyLength
	}
	return b, nil
}

// audienceEntry is one element of the audiences.json array seal reads:
// [{"name":"user","kid":"user-key-1","public_key":"<base64url 32 bytes>"}].
type audienceEntry struct {
	Name      string `json:"name"`
	Kid       string `json:"kid"`
	PublicKey string `json:"public_key"`
}

// audienceAndPublicKey pairs one audience entry with its public key,
// separately from the raw JSON structure so decoding errors can name the
// entry that failed without ever naming its key bytes.
type audienceAndPublicKey struct {
	name string
	kid  string
	pub  []byte
}

// loadAudiences reads path as a JSON array of audienceEntry and decodes each
// public_key as base64url(unpadded), 32 bytes. A wrong-length key names the
// offending audience by name (caller-chosen metadata, not secret material),
// never the key's decoded bytes.
func loadAudiences(path string) ([]audienceAndPublicKey, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // path is an operator-supplied CLI flag, not untrusted input
	if err != nil {
		return nil, fmt.Errorf("read audiences file %q: %w", path, err)
	}

	var entries []audienceEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("parse audiences file %q: %w", path, err)
	}

	out := make([]audienceAndPublicKey, 0, len(entries))
	for _, e := range entries {
		pub, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(e.PublicKey))
		if err != nil {
			return nil, fmt.Errorf("audience %q: decode public_key as base64url: %w", e.Name, err)
		}
		if len(pub) != 32 {
			return nil, fmt.Errorf("audience %q: %w", e.Name, errAudiencePublicKeyLength)
		}
		out = append(out, audienceAndPublicKey{name: e.Name, kid: e.Kid, pub: pub})
	}
	return out, nil
}
