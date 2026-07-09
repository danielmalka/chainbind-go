// Package chainbind seals a payload into per-audience segments, verifies a
// package with no keys, and opens exactly one segment given one private key.
// The core is domain-free: it knows only audience names, opaque segment
// bytes, and binding definitions supplied as data.
package chainbind

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/gowebpki/jcs"
)

// JCS returns the RFC 8785 canonical UTF-8 JSON serialization of v.
func JCS(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("chainbind: jcs marshal: %w", err)
	}

	canon, err := jcs.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("chainbind: jcs transform: %w", err)
	}

	return canon, nil
}

// H returns "sha256:" followed by the lowercase hex encoding of SHA-256(b).
func H(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
