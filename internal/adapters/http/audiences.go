package http

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/danielmalka/chainbind-go/pkg/chainbind"
)

// x25519PublicKeySize is the length in bytes of an X25519 public key.
const x25519PublicKeySize = 32

// audienceSeed is one entry in the audiences seed file: a static roster
// of recipient public keys the seal route addresses, per TECHSPEC-001 §10
// open question 1 (static seeding, not audience keys supplied in the seal
// request body).
type audienceSeed struct {
	Name      string `json:"name"`
	Kid       string `json:"kid"`
	PublicKey string `json:"public_key"` // base64url, unpadded, 32 bytes
}

// LoadAudiences reads path — a JSON array of audienceSeed — and decodes
// every entry's public key. A malformed entry fails the whole load: a
// shell with a partially-seeded audience roster is a misconfiguration to
// catch at startup, not a runtime surprise on the one seal request that
// happens to name the bad entry.
func LoadAudiences(path string) ([]chainbind.Audience, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // path is operator-supplied startup config, not untrusted input
	if err != nil {
		return nil, fmt.Errorf("http: read audiences file: %w", err)
	}

	var seeds []audienceSeed
	if err := json.Unmarshal(raw, &seeds); err != nil {
		return nil, fmt.Errorf("http: parse audiences file: %w", err)
	}

	auds := make([]chainbind.Audience, 0, len(seeds))
	for _, s := range seeds {
		pub, err := base64.RawURLEncoding.DecodeString(s.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("http: audiences file: audience %q: invalid public_key encoding", s.Name)
		}
		if len(pub) != x25519PublicKeySize {
			return nil, fmt.Errorf("http: audiences file: audience %q: public_key is not %d bytes", s.Name, x25519PublicKeySize)
		}
		auds = append(auds, chainbind.Audience{Name: s.Name, PublicKey: pub, Kid: s.Kid})
	}
	return auds, nil
}
