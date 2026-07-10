package chainbind_test

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/danielmalka/chainbind-go/internal/adapters/keywrap/x25519"
	"github.com/danielmalka/chainbind-go/internal/adapters/signer/local"
	"github.com/danielmalka/chainbind-go/pkg/chainbind"
)

// allowAll is a stand-in IntentVerifier for the example: it approves every
// execution and reports a fixed constraints hash. A real deployment supplies
// an authority the issuer does not control; Seal fails closed if that
// authority is unreachable.
type allowAll struct{}

func (allowAll) Check(context.Context, string, any) (chainbind.IntentDecision, error) {
	return chainbind.IntentDecision{Allowed: true}, nil
}

func (allowAll) ConstraintsHash(context.Context, string) (string, error) {
	return "sha256:" + "0000000000000000000000000000000000000000000000000000000000000000", nil
}

// Example_sealVerifyOpen seals one payload into two per-audience segments,
// verifies the package holding no key, and opens each segment with only its
// own recipient key. This is the whole library in one function; the README
// quotes it, and it compiles against the real API so it cannot rot.
func Example_sealVerifyOpen() {
	ctx := context.Background()

	// The issuer signs with an Ed25519 key. In production this is a Vault
	// Transit key; here it is in-process.
	issuerPub, issuerPriv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := local.New(issuerPriv, "issuer-key-1")

	// Each recipient owns an X25519 keypair. The issuer holds only the
	// public halves; opening needs the private half and nothing else.
	aliceKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	bobKey, _ := ecdh.X25519().GenerateKey(rand.Reader)

	req := chainbind.SealRequest{
		Segments: map[string][]byte{
			"alice": []byte(`{"note":"for alice only"}`),
			"bob":   []byte(`{"note":"for bob only"}`),
		},
		SegmentOrder: []string{"alice", "bob"},
		Audiences: []chainbind.Audience{
			{Name: "alice", PublicKey: aliceKey.PublicKey().Bytes(), Kid: "alice-1"},
			{Name: "bob", PublicKey: bobKey.PublicKey().Bytes(), Kid: "bob-1"},
		},
		IntentRef:   "intent:example",
		Projection:  map[string]any{"amount": 100},
		Issuer:      "did:example:issuer",
		IssuedAt:    time.Unix(0, 0).UTC(),
		TenantID:    "demo",
		Environment: "dev",
	}

	pkg, err := chainbind.Seal(ctx, req, signer, x25519.Wrapper{}, allowAll{})
	if err != nil {
		fmt.Println("seal:", err)
		return
	}

	// Verify holds no key material of its own — it needs only the issuer's
	// public key, resolved from the caller's trust store.
	report, err := chainbind.Verify(ctx, pkg, chainbind.VerifyOptions{
		IssuerKey: func(string, string) (ed25519.PublicKey, bool) { return issuerPub, true },
		Intent:    allowAll{},
	})
	if err != nil {
		fmt.Println("verify:", err)
		return
	}
	fmt.Println("verified:", report.OK())

	// Alice opens her segment with her own key. The audience is derived from
	// the key, never named by the caller.
	who, plaintext, err := chainbind.Open(ctx, pkg, aliceKey.Bytes(), x25519.Wrapper{}, chainbind.VerifyOptions{
		IssuerKey: func(string, string) (ed25519.PublicKey, bool) { return issuerPub, true },
	})
	if err != nil {
		fmt.Println("open:", err)
		return
	}
	fmt.Printf("%s opened: %s\n", who, plaintext)

	// Output:
	// verified: true
	// alice opened: {"note":"for alice only"}
}
