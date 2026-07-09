package chainbind_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/danielmalka/chainbind-go/internal/adapters/keywrap/x25519"
	"github.com/danielmalka/chainbind-go/pkg/chainbind"
)

// TestCore_SealsWithArbitraryAudiences_NoCheckoutNames pins PRD Story 5
// AC-4: with no profile at all, the core seals, verifies and opens using
// only its own concepts — arbitrary audience names and caller-supplied
// segments, no checkout vocabulary anywhere.
func TestCore_SealsWithArbitraryAudiences_NoCheckoutNames(t *testing.T) {
	audAlice, privAlice := newTestAudience(t, "alice")
	audBob, privBob := newTestAudience(t, "bob")

	segments := map[string][]byte{
		"alice": []byte(`{"note":"arbitrary data for alice"}`),
		"bob":   []byte(`{"note":"arbitrary data for bob"}`),
	}

	pub, signer := newIssuerKeypair(t)
	wrapper := x25519.Wrapper{}
	iv := newTestVerifier(t)

	req := chainbind.SealRequest{
		Segments:     segments,
		SegmentOrder: []string{"alice", "bob"},
		Audiences:    []chainbind.Audience{audAlice, audBob},
		IntentRef:    "intent:allow-example",
		Authority:    "https://intent-authority.local/v1",
		Projection:   map[string]any{"region": "us", "limit": 100},
		Issuer:       "core-only-test",
		IssuedAt:     time.Now().UTC(),
		TenantID:     "test-tenant",
		Environment:  "test",
		// Profile and BindingSpecs are deliberately left unset: core-only
		// use, no profile.
	}

	p, err := chainbind.Seal(context.Background(), req, signer, wrapper, iv)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if p.Profile != "" {
		t.Fatalf("Package.Profile = %q, want empty", p.Profile)
	}

	opt := chainbind.VerifyOptions{
		IssuerKey: func(string, string) (ed25519.PublicKey, bool) { return pub, true },
		Intent:    iv,
		// BindingSpecs left nil: no profile bindings to recompute.
	}

	report, err := chainbind.Verify(context.Background(), p, opt)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !report.OK() {
		t.Fatalf("Report.OK() = false, want true: %+v", report)
	}

	gotName, gotPlain, err := chainbind.Open(context.Background(), p, privAlice, wrapper, opt)
	if err != nil {
		t.Fatalf("Open(alice): %v", err)
	}
	if gotName != "alice" {
		t.Fatalf("audience = %q, want %q", gotName, "alice")
	}
	if !bytes.Equal(gotPlain, segments["alice"]) {
		t.Fatalf("plaintext = %s, want %s", gotPlain, segments["alice"])
	}

	gotName, gotPlain, err = chainbind.Open(context.Background(), p, privBob, wrapper, opt)
	if err != nil {
		t.Fatalf("Open(bob): %v", err)
	}
	if gotName != "bob" {
		t.Fatalf("audience = %q, want %q", gotName, "bob")
	}
	if !bytes.Equal(gotPlain, segments["bob"]) {
		t.Fatalf("plaintext = %s, want %s", gotPlain, segments["bob"])
	}
}
