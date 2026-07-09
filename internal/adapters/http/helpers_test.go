package http

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/danielmalka/chainbind-go/internal/adapters/signer/local"
	"github.com/danielmalka/chainbind-go/pkg/chainbind"
	"github.com/danielmalka/chainbind-go/pkg/chainbind/profile/agenticcheckout"
)

// testSigner returns a fresh in-process Ed25519 signer, standing in for
// the Vault signer adapter in every handler test — the HTTP shell does
// not care which chainbind.Signer it is handed — plus the matching public
// key, which local.Signer (unlike the Vault adapter) does not expose
// itself.
func testSigner(t *testing.T) (*local.Signer, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	s, err := local.New(priv, "test-issuer-key-1")
	if err != nil {
		t.Fatalf("local.New: %v", err)
	}
	return s, pub
}

// testAudiencesFile writes a seed file naming exactly the agentic-checkout
// audiences (user, merchant, gateway), each with a fresh X25519 keypair,
// and returns its path.
func testAudiencesFile(t *testing.T) string {
	t.Helper()

	type seed struct {
		Name      string `json:"name"`
		Kid       string `json:"kid"`
		PublicKey string `json:"public_key"`
	}

	var seeds []seed
	for _, name := range agenticcheckout.SegmentOrder() {
		k, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate x25519 key: %v", err)
		}
		seeds = append(seeds, seed{
			Name:      name,
			Kid:       name + "-key-1",
			PublicKey: base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes()),
		})
	}

	raw, err := json.Marshal(seeds)
	if err != nil {
		t.Fatalf("marshal seed audiences: %v", err)
	}

	path := filepath.Join(t.TempDir(), "audiences.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write audiences file: %v", err)
	}
	return path
}

// validCheckoutPayload returns an agenticcheckout.Payload that Split and
// Project both accept without error, under an intent_ref
// fakeIntentVerifier callers configure to allow by default.
func validCheckoutPayload() agenticcheckout.Payload {
	return agenticcheckout.Payload{
		RequestContext: agenticcheckout.RequestContext{
			TenantID:      "test-tenant",
			Environment:   "test",
			RequestID:     "req-1",
			CorrelationID: "corr-1",
			IssuedBy:      "chainbind-go-test",
		},
		Intent: agenticcheckout.Intent{
			IntentRef: "intent:allow-example",
			Authority: "https://intent-authority.local/v1",
		},
		Subject: agenticcheckout.Subject{
			UserID: "user-1",
			Email:  "user@example.test",
		},
		Checkout: agenticcheckout.Checkout{
			CheckoutID: "checkout-1",
			MerchantID: "merchant-1",
			Currency:   "USD",
			Items:      []agenticcheckout.Item{{SKU: "sku-1", Name: "widget", Quantity: 1, UnitPrice: 100}},
			Total:      100,
		},
		Payment: agenticcheckout.Payment{
			PaymentID:     "payment-1",
			PaymentMethod: "card",
			Amount:        100,
		},
	}
}

// fakeIntentVerifier is a fully caller-controlled chainbind.IntentVerifier,
// used instead of the mock package so http tests can drive every seal
// outcome (allow, deny with a chosen reason, unreachable) without
// depending on a shared testdata seed file whose rule fields
// (region/limit) do not match agenticcheckout's projection shape
// (amount/currency/merchant_id).
type fakeIntentVerifier struct {
	checkFn func(ctx context.Context, intentRef string, projection any) (chainbind.IntentDecision, error)
	hashFn  func(ctx context.Context, intentRef string) (string, error)
	pingErr error
}

func (f *fakeIntentVerifier) Check(ctx context.Context, intentRef string, projection any) (chainbind.IntentDecision, error) {
	return f.checkFn(ctx, intentRef, projection)
}

func (f *fakeIntentVerifier) ConstraintsHash(ctx context.Context, intentRef string) (string, error) {
	if f.hashFn != nil {
		return f.hashFn(ctx, intentRef)
	}
	return "sha256:test-constraints-hash", nil
}

func (f *fakeIntentVerifier) Ping(_ context.Context) error {
	return f.pingErr
}

// allowingIntentVerifier always allows and returns a fixed constraints
// hash — the happy-path default every seal test starts from.
func allowingIntentVerifier() *fakeIntentVerifier {
	return &fakeIntentVerifier{
		checkFn: func(context.Context, string, any) (chainbind.IntentDecision, error) {
			return chainbind.IntentDecision{Allowed: true}, nil
		},
	}
}

// fakeAuthorizer is a caller-controlled Authorizer.
type fakeAuthorizer struct {
	err error
}

func (f *fakeAuthorizer) Authorize(context.Context, string) error {
	return f.err
}

// fakeProber is a caller-controlled Prober.
type fakeProber struct {
	err error
}

func (f *fakeProber) Ping(context.Context) error {
	return f.err
}
