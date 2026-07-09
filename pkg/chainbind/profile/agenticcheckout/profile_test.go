package agenticcheckout_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/danielmalka/chainbind-go/internal/adapters/intent/mock"
	"github.com/danielmalka/chainbind-go/internal/adapters/keywrap/x25519"
	"github.com/danielmalka/chainbind-go/internal/adapters/signer/local"
	"github.com/danielmalka/chainbind-go/pkg/chainbind"
	"github.com/danielmalka/chainbind-go/pkg/chainbind/profile/agenticcheckout"
)

// testPayload returns a Payload whose projection satisfies the
// "intent:profile-test" seed authorization: currency BRL, amount within
// bound.
func testPayload() agenticcheckout.Payload {
	return agenticcheckout.Payload{
		RequestContext: agenticcheckout.RequestContext{
			TenantID:      "demo-tenant",
			Environment:   "test",
			RequestID:     "req-1",
			CorrelationID: "corr-1",
			IssuedBy:      "checkout-orchestrator",
		},
		Intent: agenticcheckout.Intent{
			IntentRef: "intent:profile-test",
			Authority: "https://intent-authority.local/v1",
		},
		Subject: agenticcheckout.Subject{
			UserID:        "usr_123",
			AccountID:     "acc_456",
			Name:          "Test User",
			Email:         "test@example.com",
			Roles:         []string{"role_user"},
			Permissions:   []string{"checkout:create"},
			AccountStatus: "active",
		},
		Checkout: agenticcheckout.Checkout{
			CheckoutID:   "chk_789",
			MerchantID:   "mer_001",
			MerchantName: "Test Store",
			Currency:     "BRL",
			Items: []agenticcheckout.Item{
				{SKU: "SKU-1", Name: "Widget", Quantity: 1, UnitPrice: 1000},
			},
			Subtotal: 1000,
			Shipping: 0,
			Discount: 0,
			Total:    1000,
		},
		Payment: agenticcheckout.Payment{
			PaymentID:         "pay_001",
			PaymentMethod:     "pix",
			BankAccountMasked: "***1234",
			BankCode:          "341",
			PaymentReference:  "pix-1",
			TransactionStatus: "pending",
			Amount:            1000,
		},
	}
}

// seedVerifier writes the given seed documents into a fresh t.TempDir() and
// returns a mock.Verifier loaded from it.
func seedVerifier(t *testing.T, docs ...string) *mock.Verifier {
	t.Helper()
	dir := t.TempDir()
	for i, doc := range docs {
		path := filepath.Join(dir, "seed-"+string(rune('a'+i))+".json")
		if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
			t.Fatalf("write seed file: %v", err)
		}
	}
	v, err := mock.New(dir)
	if err != nil {
		t.Fatalf("mock.New: %v", err)
	}
	return v
}

// allowSeed constrains all three projected fields, not just two. A rule on
// merchant_id is what makes a wrongly-sourced merchant_id a *denial* by the
// authority rather than a value nothing looks at: it is the field a real
// merchant-allowlist policy would gate on (D-009).
const allowSeed = `{"ref":"intent:profile-test","version":1,"rules":{"currency":{"equals":["BRL"]},"amount":{"max":1000000},"merchant_id":{"equals":["mer_001"]}}}`

const denySeed = `{"ref":"intent:profile-test-deny","version":1,"rules":{"currency":{"equals":["USD"]}}}`

func newTestSigner(t *testing.T) (*local.Signer, ed25519.PublicKey) {
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

// audienceKeys holds the fresh X25519 keypair generated for one audience.
type audienceKeys struct {
	aud  chainbind.Audience
	priv []byte
}

func newAudienceKeys(t *testing.T, name string) audienceKeys {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate x25519 key: %v", err)
	}
	return audienceKeys{
		aud:  chainbind.Audience{Name: name, PublicKey: k.PublicKey().Bytes(), Kid: name + "-key-1"},
		priv: k.Bytes(),
	}
}

// sealPayload builds a SealRequest for payload through the profile and seals
// it, returning the package plus the per-audience private keys.
func sealPayload(t *testing.T, payload agenticcheckout.Payload, signer *local.Signer, iv *mock.Verifier) (*chainbind.Package, map[string]audienceKeys) {
	t.Helper()

	var profile agenticcheckout.Profile
	segments, err := profile.Split(payload)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	projection, err := profile.Project(payload)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}

	keys := map[string]audienceKeys{
		agenticcheckout.AudienceUser:     newAudienceKeys(t, agenticcheckout.AudienceUser),
		agenticcheckout.AudienceMerchant: newAudienceKeys(t, agenticcheckout.AudienceMerchant),
		agenticcheckout.AudienceGateway:  newAudienceKeys(t, agenticcheckout.AudienceGateway),
	}
	audiences := []chainbind.Audience{
		keys[agenticcheckout.AudienceUser].aud,
		keys[agenticcheckout.AudienceMerchant].aud,
		keys[agenticcheckout.AudienceGateway].aud,
	}

	req := chainbind.SealRequest{
		Segments:     segments,
		SegmentOrder: agenticcheckout.SegmentOrder(),
		Audiences:    audiences,
		IntentRef:    payload.Intent.IntentRef,
		Authority:    payload.Intent.Authority,
		Projection:   projection,
		Issuer:       "agenticcheckout-test",
		IssuedAt:     time.Now().UTC(),
		TenantID:     payload.RequestContext.TenantID,
		Environment:  payload.RequestContext.Environment,
		Profile:      agenticcheckout.Name,
		BindingSpecs: agenticcheckout.BindingSpecs(),
	}

	p, err := chainbind.Seal(context.Background(), req, signer, x25519.Wrapper{}, iv)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return p, keys
}

func TestProfile_SealVerifyOpen_RoundTripsAllAudiences(t *testing.T) {
	iv := seedVerifier(t, allowSeed)
	signer, pub := newTestSigner(t)
	payload := testPayload()

	p, keys := sealPayload(t, payload, signer, iv)

	opt := chainbind.VerifyOptions{
		IssuerKey:    func(string, string) (ed25519.PublicKey, bool) { return pub, true },
		Intent:       iv,
		BindingSpecs: agenticcheckout.BindingSpecs(),
	}
	report, err := chainbind.Verify(context.Background(), p, opt)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !report.OK() {
		t.Fatalf("Report.OK() = false, want true: %+v", report)
	}
	for name, ok := range report.ProfileBindings {
		if !ok {
			t.Fatalf("profile binding %q did not verify", name)
		}
	}
	if len(report.ProfileBindings) != 3 {
		t.Fatalf("got %d profile bindings, want 3", len(report.ProfileBindings))
	}

	wantPlain, err := (agenticcheckout.Profile{}).Split(payload)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}

	for _, name := range agenticcheckout.SegmentOrder() {
		gotName, gotPlain, err := chainbind.Open(context.Background(), p, keys[name].priv, x25519.Wrapper{}, opt)
		if err != nil {
			t.Fatalf("Open(%q): %v", name, err)
		}
		if gotName != name {
			t.Fatalf("Open returned audience %q, want %q", gotName, name)
		}
		if !bytes.Equal(gotPlain, wantPlain[name]) {
			t.Fatalf("Open(%q) plaintext = %s, want %s", name, gotPlain, wantPlain[name])
		}
	}
}

func TestProfile_CheckoutHashAliasesMerchantPlainHash(t *testing.T) {
	iv := seedVerifier(t, allowSeed)
	signer, _ := newTestSigner(t)
	payload := testPayload()

	p, _ := sealPayload(t, payload, signer, iv)

	got := p.Bindings.Extra["checkout_hash"]
	want := p.Manifest.Segments[agenticcheckout.AudienceMerchant].PlainHash
	if got != want {
		t.Fatalf("checkout_hash = %q, want %q (merchant plain_hash)", got, want)
	}
}

func TestProfile_TransactionIDChangesWithEitherInput(t *testing.T) {
	iv := seedVerifier(t, allowSeed)
	signer, _ := newTestSigner(t)

	base := testPayload()
	pBase, _ := sealPayload(t, base, signer, iv)
	txnBase := pBase.Bindings.Extra["transaction_id"]

	// Reseal the identical payload: package_id differs, transaction_id must
	// not.
	pSame, _ := sealPayload(t, base, signer, iv)
	txnSame := pSame.Bindings.Extra["transaction_id"]
	if pSame.PackageID == pBase.PackageID {
		t.Fatal("package_id repeated across two seals — the resealed-identical-payload assertion below proves nothing")
	}
	if txnSame != txnBase {
		t.Fatalf("transaction_id changed across two seals of the identical payload: %q vs %q", txnBase, txnSame)
	}

	// Mutate only the checkout (merchant) section. The field must be one the
	// seeded authorization does not constrain, or Seal is denied before a
	// transaction_id is ever computed — merchant_id and currency are gated,
	// checkout_id is not.
	checkoutMutated := base
	checkoutMutated.Checkout.CheckoutID = "chk_790"
	pCheckout, _ := sealPayload(t, checkoutMutated, signer, iv)
	txnCheckout := pCheckout.Bindings.Extra["transaction_id"]

	// Mutate only the payment (gateway) section.
	paymentMutated := base
	paymentMutated.Payment.PaymentReference = "pix-2"
	pPayment, _ := sealPayload(t, paymentMutated, signer, iv)
	txnPayment := pPayment.Bindings.Extra["transaction_id"]

	if txnBase == txnCheckout {
		t.Fatal("transaction_id unchanged after mutating only the checkout section")
	}
	if txnBase == txnPayment {
		t.Fatal("transaction_id unchanged after mutating only the payment section")
	}
	if txnCheckout == txnPayment {
		t.Fatal("mutating checkout and mutating payment produced the same transaction_id")
	}
}

func TestProfile_ConditionalTransactionIDAliasesIntentCommitment(t *testing.T) {
	iv := seedVerifier(t, allowSeed)
	signer, _ := newTestSigner(t)
	payload := testPayload()

	p, _ := sealPayload(t, payload, signer, iv)

	got := p.Bindings.Extra["conditional_transaction_id"]
	want := p.Bindings.IntentCommitment
	if got != want {
		t.Fatalf("conditional_transaction_id = %q, want %q (intent_commitment)", got, want)
	}
}

func TestProfile_ProjectReturnsExactlyThreeFields(t *testing.T) {
	payload := testPayload()
	var profile agenticcheckout.Profile
	projection, err := profile.Project(payload)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}

	raw, err := json.Marshal(projection)
	if err != nil {
		t.Fatalf("marshal projection: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("unmarshal projection: %v", err)
	}

	if len(fields) != 3 {
		t.Fatalf("projection has %d fields, want 3: %v", len(fields), fields)
	}

	// Field names and count are not enough. Each value must come from the
	// section that owns it: amount from Payment, currency and merchant_id
	// from Checkout. Asserting only the key set lets a wrongly-sourced
	// merchant_id ship green, and merchant_id is the field a merchant
	// allowlist gates on (D-009).
	want := map[string]any{
		"amount":      float64(payload.Payment.Amount),
		"currency":    payload.Checkout.Currency,
		"merchant_id": payload.Checkout.MerchantID,
	}
	for key, wantVal := range want {
		gotVal, ok := fields[key]
		if !ok {
			t.Fatalf("projection missing field %q: %v", key, fields)
		}
		if gotVal != wantVal {
			t.Fatalf("projection %q = %v, want %v", key, gotVal, wantVal)
		}
	}
}

// TestProfile_BindingSpecs_RejectMissingSegmentHash exercises the guards that
// make ErrMissingSegmentHash reachable. Deleting either guard lets a missing
// plain_hash silently become "", and without this test nothing notices.
func TestProfile_BindingSpecs_RejectMissingSegmentHash(t *testing.T) {
	specs := make(map[string]chainbind.BindingSpec, 3)
	for _, s := range agenticcheckout.BindingSpecs() {
		specs[s.Name] = s
	}

	cases := map[string]map[string]string{
		"no plain_hash at all":  {},
		"merchant hash missing": {agenticcheckout.AudienceGateway: "sha256:bbbb"},
		"gateway hash missing":  {agenticcheckout.AudienceMerchant: "sha256:aaaa"},
	}

	for name, plainHash := range cases {
		t.Run(name, func(t *testing.T) {
			for _, specName := range []string{"checkout_hash", "transaction_id"} {
				if specName == "checkout_hash" && plainHash[agenticcheckout.AudienceMerchant] != "" {
					continue // checkout_hash only needs the merchant hash.
				}
				_, err := specs[specName].Compute(chainbind.BindingContext{PlainHash: plainHash})
				if !errors.Is(err, agenticcheckout.ErrMissingSegmentHash) {
					t.Fatalf("%s error = %v, want ErrMissingSegmentHash", specName, err)
				}
			}
		})
	}
}

// TestProfile_AcceptsPayloadPointer proves Split and Project accept *Payload
// and agree with the value form, and that a nil *Payload is rejected rather
// than silently splitting a zero payload into three segments.
func TestProfile_AcceptsPayloadPointer(t *testing.T) {
	payload := testPayload()
	var profile agenticcheckout.Profile

	byValue, err := profile.Split(payload)
	if err != nil {
		t.Fatalf("Split(Payload): %v", err)
	}
	byPointer, err := profile.Split(&payload)
	if err != nil {
		t.Fatalf("Split(*Payload): %v", err)
	}
	for name, want := range byValue {
		if !bytes.Equal(byPointer[name], want) {
			t.Fatalf("Split(*Payload)[%q] differs from Split(Payload)[%q]", name, name)
		}
	}

	projValue, err := profile.Project(payload)
	if err != nil {
		t.Fatalf("Project(Payload): %v", err)
	}
	projPointer, err := profile.Project(&payload)
	if err != nil {
		t.Fatalf("Project(*Payload): %v", err)
	}
	if projValue != projPointer {
		t.Fatalf("Project(*Payload) = %v, want %v", projPointer, projValue)
	}

	var nilPayload *agenticcheckout.Payload
	if _, err := profile.Split(nilPayload); !errors.Is(err, agenticcheckout.ErrUnsupportedPayload) {
		t.Fatalf("Split((*Payload)(nil)) error = %v, want ErrUnsupportedPayload", err)
	}
	if _, err := profile.Project(nilPayload); !errors.Is(err, agenticcheckout.ErrUnsupportedPayload) {
		t.Fatalf("Project((*Payload)(nil)) error = %v, want ErrUnsupportedPayload", err)
	}
}

// TestProfile_TransactionID_KnownAnswer pins the formula itself, not merely
// its sensitivity to its inputs. It builds the expected value from
// TECHSPEC-001 §6.1 directly — hand-written canonical JSON, stdlib SHA-256 —
// without calling chainbind.JCS or chainbind.H, so it fails if the "txn:"
// prefix changes, if either JSON key is renamed, or if the two plain_hash
// values are fed to the wrong fields.
//
// It exists because sensitivity alone proves nothing: Verify's L1.6
// recomputes each binding by calling this same function, so a wrong formula
// agrees with itself and every round-trip test stays green.
func TestProfile_TransactionID_KnownAnswer(t *testing.T) {
	const (
		merchantHash = "sha256:aaaa"
		gatewayHash  = "sha256:bbbb"
	)

	// RFC 8785 sorts object keys: checkout_hash before gateway_plain_hash.
	canonical := `{"checkout_hash":"` + merchantHash + `","gateway_plain_hash":"` + gatewayHash + `"}`
	sum := sha256.Sum256([]byte(canonical))
	want := "txn:sha256:" + hex.EncodeToString(sum[:])

	var spec chainbind.BindingSpec
	for _, s := range agenticcheckout.BindingSpecs() {
		if s.Name == "transaction_id" {
			spec = s
		}
	}
	if spec.Compute == nil {
		t.Fatal("BindingSpecs() has no transaction_id spec")
	}

	got, err := spec.Compute(chainbind.BindingContext{
		PlainHash: map[string]string{
			agenticcheckout.AudienceMerchant: merchantHash,
			agenticcheckout.AudienceGateway:  gatewayHash,
		},
	})
	if err != nil {
		t.Fatalf("compute transaction_id: %v", err)
	}
	if got != want {
		t.Fatalf("transaction_id = %q, want %q", got, want)
	}
}

// TestProfile_SplitMapsEachSectionToItsOwnAudience pins the A3 mapping
// directly: user <- Subject, merchant <- Checkout, gateway <- Payment.
// Disjointness and round-tripping both hold under a permutation of the three
// sections, so neither proves this.
func TestProfile_SplitMapsEachSectionToItsOwnAudience(t *testing.T) {
	payload := testPayload()
	segments, err := (agenticcheckout.Profile{}).Split(payload)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}

	var subject agenticcheckout.Subject
	if err := json.Unmarshal(segments[agenticcheckout.AudienceUser], &subject); err != nil {
		t.Fatalf("unmarshal user segment: %v", err)
	}
	if subject.UserID != payload.Subject.UserID {
		t.Fatalf("user segment is not the subject section: user_id = %q", subject.UserID)
	}

	var checkout agenticcheckout.Checkout
	if err := json.Unmarshal(segments[agenticcheckout.AudienceMerchant], &checkout); err != nil {
		t.Fatalf("unmarshal merchant segment: %v", err)
	}
	if checkout.CheckoutID != payload.Checkout.CheckoutID {
		t.Fatalf("merchant segment is not the checkout section: checkout_id = %q", checkout.CheckoutID)
	}

	var payment agenticcheckout.Payment
	if err := json.Unmarshal(segments[agenticcheckout.AudienceGateway], &payment); err != nil {
		t.Fatalf("unmarshal gateway segment: %v", err)
	}
	if payment.PaymentID != payload.Payment.PaymentID {
		t.Fatalf("gateway segment is not the payment section: payment_id = %q", payment.PaymentID)
	}
}

func TestProfile_SplitProducesDisjointSegments(t *testing.T) {
	payload := testPayload()
	var profile agenticcheckout.Profile
	segments, err := profile.Split(payload)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	if len(segments) != 3 {
		t.Fatalf("got %d segments, want 3", len(segments))
	}

	keysets := make(map[string]map[string]struct{}, 3)
	for name, plaintext := range segments {
		var fields map[string]any
		if err := json.Unmarshal(plaintext, &fields); err != nil {
			t.Fatalf("unmarshal segment %q: %v", name, err)
		}
		keys := make(map[string]struct{}, len(fields))
		for k := range fields {
			keys[k] = struct{}{}
		}
		keysets[name] = keys
	}

	names := agenticcheckout.SegmentOrder()
	for i := range names {
		for j := i + 1; j < len(names); j++ {
			for k := range keysets[names[i]] {
				if _, dup := keysets[names[j]][k]; dup {
					t.Fatalf("field %q appears in both segment %q and segment %q", k, names[i], names[j])
				}
			}
		}
	}
}

func TestProfile_Split_RejectsUnsupportedPayload(t *testing.T) {
	var profile agenticcheckout.Profile

	if _, err := profile.Split(42); !errors.Is(err, agenticcheckout.ErrUnsupportedPayload) {
		t.Fatalf("Split(42) error = %v, want ErrUnsupportedPayload", err)
	}
	if _, err := profile.Split(nil); !errors.Is(err, agenticcheckout.ErrUnsupportedPayload) {
		t.Fatalf("Split(nil) error = %v, want ErrUnsupportedPayload", err)
	}
}

func TestProfile_Seal_DeniedByAuthority(t *testing.T) {
	iv := seedVerifier(t, denySeed)
	signer, _ := newTestSigner(t)

	payload := testPayload()
	payload.Intent.IntentRef = "intent:profile-test-deny"
	// currency BRL fails the deny-seed's "equals USD" rule.

	var profile agenticcheckout.Profile
	segments, err := profile.Split(payload)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	projection, err := profile.Project(payload)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}

	audiences := []chainbind.Audience{
		newAudienceKeys(t, agenticcheckout.AudienceUser).aud,
		newAudienceKeys(t, agenticcheckout.AudienceMerchant).aud,
		newAudienceKeys(t, agenticcheckout.AudienceGateway).aud,
	}

	req := chainbind.SealRequest{
		Segments:     segments,
		SegmentOrder: agenticcheckout.SegmentOrder(),
		Audiences:    audiences,
		IntentRef:    payload.Intent.IntentRef,
		Authority:    payload.Intent.Authority,
		Projection:   projection,
		Issuer:       "agenticcheckout-test",
		IssuedAt:     time.Now().UTC(),
		TenantID:     payload.RequestContext.TenantID,
		Environment:  payload.RequestContext.Environment,
		Profile:      agenticcheckout.Name,
		BindingSpecs: agenticcheckout.BindingSpecs(),
	}

	_, err = chainbind.Seal(context.Background(), req, signer, x25519.Wrapper{}, iv)
	if !errors.Is(err, chainbind.ErrIntentDenied) {
		t.Fatalf("Seal error = %v, want ErrIntentDenied", err)
	}
}
