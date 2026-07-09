package chainbind_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/danielmalka/chainbind-go/internal/adapters/intent/mock"
	"github.com/danielmalka/chainbind-go/internal/adapters/keywrap/x25519"
	"github.com/danielmalka/chainbind-go/internal/adapters/signer/local"
	"github.com/danielmalka/chainbind-go/pkg/chainbind"
	"github.com/danielmalka/chainbind-go/pkg/chainbind/profile/agenticcheckout"
)

// updateGolden regenerates testdata/package-v1.golden.json when set:
//
//	go test ./pkg/chainbind/ -run TestGolden -update
//
// Re-sealing never reproduces the committed bytes (package_id, the GCM
// nonce and every epk are fresh per call — Design decision A), so -update
// is the only way to produce the file; the committed copy is what every
// other run of TestGolden_* is checked against.
var updateGolden = flag.Bool("update", false, "regenerate testdata/package-v1.golden.json")

// goldenFixturePath is relative to this package's directory (pkg/chainbind),
// matching seal_test.go's seedDir convention: "../.." reaches the repo root,
// where testdata/ lives.
const goldenFixturePath = "../../testdata/package-v1.golden.json"

// The key material below protects nothing. It was generated once with
// crypto/rand in a throwaway program (never committed) to produce this
// fixture, and is committed here in plain hex so the golden package can be
// both verified (the issuer public key derives from the seed) and opened
// (the three X25519 private keys unwrap the three committed segments).
// Treat every constant in this block as public: it exists only so
// TestGolden_StillOpensWithCommittedKeys and TestGolden_WireFormatIsPinned
// have something to check the committed fixture against, forever, even
// after the code that produced it changes.
//
// Each constant carries a per-line `gitleaks:allow`, and each one is
// load-bearing: delete it and the pre-commit hook fails with four
// generic-api-key findings. That is only true because these names contain
// the word "Key". gitleaks' generic-api-key rule is keyword-driven — it
// fires on `key`, `secret`, `token` near a high-entropy string, not on the
// entropy alone. Named `goldenUserPrivHex`, the very same 32 bytes are
// invisible to it.
//
// So the scanner is not what keeps private keys out of this public
// repository, and nobody should believe it is. It reads names. Review reads
// code. The names here are chosen to be seen.
const (
	// goldenIssuerSigningKeyHex is the 32-byte Ed25519 seed behind the golden
	// package's signature. ed25519.NewKeyFromSeed derives the private key;
	// .Public() derives the public key Verify is given to trust.
	goldenIssuerSigningKeyHex = "2815ff87aac6039beff58bc3b83766ab31b8b7edbe906dcd5abb6052314ecb4a" // gitleaks:allow throwaway fixture key, generated once for testdata/package-v1.golden.json, protects nothing

	// goldenUserPrivateKeyHex, goldenMerchantPrivateKeyHex and goldenGatewayPrivateKeyHex are
	// the three X25519 recipient private keys the golden package's
	// segments are sealed to, one per agentic-checkout/v1 audience.
	goldenUserPrivateKeyHex     = "21ff8d69fa3d5c48739528c9e916f8ce2f4ba7fb370ddaa0ba5a8a22c44f9ae7" // gitleaks:allow throwaway fixture key, generated once for testdata/package-v1.golden.json, protects nothing
	goldenMerchantPrivateKeyHex = "0ca57fb57128b9aaf9586eaef99c7d4a45ec45a1a577012041745d1dd0132366" // gitleaks:allow throwaway fixture key, generated once for testdata/package-v1.golden.json, protects nothing
	goldenGatewayPrivateKeyHex  = "77115bc2acc19998371fad761b286217a366f31396c8dab30c5fd3ad24d9a335" // gitleaks:allow throwaway fixture key, generated once for testdata/package-v1.golden.json, protects nothing
)

// goldenIntentRef is a fixed authorization the in-memory mock authority
// below always allows, so regeneration under -update never depends on the
// shared testdata/authorizations fixtures changing out from under it.
const goldenIntentRef = "intent:golden-fixture"

// goldenSeedDoc is the one seed document goldenIntentVerifier loads. Its
// rule accepts exactly the projection agenticcheckout.Profile.Project
// computes for goldenPayload (below): currency BRL, amount 1000, merchant
// mer_golden_001.
const goldenSeedDoc = `{"ref":"intent:golden-fixture","version":1,"rules":{"currency":{"equals":["BRL"]},"amount":{"max":1000000},"merchant_id":{"equals":["mer_golden_001"]}}}`

// goldenIssuerKey derives the Ed25519 keypair the golden package was signed
// with.
func goldenIssuerKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	seed, err := hex.DecodeString(goldenIssuerSigningKeyHex)
	if err != nil {
		t.Fatalf("decode golden issuer seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("issuer private key's Public() did not return an ed25519.PublicKey")
	}
	return pub, priv
}

// goldenAudienceKeys derives the fixed audience set the golden package is
// sealed to: one X25519 keypair per agentic-checkout/v1 audience.
func goldenAudienceKeys(t *testing.T) map[string][]byte {
	t.Helper()
	hexKeys := map[string]string{
		agenticcheckout.AudienceUser:     goldenUserPrivateKeyHex,
		agenticcheckout.AudienceMerchant: goldenMerchantPrivateKeyHex,
		agenticcheckout.AudienceGateway:  goldenGatewayPrivateKeyHex,
	}
	privs := make(map[string][]byte, len(hexKeys))
	for name, h := range hexKeys {
		priv, err := hex.DecodeString(h)
		if err != nil {
			t.Fatalf("decode golden %s priv: %v", name, err)
		}
		privs[name] = priv
	}
	return privs
}

// goldenPayload is the fixed agentic-checkout/v1 payload the golden package
// was sealed from.
func goldenPayload() agenticcheckout.Payload {
	return agenticcheckout.Payload{
		RequestContext: agenticcheckout.RequestContext{
			TenantID:      "golden-tenant",
			Environment:   "golden-env",
			RequestID:     "req-golden-1",
			CorrelationID: "corr-golden-1",
			IssuedBy:      "golden-fixture-generator",
		},
		Intent: agenticcheckout.Intent{
			IntentRef: goldenIntentRef,
			Authority: "https://intent-authority.local/v1",
		},
		Subject: agenticcheckout.Subject{
			UserID:        "usr_golden_1",
			AccountID:     "acc_golden_1",
			Name:          "Golden User",
			Email:         "golden@example.com",
			Roles:         []string{"role_user"},
			Permissions:   []string{"checkout:create"},
			AccountStatus: "active",
		},
		Checkout: agenticcheckout.Checkout{
			CheckoutID:   "chk_golden_1",
			MerchantID:   "mer_golden_001",
			MerchantName: "Golden Store",
			Currency:     "BRL",
			Items: []agenticcheckout.Item{
				{SKU: "SKU-GOLDEN-1", Name: "Golden Widget", Quantity: 1, UnitPrice: 1000},
			},
			Subtotal: 1000,
			Shipping: 0,
			Discount: 0,
			Total:    1000,
		},
		Payment: agenticcheckout.Payment{
			PaymentID:         "pay_golden_1",
			PaymentMethod:     "pix",
			BankAccountMasked: "***4321",
			BankCode:          "001",
			PaymentReference:  "pix-golden-1",
			TransactionStatus: "pending",
			Amount:            1000,
		},
	}
}

// regenerateGolden seals goldenPayload with the fixed keys above and writes
// the result to goldenFixturePath (0o600), for -update runs only.
func regenerateGolden(t *testing.T, path string) {
	t.Helper()

	dir := t.TempDir()
	seedPath := filepath.Join(dir, "golden.json")
	if err := os.WriteFile(seedPath, []byte(goldenSeedDoc), 0o600); err != nil {
		t.Fatalf("write golden seed doc: %v", err)
	}
	iv, err := mock.New(dir)
	if err != nil {
		t.Fatalf("mock.New: %v", err)
	}

	_, priv := goldenIssuerKey(t)
	signer, err := local.New(priv, "issuer-signing-key-1")
	if err != nil {
		t.Fatalf("local.New: %v", err)
	}

	var profile agenticcheckout.Profile
	payload := goldenPayload()
	segments, err := profile.Split(payload)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	projection, err := profile.Project(payload)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}

	audPrivs := goldenAudienceKeys(t)
	audiences := make([]chainbind.Audience, 0, len(audPrivs))
	for _, name := range agenticcheckout.SegmentOrder() {
		pub, err := x25519.Wrapper{}.PublicKey(audPrivs[name])
		if err != nil {
			t.Fatalf("derive public key for %q: %v", name, err)
		}
		audiences = append(audiences, chainbind.Audience{Name: name, PublicKey: pub, Kid: name + "-key-1"})
	}

	req := chainbind.SealRequest{
		Segments:     segments,
		SegmentOrder: agenticcheckout.SegmentOrder(),
		Audiences:    audiences,
		IntentRef:    payload.Intent.IntentRef,
		Authority:    payload.Intent.Authority,
		Projection:   projection,
		Issuer:       "chainbind-go",
		IssuedAt:     time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC),
		TenantID:     payload.RequestContext.TenantID,
		Environment:  payload.RequestContext.Environment,
		Profile:      agenticcheckout.Name,
		BindingSpecs: agenticcheckout.BindingSpecs(),
	}

	p, err := chainbind.Seal(context.Background(), req, signer, x25519.Wrapper{}, iv)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		t.Fatalf("marshal golden package: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write golden fixture: %v", err)
	}
}

// wantTopLevelKeys, wantIssuerKeys, ... name the exact field sets the golden
// wire format must carry — taken from package.go's json tags and
// testdata/package-example-v1.json. A renamed, added or removed field
// changes one of these sets and fails the test, which is the entire point
// of pinning a spec_version.
var (
	wantTopLevelKeys = []string{
		"bindings", "cnf", "intent", "issued_at", "issuer", "manifest",
		"package_id", "profile", "segments", "signature", "spec_version",
	}
	wantIssuerKeys      = []string{"iss", "kid"}
	wantIntentKeys      = []string{"authority", "constraints_hash", "intent_ref"}
	wantSignatureKeys   = []string{"alg", "kid", "signed_fields", "value"}
	wantBindingsKeys    = []string{"checkout_hash", "conditional_transaction_id", "intent_commitment", "segments_root", "transaction_id"}
	wantManifestKeys    = []string{"aad_context", "canonicalization", "disclosures", "hash_alg", "schema", "segment_order", "segments"}
	wantManifestSegKeys = []string{"alg", "audience", "cipher_hash", "kid", "plain_hash", "wrap_alg"}
	wantSegmentKeys     = []string{"ciphertext", "dek_wrapped", "epk", "nonce", "tag"}
	wantCNFEntryKeys    = []string{"jkt", "kid", "method"}

	// The two nested objects below need their own key sets, and epk needs
	// one most of all: it is not covered by the issuer signature. The
	// signing view spans nine fields, and segments is not among them —
	// ciphertexts are covered transitively through
	// manifest.segments[a].cipher_hash, which hashes ciphertext‖tag and
	// nothing else. So a field added to epk changes no signed byte. Without
	// this assertion, adding one and regenerating with -update produces a
	// validly signed package of a different wire shape, and the test that
	// exists to pin the wire shape says nothing.
	wantEPKKeys        = []string{"crv", "kty", "x"}
	wantAADContextKeys = []string{"environment", "package_id", "tenant_id"}

	wantB64URLNoPad = "no base64url field may decode from a string containing '=', '+' or '/'"
)

// sortedKeys returns m's keys as a sorted slice, for order-independent
// key-set comparison.
func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// assertKeySet fails t unless got (as a sorted slice) equals want exactly:
// this catches both a removed and an added field, unlike a subset check.
func assertKeySet(t *testing.T, label string, m map[string]any, want []string) {
	t.Helper()
	got := sortedKeys(m)
	wantSorted := append([]string(nil), want...)
	sort.Strings(wantSorted)
	if len(got) != len(wantSorted) {
		t.Fatalf("%s keys = %v, want %v", label, got, wantSorted)
	}
	for i := range got {
		if got[i] != wantSorted[i] {
			t.Fatalf("%s keys = %v, want %v", label, got, wantSorted)
		}
	}
}

// asObject type-asserts v as a JSON object, failing t with a clear message
// otherwise.
func asObject(t *testing.T, label string, v any) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("%s = %T, want a JSON object", label, v)
	}
	return m
}

// assertB64URLNoPad fails t unless s decodes with base64.RawURLEncoding and
// contains none of '=', '+', '/' — the padded/standard-alphabet characters
// unpadded base64url must never contain.
func assertB64URLNoPad(t *testing.T, label, s string) {
	t.Helper()
	if strings.ContainsAny(s, "=+/") {
		t.Fatalf("%s = %q: %s", label, s, wantB64URLNoPad)
	}
	if _, err := base64.RawURLEncoding.DecodeString(s); err != nil {
		t.Fatalf("%s = %q does not decode as base64.RawURLEncoding: %v", label, s, err)
	}
}

// TestGolden_WireFormatIsPinned asserts the committed
// testdata/package-v1.golden.json still carries exactly the field set
// TECHSPEC-001 §6 defines, then verifies it with the derived issuer key.
//
// It unmarshals into map[string]any rather than chainbind.Package on
// purpose: unmarshalling straight into the struct would silently ignore a
// renamed or removed JSON field (encoding/json only fills the fields it
// recognises) — exactly the regression this test exists to catch. The
// generic map is what lets a missing or extra key fail loudly.
//
// Two distinct guards, and it is worth knowing which fires when. Rename a
// json tag in package.go and *do not* regenerate: the committed bytes still
// carry the old name, so the key-set assertions below still pass — but
// BuildSigningView now canonicalizes the new name, the reconstructed signing
// view no longer matches, and the signature check fails. Rename a tag and
// *do* regenerate with -update: the signature is valid over the new shape,
// and the hardcoded want-lists below are what refuse it. Neither guard alone
// covers both directions.
func TestGolden_WireFormatIsPinned(t *testing.T) {
	if *updateGolden {
		regenerateGolden(t, goldenFixturePath)
	}

	raw, err := os.ReadFile(goldenFixturePath)
	if err != nil {
		t.Fatalf("read %s: %v", goldenFixturePath, err)
	}

	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal golden fixture as map[string]any: %v", err)
	}

	assertKeySet(t, "top-level", generic, wantTopLevelKeys)
	assertKeySet(t, "issuer", asObject(t, "issuer", generic["issuer"]), wantIssuerKeys)
	assertKeySet(t, "intent", asObject(t, "intent", generic["intent"]), wantIntentKeys)
	assertKeySet(t, "signature", asObject(t, "signature", generic["signature"]), wantSignatureKeys)
	assertKeySet(t, "bindings", asObject(t, "bindings", generic["bindings"]), wantBindingsKeys)
	assertKeySet(t, "manifest", asObject(t, "manifest", generic["manifest"]), wantManifestKeys)

	// Every entry is checked, not just the first: Go's map iteration order is
	// randomized, so breaking after one entry would check an arbitrary one
	// and silently skip a divergence in the other two.
	manifest := asObject(t, "manifest", generic["manifest"])
	manifestSegments := asObject(t, "manifest.segments", manifest["segments"])
	for name, seg := range manifestSegments {
		assertKeySet(t, "manifest.segments["+name+"]", asObject(t, "manifest.segments["+name+"]", seg), wantManifestSegKeys)
	}

	assertKeySet(t, "manifest.aad_context", asObject(t, "manifest.aad_context", manifest["aad_context"]), wantAADContextKeys)

	segments := asObject(t, "segments", generic["segments"])
	for name, seg := range segments {
		segObj := asObject(t, "segments["+name+"]", seg)
		assertKeySet(t, "segments["+name+"]", segObj, wantSegmentKeys)
		assertKeySet(t, "segments["+name+"].epk", asObject(t, "segments["+name+"].epk", segObj["epk"]), wantEPKKeys)
	}

	cnf := asObject(t, "cnf", generic["cnf"])
	for name, entry := range cnf {
		assertKeySet(t, "cnf["+name+"]", asObject(t, "cnf["+name+"]", entry), wantCNFEntryKeys)
	}

	disclosures, ok := manifest["disclosures"].([]any)
	if !ok {
		t.Fatalf("manifest.disclosures = %T, want a JSON array (possibly empty)", manifest["disclosures"])
	}
	if len(disclosures) != 0 {
		t.Fatalf("manifest.disclosures = %v, want an empty array", disclosures)
	}
	// The above type assertion already rules out null and "absent" (a nil
	// map lookup would fail the assertion); this length check additionally
	// rules out a non-empty array smuggled in by accident.

	signature := asObject(t, "signature", generic["signature"])
	assertB64URLNoPad(t, "signature.value", signature["value"].(string))
	for name, seg := range segments {
		s := asObject(t, "segments["+name+"]", seg)
		assertB64URLNoPad(t, "segments["+name+"].dek_wrapped", s["dek_wrapped"].(string))
		assertB64URLNoPad(t, "segments["+name+"].nonce", s["nonce"].(string))
		assertB64URLNoPad(t, "segments["+name+"].ciphertext", s["ciphertext"].(string))
		assertB64URLNoPad(t, "segments["+name+"].tag", s["tag"].(string))
		epk := asObject(t, "segments["+name+"].epk", s["epk"])
		assertB64URLNoPad(t, "segments["+name+"].epk.x", epk["x"].(string))
	}

	signedFields, ok := signature["signed_fields"].([]any)
	if !ok {
		t.Fatalf("signature.signed_fields = %T, want a JSON array", signature["signed_fields"])
	}
	gotSignedFields := make([]string, 0, len(signedFields))
	for _, f := range signedFields {
		s, ok := f.(string)
		if !ok {
			t.Fatalf("signature.signed_fields contains non-string element %v", f)
		}
		gotSignedFields = append(gotSignedFields, s)
	}
	sort.Strings(gotSignedFields)
	wantSignedFields := append([]string(nil), chainbind.RequiredSignedFields...)
	sort.Strings(wantSignedFields)
	if len(gotSignedFields) != len(wantSignedFields) {
		t.Fatalf("signature.signed_fields = %v, want %v", gotSignedFields, wantSignedFields)
	}
	for i := range gotSignedFields {
		if gotSignedFields[i] != wantSignedFields[i] {
			t.Fatalf("signature.signed_fields = %v, want %v", gotSignedFields, wantSignedFields)
		}
	}

	specVersion, _ := generic["spec_version"].(string)
	if specVersion != chainbind.SupportedSpecVersion {
		t.Fatalf("spec_version = %q, want %q", specVersion, chainbind.SupportedSpecVersion)
	}

	// Now unmarshal into the real struct and verify it: the nine-field
	// signing view must still reconstruct against the derived issuer key,
	// every cipher_hash must still check out, segments_root must still
	// recompute, and every agentic-checkout/v1 binding must still recompute.
	var p chainbind.Package
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("unmarshal golden fixture as chainbind.Package: %v", err)
	}

	pub, _ := goldenIssuerKey(t)
	report, err := chainbind.Verify(context.Background(), &p, chainbind.VerifyOptions{
		IssuerKey:    func(string, string) (ed25519.PublicKey, bool) { return pub, true },
		BindingSpecs: agenticcheckout.BindingSpecs(),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !report.Level1() {
		t.Fatalf("Level1() = false for the golden package: %+v", report)
	}
	for name, ok := range report.CipherHashes {
		if !ok {
			t.Fatalf("CipherHashes[%q] = false for the golden package", name)
		}
	}
	if !report.SegmentsRoot {
		t.Fatal("SegmentsRoot = false for the golden package")
	}
	for name, ok := range report.ProfileBindings {
		if !ok {
			t.Fatalf("ProfileBindings[%q] = false for the golden package", name)
		}
	}
	if len(report.ProfileBindings) != 3 {
		t.Fatalf("got %d profile bindings, want 3", len(report.ProfileBindings))
	}
}

// TestGolden_StillOpensWithCommittedKeys is the backward-compatibility test:
// if a future change to the AAD formula, the Concat KDF, the A256KW wrap or
// plain_hash ever silently changes behavior, this is the test that fails,
// because it opens a package sealed under the *old* behavior with keys
// committed the day that behavior was pinned. Open runs entirely offline
// (architecture invariant 1), so VerifyOptions carries no Intent here.
func TestGolden_StillOpensWithCommittedKeys(t *testing.T) {
	raw, err := os.ReadFile(goldenFixturePath)
	if err != nil {
		t.Fatalf("read %s: %v", goldenFixturePath, err)
	}
	var p chainbind.Package
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("unmarshal golden fixture: %v", err)
	}

	pub, _ := goldenIssuerKey(t)
	opt := chainbind.VerifyOptions{
		IssuerKey:    func(string, string) (ed25519.PublicKey, bool) { return pub, true },
		BindingSpecs: agenticcheckout.BindingSpecs(),
	}

	wantPlain, err := (agenticcheckout.Profile{}).Split(goldenPayload())
	if err != nil {
		t.Fatalf("Split: %v", err)
	}

	audPrivs := goldenAudienceKeys(t)
	for _, name := range agenticcheckout.SegmentOrder() {
		gotName, gotPlain, err := chainbind.Open(context.Background(), &p, audPrivs[name], x25519.Wrapper{}, opt)
		if err != nil {
			t.Fatalf("Open(%q): %v", name, err)
		}
		if gotName != name {
			t.Fatalf("Open(%q's key) returned audience %q", name, gotName)
		}
		if !bytes.Equal(gotPlain, wantPlain[name]) {
			t.Fatalf("Open(%q) plaintext = %s, want %s", name, gotPlain, wantPlain[name])
		}
	}
}
