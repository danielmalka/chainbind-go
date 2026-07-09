package chainbind_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/danielmalka/chainbind-go/internal/adapters/keywrap/x25519"
	"github.com/danielmalka/chainbind-go/internal/adapters/signer/local"
	"github.com/danielmalka/chainbind-go/pkg/chainbind"
)

// newIssuerKeypair returns a fresh Ed25519 keypair and a Signer wrapping its
// private half, so a test can both seal a package and later assert what a
// verifier resolving that exact public key would see.
func newIssuerKeypair(t *testing.T) (ed25519.PublicKey, *local.Signer) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	signer, err := local.New(priv, "test-issuer-key-1")
	if err != nil {
		t.Fatalf("local.New: %v", err)
	}
	return pub, signer
}

// sealTestPackage seals a package for the given audiences with a
// fresh, test-owned issuer keypair and returns both the package and the
// issuer's public key, for tests that need to build a VerifyOptions that
// trusts exactly that key.
func sealTestPackage(t *testing.T, audiences ...chainbind.Audience) (*chainbind.Package, ed25519.PublicKey) {
	t.Helper()
	pub, signer := newIssuerKeypair(t)
	req := baseSealRequest(audiences...)
	p, err := chainbind.Seal(context.Background(), req, signer, x25519.Wrapper{}, newTestVerifier(t))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return p, pub
}

// verifyOpts builds VerifyOptions that trust exactly pub for any claimed
// iss/kid, backed by iv for the intent level.
func verifyOpts(pub ed25519.PublicKey, iv chainbind.IntentVerifier) chainbind.VerifyOptions {
	return chainbind.VerifyOptions{
		IssuerKey: func(string, string) (ed25519.PublicKey, bool) { return pub, true },
		Intent:    iv,
	}
}

// resign rebuilds the signing view over p's current content and overwrites
// p.Signature.Value with a fresh signature from signer. It is what a
// malicious issuer who controls the signing key — but not the intent
// authority — can legitimately do: change signed content, then re-sign it.
func resign(t *testing.T, signer *local.Signer, p *chainbind.Package) {
	t.Helper()
	view, err := chainbind.BuildSigningView(*p)
	if err != nil {
		t.Fatalf("BuildSigningView: %v", err)
	}
	sig, err := signer.Sign(context.Background(), view)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	p.Signature.Value = chainbind.EncodeSignatureValue(sig)
}

// flipCiphertext flips the first byte of the named audience's ciphertext,
// leaving the signed manifest untouched — the shape of a tampered payload
// that never reaches the plaintext.
func flipCiphertext(t *testing.T, p *chainbind.Package, name string) {
	t.Helper()
	sealed := p.Segments[name]
	ct, err := base64.RawURLEncoding.DecodeString(sealed.Ciphertext)
	if err != nil {
		t.Fatalf("decode ciphertext for %q: %v", name, err)
	}
	ct = bytes.Clone(ct)
	ct[0] ^= 0xFF
	sealed.Ciphertext = base64.RawURLEncoding.EncodeToString(ct)
	p.Segments[name] = sealed
}

// wrongHashVerifier wraps a real IntentVerifier but answers
// ConstraintsHash with a fixed value that never matches what any real seal
// embedded, simulating an authority whose authoritative value diverges from
// the package's claim.
type wrongHashVerifier struct {
	inner chainbind.IntentVerifier
}

func (w wrongHashVerifier) Check(ctx context.Context, intentRef string, projection any) (chainbind.IntentDecision, error) {
	return w.inner.Check(ctx, intentRef, projection)
}

func (wrongHashVerifier) ConstraintsHash(context.Context, string) (string, error) {
	return "sha256:" + strings.Repeat("1", 64), nil
}

// unreachableVerifier simulates an intent authority that cannot be reached:
// every call returns an error, never a decision.
type unreachableVerifier struct{}

func (unreachableVerifier) Check(context.Context, string, any) (chainbind.IntentDecision, error) {
	return chainbind.IntentDecision{}, errors.New("verify_test: authority unreachable")
}

func (unreachableVerifier) ConstraintsHash(context.Context, string) (string, error) {
	return "", errors.New("verify_test: authority unreachable")
}

func TestVerify_RejectsUnknownSpecVersion(t *testing.T) {
	aud, _ := newTestAudience(t, "alpha")
	p, pub := sealTestPackage(t, aud)
	p.SpecVersion = "9.9.9"

	report, err := chainbind.Verify(context.Background(), p, verifyOpts(pub, newTestVerifier(t)))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.SpecVersionSupported {
		t.Fatal("SpecVersionSupported = true for an unrecognised spec_version")
	}
	if report.OK() {
		t.Fatal("OK() = true for an unrecognised spec_version")
	}
}

func TestVerify_FlippedCiphertextByte_ReportsCipherHashInvalid(t *testing.T) {
	aud, _ := newTestAudience(t, "alpha")
	p, pub := sealTestPackage(t, aud)

	flipCiphertext(t, p, "alpha")

	report, err := chainbind.Verify(context.Background(), p, verifyOpts(pub, newTestVerifier(t)))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !report.Signature {
		t.Fatal("Signature = false: segments are not part of the signing view, flipping a ciphertext byte must not break it")
	}
	if report.CipherHashes["alpha"] {
		t.Fatal("CipherHashes[\"alpha\"] = true for a flipped ciphertext byte")
	}
	if report.OK() {
		t.Fatal("OK() = true with an invalid cipher hash")
	}
}

func TestVerify_MutatedManifest_ReportsSignatureInvalid(t *testing.T) {
	aud, _ := newTestAudience(t, "alpha")
	p, pub := sealTestPackage(t, aud)

	seg := p.Manifest.Segments["alpha"]
	seg.PlainHash = "sha256:" + strings.Repeat("0", 64)
	p.Manifest.Segments["alpha"] = seg

	report, err := chainbind.Verify(context.Background(), p, verifyOpts(pub, newTestVerifier(t)))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.Signature {
		t.Fatal("Signature = true after the signed manifest was mutated")
	}
	if report.CipherHashes != nil {
		t.Fatalf("CipherHashes = %v, want nil after an L1.2 abort", report.CipherHashes)
	}
	if report.OK() {
		t.Fatal("OK() = true with an invalid signature")
	}
}

func TestVerify_RequiresNoKeys(t *testing.T) {
	// VerifyOptions must carry no field capable of holding a private key
	// or a decryption capability — only a public-key resolver, an intent
	// authority, and profile binding specs.
	typ := reflect.TypeOf(chainbind.VerifyOptions{})
	allowed := map[string]bool{"IssuerKey": true, "Intent": true, "BindingSpecs": true}
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if !allowed[name] {
			t.Fatalf("VerifyOptions has unexpected field %q — Verify must require no private key material", name)
		}
	}

	aud, _ := newTestAudience(t, "alpha")
	p, pub := sealTestPackage(t, aud)

	report, err := chainbind.Verify(context.Background(), p, verifyOpts(pub, newTestVerifier(t)))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !report.OK() {
		t.Fatalf("report not OK for a validly sealed package, verified with only a public key: %+v", report)
	}
}

func TestVerify_BadSignature_DoesNotEvaluateLaterChecks(t *testing.T) {
	aud, _ := newTestAudience(t, "alpha")
	p, pub := sealTestPackage(t, aud)

	p.Bindings.SegmentsRoot = "sha256:" + strings.Repeat("0", 64)

	report, err := chainbind.Verify(context.Background(), p, verifyOpts(pub, newTestVerifier(t)))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.Signature {
		t.Fatal("Signature = true after bindings was mutated")
	}
	if report.CipherHashes != nil {
		t.Fatalf("CipherHashes = %v, want nil after an L1.2 abort", report.CipherHashes)
	}
	if report.SegmentsRoot {
		t.Fatal("SegmentsRoot = true after an L1.2 abort")
	}
	if report.ProfileBindings != nil {
		t.Fatalf("ProfileBindings = %v, want nil after an L1.2 abort", report.ProfileBindings)
	}
	if report.Intent.Evaluated {
		t.Fatal("Intent.Evaluated = true after an L1.2 abort")
	}
}

func TestVerify_TwoBrokenSegments_ReportsBoth(t *testing.T) {
	audA, _ := newTestAudience(t, "alpha")
	audB, _ := newTestAudience(t, "bravo")
	p, pub := sealTestPackage(t, audA, audB)

	flipCiphertext(t, p, "alpha")
	flipCiphertext(t, p, "bravo")

	report, err := chainbind.Verify(context.Background(), p, verifyOpts(pub, newTestVerifier(t)))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !report.Signature {
		t.Fatal("Signature = false: nothing in the signed view was touched")
	}
	if report.CipherHashes["alpha"] {
		t.Fatal("CipherHashes[\"alpha\"] = true for a flipped ciphertext byte")
	}
	if report.CipherHashes["bravo"] {
		t.Fatal("CipherHashes[\"bravo\"] = true for a flipped ciphertext byte")
	}
	if !report.SegmentsRoot {
		t.Fatal("SegmentsRoot = false: plain_hash was never touched, only ciphertext")
	}
}

func TestVerify_SplicedSegment_CaughtByCipherHash_WithoutAAD(t *testing.T) {
	audA, _ := newTestAudience(t, "alpha")
	pkgA, _ := sealTestPackage(t, audA)

	audB, _ := newTestAudience(t, "alpha")
	pkgB, pubB := sealTestPackage(t, audB)

	// Splice A's sealed segment into B, under the same audience name so B
	// stays structurally well-formed. B's signed manifest — including
	// cipher_hash["alpha"] — is untouched.
	pkgB.Segments["alpha"] = pkgA.Segments["alpha"]

	report, err := chainbind.Verify(context.Background(), pkgB, verifyOpts(pubB, newTestVerifier(t)))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !report.Signature {
		t.Fatal("Signature = false: manifest and bindings were never touched")
	}
	if report.CipherHashes["alpha"] {
		t.Fatal("CipherHashes[\"alpha\"] = true for a spliced segment — Level 1 must catch this via cipher_hash, with no key material at all")
	}
	if report.OK() {
		t.Fatal("OK() = true for a package carrying a spliced segment")
	}
}

func TestReport_OK_FalseWhenIntentNotEvaluated(t *testing.T) {
	r := &chainbind.Report{
		SpecVersionSupported: true,
		Signature:            true,
		AADContextConsistent: true,
		CipherHashes:         map[string]bool{"alpha": true},
		SegmentsRoot:         true,
		// Intent left at its zero value: Evaluated == false.
	}
	if r.OK() {
		t.Fatal("OK() = true despite Intent.Evaluated == false")
	}
}

func TestVerify_AuthorityUnreachable_Indeterminate_NotVerified(t *testing.T) {
	aud, _ := newTestAudience(t, "alpha")
	p, pub := sealTestPackage(t, aud)

	t.Run("nil intent verifier", func(t *testing.T) {
		report, err := chainbind.Verify(context.Background(), p, chainbind.VerifyOptions{
			IssuerKey: func(string, string) (ed25519.PublicKey, bool) { return pub, true },
			Intent:    nil,
		})
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if report.Intent.Evaluated {
			t.Fatal("Intent.Evaluated = true with no authority configured")
		}
		if report.Intent.Valid {
			t.Fatal("Intent.Valid = true with no authority configured")
		}
		if report.OK() {
			t.Fatal("OK() = true with no authority configured")
		}
	})

	t.Run("authority returns an error", func(t *testing.T) {
		report, err := chainbind.Verify(context.Background(), p, verifyOpts(pub, unreachableVerifier{}))
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if report.Intent.Evaluated {
			t.Fatal("Intent.Evaluated = true when the authority returned an error")
		}
		if report.OK() {
			t.Fatal("OK() = true when the authority was unreachable")
		}
	})
}

func TestVerify_ConstraintsHashMismatch_IntentInvalid(t *testing.T) {
	aud, _ := newTestAudience(t, "alpha")
	p, pub := sealTestPackage(t, aud)

	report, err := chainbind.Verify(context.Background(), p, verifyOpts(pub, wrongHashVerifier{inner: newTestVerifier(t)}))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !report.Intent.Evaluated {
		t.Fatal("Intent.Evaluated = false: the authority was reached and answered")
	}
	if report.Intent.Valid {
		t.Fatal("Intent.Valid = true despite a constraints_hash mismatch")
	}
	if report.OK() {
		t.Fatal("OK() = true with a constraints_hash mismatch")
	}
}

func TestVerify_SignedFieldsMissingName_Rejected(t *testing.T) {
	aud, _ := newTestAudience(t, "alpha")
	p, pub := sealTestPackage(t, aud)

	trimmed := make([]string, 0, len(p.Signature.SignedFields)-1)
	for _, n := range p.Signature.SignedFields {
		if n != "bindings" {
			trimmed = append(trimmed, n)
		}
	}
	p.Signature.SignedFields = trimmed

	report, err := chainbind.Verify(context.Background(), p, verifyOpts(pub, newTestVerifier(t)))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.Signature {
		t.Fatal("Signature = true with \"bindings\" missing from signed_fields")
	}
	if report.OK() {
		t.Fatal("OK() = true with a malformed signed_fields")
	}
}

func TestVerify_SignedFieldsUnknownName_Rejected(t *testing.T) {
	aud, _ := newTestAudience(t, "alpha")
	p, pub := sealTestPackage(t, aud)

	extended := append(append([]string{}, p.Signature.SignedFields...), "segments")
	p.Signature.SignedFields = extended

	report, err := chainbind.Verify(context.Background(), p, verifyOpts(pub, newTestVerifier(t)))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.Signature {
		t.Fatal("Signature = true with an unrecognised name in signed_fields")
	}
	if report.OK() {
		t.Fatal("OK() = true with a malformed signed_fields")
	}
}

func TestVerify_MalformedIssuerKey_DoesNotPanic(t *testing.T) {
	aud, _ := newTestAudience(t, "alpha")
	p, _ := sealTestPackage(t, aud)

	opt := chainbind.VerifyOptions{
		IssuerKey: func(string, string) (ed25519.PublicKey, bool) {
			return make(ed25519.PublicKey, 10), true
		},
		Intent: newTestVerifier(t),
	}

	report, err := chainbind.Verify(context.Background(), p, opt)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.Signature {
		t.Fatal("Signature = true with a malformed (10-byte) issuer public key")
	}
}

func TestVerify_IssuerKeyNotTrusted_SignatureFalse(t *testing.T) {
	aud, _ := newTestAudience(t, "alpha")
	p, _ := sealTestPackage(t, aud)

	opt := chainbind.VerifyOptions{
		IssuerKey: func(string, string) (ed25519.PublicKey, bool) { return nil, false },
		Intent:    newTestVerifier(t),
	}

	report, err := chainbind.Verify(context.Background(), p, opt)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.Signature {
		t.Fatal("Signature = true when IssuerKey reported the key as untrusted")
	}
	if report.CipherHashes != nil {
		t.Fatalf("CipherHashes = %v, want nil after an L1.2 abort", report.CipherHashes)
	}
}

// TestVerify_ForgedPackageWithIssuerOwnConstraintsHash_IntentInvalid is the
// test that matters most in this file. A malicious issuer who controls the
// signing key rewrites intent.constraints_hash, recomputes
// bindings.intent_commitment from that forged value so the package is
// internally perfectly consistent, and re-signs. Level 1 must pass
// completely — signature valid, every hash valid, the commitment
// self-consistent. Level 2 must still reject it, because recomputing
// intent_commitment from the authority's constraints_hash (never the
// package's claim) makes the forged pairing detectable regardless.
func TestVerify_ForgedPackageWithIssuerOwnConstraintsHash_IntentInvalid(t *testing.T) {
	aud, _ := newTestAudience(t, "alpha")
	pub, signer := newIssuerKeypair(t)
	req := baseSealRequest(aud)

	p, err := chainbind.Seal(context.Background(), req, signer, x25519.Wrapper{}, newTestVerifier(t))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	forgedHash := "sha256:" + strings.Repeat("f", 64)
	p.Intent.ConstraintsHash = forgedHash

	commitment, err := chainbind.IntentCommitment(p.Intent.IntentRef, forgedHash, p.Bindings.SegmentsRoot)
	if err != nil {
		t.Fatalf("IntentCommitment: %v", err)
	}
	p.Bindings.IntentCommitment = commitment

	resign(t, signer, p)

	report, err := chainbind.Verify(context.Background(), p, verifyOpts(pub, newTestVerifier(t)))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if !report.Signature {
		t.Fatal("Signature = false: the forged package was correctly re-signed by its own issuer key")
	}
	if !report.SegmentsRoot {
		t.Fatal("SegmentsRoot = false: unrelated to the forged intent fields")
	}
	if !report.Intent.Evaluated {
		t.Fatal("Intent.Evaluated = false: the authority was reached and answered")
	}
	if report.Intent.Valid {
		t.Fatal("Intent.Valid = true for a forged constraints_hash/commitment pair — Verify must be recomputing intent_commitment from the embedded constraints_hash instead of the authority's, which is the one bug this project exists to prevent")
	}
	if report.OK() {
		t.Fatal("OK() = true for a forged package")
	}
}

// TestVerify_OnlyL23RejectsThis pins L2.3 in isolation. The issuer forges the
// embedded constraints_hash but leaves intent_commitment computed from the
// authority's real value. L2.4 recomputes the commitment from the authority's
// hash and finds it matching, so L2.4 alone would pass this package. Only the
// direct comparison of L2.3 catches it — which is exactly what PRD Story 3
// AC-8 requires: the authority's constraints_hash differing from the embedded
// one is itself the failure, regardless of whether the commitment agrees.
//
// Without this test, L2.3 could be deleted as "redundant" and the suite would
// stay green.
func TestVerify_OnlyL23RejectsThis(t *testing.T) {
	aud, _ := newTestAudience(t, "alpha")
	pub, signer := newIssuerKeypair(t)
	req := baseSealRequest(aud)

	p, err := chainbind.Seal(context.Background(), req, signer, x25519.Wrapper{}, newTestVerifier(t))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// The commitment stays as Seal computed it, from the authority's true
	// constraints_hash. Only the embedded claim is rewritten.
	p.Intent.ConstraintsHash = "sha256:" + strings.Repeat("a", 64)
	resign(t, signer, p)

	report, err := chainbind.Verify(context.Background(), p, verifyOpts(pub, newTestVerifier(t)))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !report.Signature {
		t.Fatal("Signature = false: the package was re-signed by its own issuer key")
	}
	if !report.Intent.Evaluated {
		t.Fatal("Intent.Evaluated = false: the authority was reachable")
	}
	if report.Intent.Valid {
		t.Fatal("Intent.Valid = true: an embedded constraints_hash that disagrees with the authority must be invalid (Story 3 AC-8)")
	}
	if report.OK() {
		t.Fatal("OK() = true for a package whose embedded constraints_hash the authority does not confirm")
	}
}

// TestVerify_OnlyL24RejectsThis pins L2.4 in isolation. The embedded
// constraints_hash agrees with the authority, so L2.3 passes. But the
// commitment was computed over a different intent_ref, so it does not bind
// this authorization to these segments. Only recomputing the commitment
// catches it.
//
// Without this test, L2.4 could be deleted as "redundant" and the suite would
// stay green. Together with TestVerify_OnlyL23RejectsThis, the two checks are
// pinned independently rather than covering for each other.
func TestVerify_OnlyL24RejectsThis(t *testing.T) {
	aud, _ := newTestAudience(t, "alpha")
	pub, signer := newIssuerKeypair(t)
	req := baseSealRequest(aud)

	p, err := chainbind.Seal(context.Background(), req, signer, x25519.Wrapper{}, newTestVerifier(t))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// constraints_hash is left exactly as the authority attests it. The
	// commitment is recomputed over a *different* intent_ref, so it commits
	// to a pairing that never existed.
	bogus, err := chainbind.IntentCommitment("intent:some-other-authorization", p.Intent.ConstraintsHash, p.Bindings.SegmentsRoot)
	if err != nil {
		t.Fatalf("IntentCommitment: %v", err)
	}
	p.Bindings.IntentCommitment = bogus
	resign(t, signer, p)

	report, err := chainbind.Verify(context.Background(), p, verifyOpts(pub, newTestVerifier(t)))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !report.Signature {
		t.Fatal("Signature = false: the package was re-signed by its own issuer key")
	}
	if !report.Intent.Evaluated {
		t.Fatal("Intent.Evaluated = false: the authority was reachable")
	}
	if report.Intent.Valid {
		t.Fatal("Intent.Valid = true: a commitment that does not bind this intent_ref to these segments must be invalid")
	}
	if report.OK() {
		t.Fatal("OK() = true for a package whose intent_commitment binds nothing")
	}
}

// TestVerify_NilIssuerKeyResolver_SignatureFalse closes the gap between a nil
// interface and a nil func. VerifyOptions.IssuerKey is a func value: leaving
// it unset is not a compile error and not a nil interface, so a careless
// implementation dereferences it and panics, or worse, treats "no resolver"
// as "nothing to check". A verifier with no trust store trusts nothing.
func TestVerify_NilIssuerKeyResolver_SignatureFalse(t *testing.T) {
	aud, _ := newTestAudience(t, "alpha")
	p, _ := sealTestPackage(t, aud)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Verify panicked with a nil IssuerKey resolver: %v", r)
		}
	}()

	report, err := chainbind.Verify(context.Background(), p, chainbind.VerifyOptions{
		Intent: newTestVerifier(t),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.Signature {
		t.Fatal("Signature = true with no issuer key resolver: a verifier with no trust store trusts nothing")
	}
	if report.CipherHashes != nil {
		t.Fatalf("CipherHashes = %v, want nil after an L1.2 abort", report.CipherHashes)
	}
	if report.OK() {
		t.Fatal("OK() = true with no issuer key resolver")
	}
}
