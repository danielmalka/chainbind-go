package chainbind_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/danielmalka/chainbind-go/internal/adapters/keywrap/x25519"
	"github.com/danielmalka/chainbind-go/internal/adapters/signer/local"
	"github.com/danielmalka/chainbind-go/pkg/chainbind"
)

// leakSentinel is a long, distinctive, high-entropy marker embedded in the
// test plaintext below. Its presence in any collected error string would
// mean a plaintext byte leaked into an error message.
const leakSentinel = "CHAINBIND-CONFORMANCE-LEAK-SENTINEL-DO-NOT-LEAK-ME"

// forbiddenSubstrings returns every representation (raw, hex, both base64
// alphabets) of each secret in secrets, plus the literal sentinel, as the
// full set of substrings no collected error string may contain.
func forbiddenSubstrings(sentinel string, secrets ...[]byte) []string {
	out := []string{sentinel}
	for _, s := range secrets {
		if len(s) == 0 {
			continue
		}
		out = append(
			out,
			string(s),
			hex.EncodeToString(s),
			base64.StdEncoding.EncodeToString(s),
			base64.RawURLEncoding.EncodeToString(s),
		)
	}
	return out
}

// TestErrors_NeverLeakSecrets drives every Seal, Verify and Open failure
// path this suite can reach and asserts that none of the resulting error
// strings contains any byte of the test's plaintext, its sentinel marker,
// a recipient private key, or the issuer's private seed — in any of raw,
// hex or base64 form (architecture invariant 10).
//
// Two mutations demonstrate this test is not vacuous, and both were run:
//
//   - Make Open's plain_hash mismatch return
//     fmt.Errorf("%w: recovered plaintext %s", ErrHashMismatch, plaintext).
//     The scan below catches the sentinel and fails.
//   - Delete Seal's duplicate-audience guard. mustErr fails, because a
//     failure path that stops failing stops being scanned — and a test that
//     scans nothing finds no secrets.
//
// The first mutation is what makes the second necessary: when this test was
// first written, its "plain_hash mismatch" case never reached Open's
// plain_hash check at all (see the comment at that case), so leaking the
// plaintext there changed nothing and the suite stayed green.
func TestErrors_NeverLeakSecrets(t *testing.T) {
	sentinelKey := make([]byte, 32)
	if _, err := cryptorand.Read(sentinelKey); err != nil {
		t.Fatalf("generate sentinel entropy: %v", err)
	}
	plaintext := []byte(hex.EncodeToString(sentinelKey) + ":" + leakSentinel)

	audPub, audPriv := genX25519Keypair(t)
	issuerPub, issuerPriv, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	issuerSigner, err := local.New(issuerPriv, "leak-test-issuer-key-1")
	if err != nil {
		t.Fatalf("local.New: %v", err)
	}

	iv := newTestVerifier(t)
	wrapper := x25519.Wrapper{}
	ctx := context.Background()

	var errs []string

	// mustErr records err's message and fails if the path did not error at
	// all. A plain "append if non-nil" collector would let this whole test
	// pass vacuously: a refactor that stops Seal from rejecting duplicate
	// audiences shrinks the collected set, and a test that scans zero error
	// strings for secrets finds no secrets. Every path named below must
	// actually fail, or the leak assertion is scanning nothing.
	mustErr := func(label string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s: expected an error, got nil — this failure path no longer fails, so it is no longer scanned for leaks", label)
		}
		errs = append(errs, err.Error())
	}

	// collectReport records a *Report's rendering. Verify answers a malformed
	// or unverifiable package with a report and a nil error, so these are not
	// failure paths in the mustErr sense — but the report is returned to the
	// caller and must not carry secrets either.
	collectReport := func(label string, r *chainbind.Report) {
		t.Helper()
		if r == nil {
			t.Fatalf("%s: expected a non-nil report", label)
		}
		errs = append(errs, fmt.Sprintf("%+v", r))
	}

	aud := chainbind.Audience{Name: "alpha", PublicKey: audPub, Kid: "alpha-key-1"}
	baseReq := func() chainbind.SealRequest {
		return chainbind.SealRequest{
			Segments:     map[string][]byte{"alpha": plaintext},
			SegmentOrder: []string{"alpha"},
			Audiences:    []chainbind.Audience{aud},
			IntentRef:    "intent:allow-example",
			Authority:    "https://intent-authority.local/v1",
			Projection:   map[string]any{"region": "us", "limit": 100},
			Issuer:       "leak-test",
			IssuedAt:     time.Now().UTC(),
			TenantID:     "leak-tenant",
			Environment:  "leak-env",
		}
	}

	// Seal failure paths.
	denied := baseReq()
	denied.IntentRef = "intent:deny-example"
	denied.Projection = map[string]any{"region": "eu"}
	_, err = chainbind.Seal(ctx, denied, issuerSigner, wrapper, iv)
	mustErr("Seal/intent denied", err)

	unreachable := baseReq()
	unreachable.IntentRef = "intent:does-not-exist"
	_, err = chainbind.Seal(ctx, unreachable, issuerSigner, wrapper, iv)
	mustErr("Seal/authority unreachable", err)

	missingSeg := baseReq()
	missingSeg.Segments = map[string][]byte{}
	_, err = chainbind.Seal(ctx, missingSeg, issuerSigner, wrapper, iv)
	mustErr("Seal/missing segment", err)

	dup := baseReq()
	dup.Audiences = []chainbind.Audience{aud, aud}
	_, err = chainbind.Seal(ctx, dup, issuerSigner, wrapper, iv)
	mustErr("Seal/duplicate audience", err)

	noAud := baseReq()
	noAud.Audiences = nil
	_, err = chainbind.Seal(ctx, noAud, issuerSigner, wrapper, iv)
	mustErr("Seal/no audiences", err)

	// A validly sealed package to drive Verify/Open failure paths against.
	p, err := chainbind.Seal(ctx, baseReq(), issuerSigner, wrapper, iv)
	if err != nil {
		t.Fatalf("Seal (base): %v", err)
	}

	opt := chainbind.VerifyOptions{
		IssuerKey: func(string, string) (ed25519.PublicKey, bool) { return issuerPub, true },
	}

	// Verify failure paths.
	_, err = chainbind.Verify(ctx, nil, opt)
	mustErr("Verify/nil package", err)

	unknownVersion := clonePackage(t, p)
	unknownVersion.SpecVersion = "9.9.9"
	report, err := chainbind.Verify(ctx, unknownVersion, opt)
	if err != nil {
		t.Fatalf("Verify/unknown spec_version returned an error, want a report: %v", err)
	}
	collectReport("Verify/unknown spec_version", report)

	emptyOrder := clonePackage(t, p)
	emptyOrder.Manifest.SegmentOrder = nil
	report, err = chainbind.Verify(ctx, emptyOrder, opt)
	if err != nil {
		t.Fatalf("Verify/empty segment_order returned an error, want a report: %v", err)
	}
	collectReport("Verify/empty segment_order", report)

	mutatedManifest := clonePackage(t, p)
	seg := mutatedManifest.Manifest.Segments["alpha"]
	seg.PlainHash = "sha256:" + strings.Repeat("0", 64)
	mutatedManifest.Manifest.Segments["alpha"] = seg
	report, err = chainbind.Verify(ctx, mutatedManifest, opt)
	if err != nil {
		t.Fatalf("Verify/mutated manifest returned an error, want a report: %v", err)
	}
	collectReport("Verify/mutated manifest (bad signature)", report)

	// Open failure paths.
	_, strangerPriv := genX25519Keypair(t)
	_, _, err = chainbind.Open(ctx, p, strangerPriv, wrapper, opt)
	mustErr("Open/key belonging to no audience", err)

	_, _, err = chainbind.Open(ctx, p, audPriv, wrapper, chainbind.VerifyOptions{
		IssuerKey: func(string, string) (ed25519.PublicKey, bool) { return nil, false },
	})
	mustErr("Open/untrusted issuer key", err)

	flipped := clonePackage(t, p)
	flipCiphertextAndReconcile(t, issuerSigner, flipped, "alpha")
	_, _, err = chainbind.Open(ctx, flipped, audPriv, wrapper, opt)
	mustErr("Open/flipped ciphertext byte", err)

	// Reaching Open's plain_hash check takes more than editing plain_hash:
	// segments_root is recomputed from the manifest's plain_hash values, so
	// editing one makes Level 1 fail and Open aborts long before it decrypts
	// anything. The only way in is the malicious-issuer shape — re-encrypt a
	// different plaintext under the same AAD, update cipher_hash to match,
	// leave plain_hash stale, re-sign — exactly as
	// TestOpen_PlainHashMismatch_Fails does. The substituted plaintext still
	// carries the sentinel, so an error that echoes the *recovered* plaintext
	// is caught here rather than slipping through.
	badPlainHash := clonePackage(t, p)
	substituted := append(bytes.Clone(plaintext), []byte(":substituted")...)
	reEncryptSegment(t, issuerSigner, badPlainHash, "alpha", audPriv, substituted)
	preOpen, err := chainbind.Verify(ctx, badPlainHash, opt)
	if err != nil {
		t.Fatalf("Verify(badPlainHash): %v", err)
	}
	if !preOpen.Level1() {
		t.Fatalf("Level1() = false; this case does not reach Open's plain_hash check: %+v", preOpen)
	}
	_, _, err = chainbind.Open(ctx, badPlainHash, audPriv, wrapper, opt)
	mustErr("Open/plain_hash mismatch", err)

	level1Broken := clonePackage(t, p)
	seg3 := level1Broken.Manifest.Segments["alpha"]
	seg3.PlainHash = "sha256:" + strings.Repeat("2", 64)
	level1Broken.Manifest.Segments["alpha"] = seg3
	_, _, err = chainbind.Open(ctx, level1Broken, audPriv, wrapper, opt)
	mustErr("Open/level 1 failure", err)

	// A floor on what was actually collected. Without it, deleting failure
	// paths above would quietly narrow this test's reach while it stayed
	// green.
	const wantCollected = 14
	if len(errs) != wantCollected {
		t.Fatalf("collected %d error/report strings, want %d — a failure path was added or removed without updating this floor", len(errs), wantCollected)
	}

	forbidden := forbiddenSubstrings(leakSentinel, plaintext, audPriv, issuerPriv.Seed())
	for _, e := range errs {
		for _, f := range forbidden {
			if f == "" {
				continue
			}
			if strings.Contains(e, f) {
				t.Fatalf("collected error/report %q contains forbidden secret material %q", e, f)
			}
		}
	}
}

// clonePackage round-trips p through Seal's own JSON encoding to produce an
// independent copy a test can mutate without disturbing other cases sharing
// the same sealed package.
func clonePackage(t *testing.T, p *chainbind.Package) *chainbind.Package {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal package for clone: %v", err)
	}
	var clone chainbind.Package
	if err := json.Unmarshal(raw, &clone); err != nil {
		t.Fatalf("unmarshal package for clone: %v", err)
	}
	return &clone
}

// flipCiphertextAndReconcile flips the first byte of name's ciphertext,
// reconciles cipher_hash to the flipped bytes so Verify's Level 1 still
// passes, and re-signs — the same shape as open_test.go's
// tamperCiphertextPastLevel1, duplicated here in miniature so this file
// does not reach across into another test file's unexported helper for a
// single call site.
func flipCiphertextAndReconcile(t *testing.T, signer chainbind.Signer, p *chainbind.Package, name string) {
	t.Helper()
	flipCiphertext(t, p, name)

	sealed := p.Segments[name]
	ciphertext, err := base64.RawURLEncoding.DecodeString(sealed.Ciphertext)
	if err != nil {
		t.Fatalf("decode ciphertext: %v", err)
	}
	tag, err := base64.RawURLEncoding.DecodeString(sealed.Tag)
	if err != nil {
		t.Fatalf("decode tag: %v", err)
	}
	combined := append(bytes.Clone(ciphertext), tag...)

	seg := p.Manifest.Segments[name]
	seg.CipherHash = chainbind.H(combined)
	p.Manifest.Segments[name] = seg

	sig, err := signer.Sign(context.Background(), mustBuildSigningView(t, p))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	p.Signature.Value = chainbind.EncodeSignatureValue(sig)
}

// reEncryptSegment replaces name's ciphertext with an encryption of
// newPlaintext under the segment's own DEK and AAD, reconciles cipher_hash so
// Verify's Level 1 still passes, and re-signs — leaving plain_hash stale.
// This is the only shape that drives Open all the way to its plain_hash
// check: it is what a malicious issuer, holding the signing key, can do.
func reEncryptSegment(t *testing.T, signer *local.Signer, p *chainbind.Package, name string, recipientPriv, newPlaintext []byte) {
	t.Helper()

	aadBytes, err := chainbind.AAD(p.Manifest.AADContext, name, p.SpecVersion)
	if err != nil {
		t.Fatalf("AAD: %v", err)
	}
	dek := unwrapDEK(t, x25519.Wrapper{}, p, name, recipientPriv)

	combined, nonce, err := chainbind.Encrypt(dek, newPlaintext, aadBytes)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ciphertext := combined[:len(combined)-gcmTagSizeForTest]
	tag := combined[len(combined)-gcmTagSizeForTest:]

	sealed := p.Segments[name]
	sealed.Nonce = b64(nonce)
	sealed.Ciphertext = b64(ciphertext)
	sealed.Tag = b64(tag)
	p.Segments[name] = sealed

	seg := p.Manifest.Segments[name]
	seg.CipherHash = chainbind.H(combined)
	p.Manifest.Segments[name] = seg

	resign(t, signer, p)
}

func mustBuildSigningView(t *testing.T, p *chainbind.Package) []byte {
	t.Helper()
	view, err := chainbind.BuildSigningView(*p)
	if err != nil {
		t.Fatalf("BuildSigningView: %v", err)
	}
	return view
}
