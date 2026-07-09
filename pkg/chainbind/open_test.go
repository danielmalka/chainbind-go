package chainbind_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
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

// gcmTagSizeForTest mirrors seal.go's unexported gcmTagSize: the length of
// the AES-256-GCM tag appended to Encrypt's combined output.
const gcmTagSizeForTest = 16

func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	return b
}

func TestOpen_ReturnsExactlyTheSegmentSealedToTheKey(t *testing.T) {
	audA, privA := newTestAudience(t, "alpha")
	audB, privB := newTestAudience(t, "bravo")
	p, pub := sealTestPackage(t, audA, audB)

	opt := chainbind.VerifyOptions{
		IssuerKey: func(string, string) (ed25519.PublicKey, bool) { return pub, true },
	}

	gotName, gotPlain, err := chainbind.Open(context.Background(), p, privA, x25519.Wrapper{}, opt)
	if err != nil {
		t.Fatalf("Open(alpha's key): %v", err)
	}
	if gotName != "alpha" {
		t.Fatalf("audience = %q, want %q", gotName, "alpha")
	}
	if !bytes.Equal(gotPlain, []byte("plaintext for alpha")) {
		t.Fatalf("plaintext = %q, want %q", gotPlain, "plaintext for alpha")
	}

	gotName, gotPlain, err = chainbind.Open(context.Background(), p, privB, x25519.Wrapper{}, opt)
	if err != nil {
		t.Fatalf("Open(bravo's key): %v", err)
	}
	if gotName != "bravo" {
		t.Fatalf("audience = %q, want %q", gotName, "bravo")
	}
	if !bytes.Equal(gotPlain, []byte("plaintext for bravo")) {
		t.Fatalf("plaintext = %q, want %q", gotPlain, "plaintext for bravo")
	}
}

func TestOpen_WrongRecipientKey_Fails(t *testing.T) {
	aud, priv := newTestAudience(t, "alpha")
	pub, signer := newIssuerKeypair(t)
	req := baseSealRequest(aud)
	p, err := chainbind.Seal(context.Background(), req, signer, x25519.Wrapper{}, newTestVerifier(t))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// A third keypair the package was never sealed to.
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate x25519 key: %v", err)
	}
	stranger := k.Bytes()

	opt := chainbind.VerifyOptions{
		IssuerKey: func(string, string) (ed25519.PublicKey, bool) { return pub, true },
	}

	_, plaintext, wrongKeyErr := chainbind.Open(context.Background(), p, stranger, x25519.Wrapper{}, opt)
	if wrongKeyErr == nil {
		t.Fatal("Open succeeded with a key the package was never sealed to")
	}
	if plaintext != nil {
		t.Fatal("Open returned plaintext alongside an error")
	}
	if !errors.Is(wrongKeyErr, chainbind.ErrDecryptionFailed) {
		t.Fatalf("error = %v, want ErrDecryptionFailed", wrongKeyErr)
	}

	// The failure must reveal nothing about *why*: a tampered ciphertext,
	// opened with the *correct* key, produces the identical sentinel. The
	// tamper flips a ciphertext byte but leaves the original tag in place,
	// and cipher_hash/the signature are reconciled to the tampered bytes so
	// Level 1 still passes — isolating the failure to the GCM tag check
	// inside Open, exactly where a wrong key also fails.
	tamperCiphertextPastLevel1(t, signer, p, "alpha")
	_, plaintext, tamperedErr := chainbind.Open(context.Background(), p, priv, x25519.Wrapper{}, opt)
	if plaintext != nil {
		t.Fatal("Open returned plaintext for a tampered ciphertext")
	}
	if !errors.Is(tamperedErr, chainbind.ErrDecryptionFailed) {
		t.Fatalf("tampered-ciphertext error = %v, want ErrDecryptionFailed", tamperedErr)
	}
	if wrongKeyErr.Error() != tamperedErr.Error() {
		t.Fatalf("a wrong key and a tampered ciphertext produced different error text: %q vs %q — the failure must be indistinguishable", wrongKeyErr, tamperedErr)
	}
}

// tamperCiphertextPastLevel1 flips the first byte of name's ciphertext,
// then reconciles cipher_hash and the signature to the tampered bytes so
// Verify's Level 1 still passes completely. The original GCM tag is left
// untouched, so it no longer authenticates the flipped ciphertext: the
// failure is pushed past Level 1 and into the GCM tag check Open performs,
// rather than being caught earlier by cipher_hash.
func tamperCiphertextPastLevel1(t *testing.T, signer *local.Signer, p *chainbind.Package, name string) {
	t.Helper()
	flipCiphertext(t, p, name)

	sealed := p.Segments[name]
	ciphertext := decodeB64(t, sealed.Ciphertext)
	tag := decodeB64(t, sealed.Tag)
	combined := append(bytes.Clone(ciphertext), tag...)

	seg := p.Manifest.Segments[name]
	seg.CipherHash = chainbind.H(combined)
	p.Manifest.Segments[name] = seg

	resign(t, signer, p)
}

func TestOpen_PlainHashMismatch_Fails(t *testing.T) {
	aud, priv := newTestAudience(t, "alpha")
	pub, signer := newIssuerKeypair(t)
	req := baseSealRequest(aud)

	p, err := chainbind.Seal(context.Background(), req, signer, x25519.Wrapper{}, newTestVerifier(t))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// As a malicious issuer: re-encrypt the segment with different
	// plaintext under the same AAD, but leave manifest.segments["alpha"]
	// .plain_hash claiming the original plaintext's hash. cipher_hash is
	// updated to match the new ciphertext so L1.4 still passes and Open
	// reaches decryption; only plain_hash is left stale.
	aadBytes, err := chainbind.AAD(p.Manifest.AADContext, "alpha", p.SpecVersion)
	if err != nil {
		t.Fatalf("AAD: %v", err)
	}

	dek := unwrapDEK(t, x25519.Wrapper{}, p, "alpha", priv)
	newPlaintext := []byte("substituted plaintext for alpha")
	combined, nonce, err := chainbind.Encrypt(dek, newPlaintext, aadBytes)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ciphertext := combined[:len(combined)-gcmTagSizeForTest]
	tag := combined[len(combined)-gcmTagSizeForTest:]

	sealed := p.Segments["alpha"]
	sealed.Nonce = b64(nonce)
	sealed.Ciphertext = b64(ciphertext)
	sealed.Tag = b64(tag)
	p.Segments["alpha"] = sealed

	seg := p.Manifest.Segments["alpha"]
	seg.CipherHash = chainbind.H(combined)
	p.Manifest.Segments["alpha"] = seg

	resign(t, signer, p)

	opt := chainbind.VerifyOptions{
		IssuerKey: func(string, string) (ed25519.PublicKey, bool) { return pub, true },
	}

	report, err := chainbind.Verify(context.Background(), p, opt)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !report.Level1() {
		t.Fatalf("Level1() = false; test does not exercise the plain_hash check as intended: %+v", report)
	}

	_, plaintext, err := chainbind.Open(context.Background(), p, priv, x25519.Wrapper{}, opt)
	if err == nil {
		t.Fatal("Open succeeded despite a plain_hash that does not describe the recovered plaintext")
	}
	if plaintext != nil {
		t.Fatal("Open returned plaintext alongside a plain_hash mismatch error")
	}
	if !errors.Is(err, chainbind.ErrHashMismatch) {
		t.Fatalf("error = %v, want ErrHashMismatch", err)
	}
}

func TestOpen_SplicedSegmentFromAnotherPackage_Fails(t *testing.T) {
	audA, _ := newTestAudience(t, "alpha")
	pkgA, _ := sealTestPackage(t, audA)

	audB, privB := newTestAudience(t, "alpha")
	pubB, signerB := newIssuerKeypair(t)
	reqB := baseSealRequest(audB)
	pkgB, err := chainbind.Seal(context.Background(), reqB, signerB, x25519.Wrapper{}, newTestVerifier(t))
	if err != nil {
		t.Fatalf("Seal (B): %v", err)
	}

	// Splice A's sealed segment into B, then rewrite cipher_hash to match
	// the spliced bytes and re-sign as B's own issuer — the strongest case:
	// a compromised issuer signing key, not just a skipped verification.
	spliced := pkgA.Segments["alpha"]
	pkgB.Segments["alpha"] = spliced

	ciphertext := decodeB64(t, spliced.Ciphertext)
	tag := decodeB64(t, spliced.Tag)
	combined := append(bytes.Clone(ciphertext), tag...)

	seg := pkgB.Manifest.Segments["alpha"]
	seg.CipherHash = chainbind.H(combined)
	pkgB.Manifest.Segments["alpha"] = seg

	resign(t, signerB, pkgB)

	opt := chainbind.VerifyOptions{
		IssuerKey: func(string, string) (ed25519.PublicKey, bool) { return pubB, true },
	}

	// Level 1 must pass completely: this proves what catches the splice at
	// Open is the AAD/GCM control, not cipher_hash or the signature.
	report, err := chainbind.Verify(context.Background(), pkgB, opt)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !report.Level1() {
		t.Fatalf("Level1() = false for the spliced-but-resigned package; test does not exercise the AAD control as intended: %+v", report)
	}

	_, plaintext, err := chainbind.Open(context.Background(), pkgB, privB, x25519.Wrapper{}, opt)
	if err == nil {
		t.Fatal("Open succeeded on a segment spliced from another package — the AAD control (package_id) must catch this via the GCM tag")
	}
	if plaintext != nil {
		t.Fatal("Open returned plaintext for a spliced segment")
	}
	if !errors.Is(err, chainbind.ErrDecryptionFailed) {
		t.Fatalf("error = %v, want ErrDecryptionFailed", err)
	}
}

// spyKeyWrapper wraps a real KeyWrapper and records whether Unwrap was ever
// called, so a test can prove Open never reaches decryption when integrity
// verification fails.
type spyKeyWrapper struct {
	inner        chainbind.KeyWrapper
	unwrapCalled *bool
}

func (s spyKeyWrapper) Wrap(ctx context.Context, recipientPub, dek []byte) ([]byte, []byte, error) {
	return s.inner.Wrap(ctx, recipientPub, dek)
}

func (s spyKeyWrapper) Unwrap(ctx context.Context, priv, epk, wrapped []byte) ([]byte, error) {
	*s.unwrapCalled = true
	return s.inner.Unwrap(ctx, priv, epk, wrapped)
}

func (s spyKeyWrapper) Thumbprint(recipientPub []byte) (string, error) {
	return s.inner.Thumbprint(recipientPub)
}

func (s spyKeyWrapper) PublicKey(priv []byte) ([]byte, error) {
	return s.inner.PublicKey(priv)
}

func TestOpen_IntegrityFailure_DoesNotDecrypt(t *testing.T) {
	aud, priv := newTestAudience(t, "alpha")
	p, pub := sealTestPackage(t, aud)

	// Mutate the signed manifest so the signature no longer verifies —
	// Level 1 must fail.
	seg := p.Manifest.Segments["alpha"]
	seg.PlainHash = "sha256:" + strings.Repeat("0", 64)
	p.Manifest.Segments["alpha"] = seg

	var unwrapCalled bool
	spy := spyKeyWrapper{inner: x25519.Wrapper{}, unwrapCalled: &unwrapCalled}

	opt := chainbind.VerifyOptions{
		IssuerKey: func(string, string) (ed25519.PublicKey, bool) { return pub, true },
	}

	_, plaintext, err := chainbind.Open(context.Background(), p, priv, spy, opt)
	if err == nil {
		t.Fatal("Open succeeded despite a broken signature")
	}
	if plaintext != nil {
		t.Fatal("Open returned plaintext despite failed integrity verification")
	}
	if !errors.Is(err, chainbind.ErrIntegrityCheckFailed) {
		t.Fatalf("error = %v, want ErrIntegrityCheckFailed", err)
	}
	if unwrapCalled {
		t.Fatal("KeyWrapper.Unwrap was called even though Level 1 failed — no DEK may be recovered before integrity is verified")
	}
}

func TestOpen_ResponseCarriesNoForeignMaterial(t *testing.T) {
	// Open's return signature must be (string, []byte, error): a plain
	// string cannot carry key material or another segment's anything.
	fn := reflect.TypeOf(chainbind.Open)
	if fn.NumOut() != 3 {
		t.Fatalf("Open has %d return values, want 3", fn.NumOut())
	}
	if fn.Out(0).Kind() != reflect.String {
		t.Fatalf("Open's first return value is %v, want string", fn.Out(0))
	}
	if fn.Out(1).String() != "[]uint8" {
		t.Fatalf("Open's second return value is %v, want []byte", fn.Out(1))
	}
	wantErr := reflect.TypeOf((*error)(nil)).Elem()
	if fn.Out(2) != wantErr {
		t.Fatalf("Open's third return value is %v, want error", fn.Out(2))
	}
}

func TestOpen_NoSegmentNameParameter(t *testing.T) {
	// Pins D-002: nothing in Open's parameter list is capable of naming
	// which segment to open. In particular, no parameter is a bare string
	// — the shape a "segment name" argument would take.
	fn := reflect.TypeOf(chainbind.Open)
	wantKinds := []reflect.Kind{
		reflect.Interface, // context.Context
		reflect.Ptr,       // *Package
		reflect.Slice,     // priv []byte
		reflect.Interface, // KeyWrapper
		reflect.Struct,    // VerifyOptions
	}
	if fn.NumIn() != len(wantKinds) {
		t.Fatalf("Open has %d parameters, want %d", fn.NumIn(), len(wantKinds))
	}
	for i, want := range wantKinds {
		if got := fn.In(i).Kind(); got != want {
			t.Fatalf("Open parameter %d has kind %v, want %v", i, got, want)
		}
	}
	for i := 0; i < fn.NumIn(); i++ {
		if fn.In(i).Kind() == reflect.String {
			t.Fatalf("Open parameter %d is a bare string — this is the shape a segment-name parameter would take, and D-002 forbids it", i)
		}
	}
}
