package chainbind_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielmalka/chainbind-go/internal/adapters/intent/mock"
	"github.com/danielmalka/chainbind-go/internal/adapters/keywrap/x25519"
	"github.com/danielmalka/chainbind-go/internal/adapters/signer/local"
	"github.com/danielmalka/chainbind-go/pkg/chainbind"
)

// seedDir points Seal's tests at the same authorization fixtures
// internal/adapters/intent/mock uses, relative to pkg/chainbind.
const seedDir = "../../testdata/authorizations"

func newTestVerifier(t *testing.T) *mock.Verifier {
	t.Helper()
	v, err := mock.New(seedDir)
	if err != nil {
		t.Fatalf("mock.New: %v", err)
	}
	return v
}

func newTestSigner(t *testing.T) *local.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	s, err := local.New(priv, "test-issuer-key-1")
	if err != nil {
		t.Fatalf("local.New: %v", err)
	}
	return s
}

// newTestAudience returns an Audience with a fresh X25519 keypair and the
// matching private key, for tests that need to unwrap what Seal produced.
func newTestAudience(t *testing.T, name string) (aud chainbind.Audience, priv []byte) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate x25519 key: %v", err)
	}
	return chainbind.Audience{Name: name, PublicKey: k.PublicKey().Bytes(), Kid: name + "-key-1"}, k.Bytes()
}

// baseSealRequest builds a request that Seal accepts as-is: a fresh
// plaintext per audience, and an intent_ref/projection pair the mock
// authority allows.
func baseSealRequest(audiences ...chainbind.Audience) chainbind.SealRequest {
	segments := make(map[string][]byte, len(audiences))
	order := make([]string, len(audiences))
	for i, a := range audiences {
		segments[a.Name] = []byte("plaintext for " + a.Name)
		order[i] = a.Name
	}
	return chainbind.SealRequest{
		Segments:     segments,
		SegmentOrder: order,
		Audiences:    audiences,
		IntentRef:    "intent:allow-example",
		Authority:    "https://intent-authority.local/v1",
		Projection:   map[string]any{"region": "us", "limit": 100},
		Issuer:       "chainbind-go-test",
		IssuedAt:     time.Now().UTC(),
		TenantID:     "test-tenant",
		Environment:  "test",
	}
}

func unwrapDEK(t *testing.T, w x25519.Wrapper, p *chainbind.Package, name string, priv []byte) []byte {
	t.Helper()
	seg, ok := p.Segments[name]
	if !ok {
		t.Fatalf("package has no segment %q", name)
	}
	epk, err := base64.RawURLEncoding.DecodeString(seg.EPK.X)
	if err != nil {
		t.Fatalf("decode epk: %v", err)
	}
	wrapped, err := base64.RawURLEncoding.DecodeString(seg.DEKWrapped)
	if err != nil {
		t.Fatalf("decode dek_wrapped: %v", err)
	}
	dek, err := w.Unwrap(context.Background(), priv, epk, wrapped)
	if err != nil {
		t.Fatalf("Unwrap(%q): %v", name, err)
	}
	return dek
}

func TestSeal_ProducesOneSegmentPerAudience_DistinctDEKs(t *testing.T) {
	audA, privA := newTestAudience(t, "alpha")
	audB, privB := newTestAudience(t, "bravo")
	req := baseSealRequest(audA, audB)

	wrapper := x25519.Wrapper{}
	p, err := chainbind.Seal(context.Background(), req, newTestSigner(t), wrapper, newTestVerifier(t))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if len(p.Segments) != 2 {
		t.Fatalf("got %d segments, want 2", len(p.Segments))
	}
	if len(p.Manifest.Segments) != 2 {
		t.Fatalf("got %d manifest segments, want 2", len(p.Manifest.Segments))
	}

	dekA := unwrapDEK(t, wrapper, p, "alpha", privA)
	dekB := unwrapDEK(t, wrapper, p, "bravo", privB)
	if bytes.Equal(dekA, dekB) {
		t.Fatal("both segments were sealed under the same DEK")
	}
}

func TestSeal_SamePayloadTwice_DistinctIDsAndCiphertexts(t *testing.T) {
	aud, _ := newTestAudience(t, "alpha")
	req := baseSealRequest(aud)

	signer := newTestSigner(t)
	wrapper := x25519.Wrapper{}
	iv := newTestVerifier(t)

	p1, err := chainbind.Seal(context.Background(), req, signer, wrapper, iv)
	if err != nil {
		t.Fatalf("Seal (1st): %v", err)
	}
	p2, err := chainbind.Seal(context.Background(), req, signer, wrapper, iv)
	if err != nil {
		t.Fatalf("Seal (2nd): %v", err)
	}

	if p1.PackageID == p2.PackageID {
		t.Fatalf("package_id repeated across two seals of the same payload: %q", p1.PackageID)
	}
	if p1.Segments["alpha"].Ciphertext == p2.Segments["alpha"].Ciphertext {
		t.Fatal("ciphertext repeated across two seals of the same payload")
	}
}

func TestSeal_IntentDenied_Refuses(t *testing.T) {
	aud, _ := newTestAudience(t, "alpha")
	req := baseSealRequest(aud)
	req.IntentRef = "intent:deny-example"
	req.Projection = map[string]any{"region": "eu"}

	p, err := chainbind.Seal(context.Background(), req, newTestSigner(t), x25519.Wrapper{}, newTestVerifier(t))
	if p != nil {
		t.Fatal("Seal returned a package when the authority denied the execution")
	}
	if !errors.Is(err, chainbind.ErrIntentDenied) {
		t.Fatalf("error = %v, want ErrIntentDenied", err)
	}

	const wantReason = `field "region": value eu is not in the allowed set`
	if !strings.Contains(err.Error(), wantReason) {
		t.Fatalf("error %q does not carry the authority's reason verbatim; want it to contain %q", err.Error(), wantReason)
	}
}

func TestSeal_AuthorityUnreachable_FailsClosed(t *testing.T) {
	aud, _ := newTestAudience(t, "alpha")
	req := baseSealRequest(aud)
	// intent:does-not-exist is not a seeded authorization: the mock
	// answers with an error rather than a decision, exactly what a real
	// unreachable authority would also cause Check to do. Seal must treat
	// any error from Check identically: refuse, no fallback.
	req.IntentRef = "intent:does-not-exist"

	p, err := chainbind.Seal(context.Background(), req, newTestSigner(t), x25519.Wrapper{}, newTestVerifier(t))
	if p != nil {
		t.Fatal("Seal returned a non-nil package when the authority was unreachable")
	}
	if err == nil {
		t.Fatal("Seal returned a nil error when the authority was unreachable")
	}
	if errors.Is(err, chainbind.ErrIntentDenied) {
		t.Fatal("an unreachable authority was reported as a denial rather than as unreachable")
	}
}

// spyWrapper wraps a real KeyWrapper and flips wrapCalled the first time
// Wrap runs. Wrap only ever runs after Encrypt has produced ciphertext for
// that same segment, so wrapCalled is a real, call-graph-driven proxy for
// "ciphertext exists somewhere in this package" — not a flag Seal itself
// sets for the test's benefit.
type spyWrapper struct {
	inner      chainbind.KeyWrapper
	wrapCalled *atomic.Bool
}

func (s spyWrapper) PublicKey(priv []byte) ([]byte, error) {
	return s.inner.PublicKey(priv)
}

func (s spyWrapper) Wrap(ctx context.Context, recipientPub, dek []byte) ([]byte, []byte, error) {
	s.wrapCalled.Store(true)
	return s.inner.Wrap(ctx, recipientPub, dek)
}

func (s spyWrapper) Unwrap(ctx context.Context, priv, epk, wrapped []byte) ([]byte, error) {
	return s.inner.Unwrap(ctx, priv, epk, wrapped)
}

func (s spyWrapper) Thumbprint(recipientPub []byte) (string, error) {
	return s.inner.Thumbprint(recipientPub)
}

// spyVerifier wraps a real IntentVerifier and fails the test the moment
// Check is called after wrapCalled has already gone true.
type spyVerifier struct {
	inner      chainbind.IntentVerifier
	wrapCalled *atomic.Bool
	t          *testing.T
}

func (s spyVerifier) Check(ctx context.Context, intentRef string, projection any) (chainbind.IntentDecision, error) {
	if s.wrapCalled.Load() {
		s.t.Fatal("IntentVerifier.Check was called after a DEK had already been wrapped — ciphertext existed before the authority was consulted")
	}
	return s.inner.Check(ctx, intentRef, projection)
}

func (s spyVerifier) ConstraintsHash(ctx context.Context, intentRef string) (string, error) {
	return s.inner.ConstraintsHash(ctx, intentRef)
}

func TestSeal_AuthorityConsultedBeforeAnyCiphertextExists(t *testing.T) {
	audA, _ := newTestAudience(t, "alpha")
	audB, _ := newTestAudience(t, "bravo")
	req := baseSealRequest(audA, audB)

	var wrapCalled atomic.Bool
	wrapper := spyWrapper{inner: x25519.Wrapper{}, wrapCalled: &wrapCalled}
	iv := spyVerifier{inner: newTestVerifier(t), wrapCalled: &wrapCalled, t: t}

	if _, err := chainbind.Seal(context.Background(), req, newTestSigner(t), wrapper, iv); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Guard against a spy that never actually observed anything: if Wrap
	// was never called, spyVerifier.Check never had a chance to fail and
	// the test above proves nothing.
	if !wrapCalled.Load() {
		t.Fatal("spyWrapper.Wrap was never called; the ordering assertion above was never exercised")
	}
}

func TestSeal_RejectsEmptyAudienceSet(t *testing.T) {
	req := chainbind.SealRequest{
		IntentRef:  "intent:allow-example",
		Projection: map[string]any{"region": "us", "limit": 1},
		Issuer:     "chainbind-go-test",
		IssuedAt:   time.Now().UTC(),
	}

	_, err := chainbind.Seal(context.Background(), req, newTestSigner(t), x25519.Wrapper{}, newTestVerifier(t))
	if !errors.Is(err, chainbind.ErrNoAudiences) {
		t.Fatalf("error = %v, want ErrNoAudiences", err)
	}
}

// TestSeal_CipherHashCoversCiphertextAndTag is the trap test: cipher_hash
// must be H(ciphertext || tag) over Encrypt's full, unsplit output. Hashing
// only the shortened wire ciphertext would still round-trip through Seal's
// own output, so this recomputes the hash independently from the decoded
// wire fields and compares.
func TestSeal_CipherHashCoversCiphertextAndTag(t *testing.T) {
	aud, _ := newTestAudience(t, "alpha")
	req := baseSealRequest(aud)

	p, err := chainbind.Seal(context.Background(), req, newTestSigner(t), x25519.Wrapper{}, newTestVerifier(t))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	sealed := p.Segments["alpha"]
	manifestSeg := p.Manifest.Segments["alpha"]

	ciphertext, err := base64.RawURLEncoding.DecodeString(sealed.Ciphertext)
	if err != nil {
		t.Fatalf("decode ciphertext: %v", err)
	}
	tag, err := base64.RawURLEncoding.DecodeString(sealed.Tag)
	if err != nil {
		t.Fatalf("decode tag: %v", err)
	}

	combined := append(bytes.Clone(ciphertext), tag...)
	want := chainbind.H(combined)
	if manifestSeg.CipherHash != want {
		t.Fatalf("cipher_hash = %q, want %q (H(ciphertext || tag))", manifestSeg.CipherHash, want)
	}
}

func TestSeal_SignatureVerifiesAgainstReconstructedSigningView(t *testing.T) {
	aud, _ := newTestAudience(t, "alpha")
	req := baseSealRequest(aud)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	signer, err := local.New(priv, "test-issuer-key-1")
	if err != nil {
		t.Fatalf("local.New: %v", err)
	}

	p, err := chainbind.Seal(context.Background(), req, signer, x25519.Wrapper{}, newTestVerifier(t))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	view, err := chainbind.ReconstructSigningView(*p)
	if err != nil {
		t.Fatalf("ReconstructSigningView: %v", err)
	}
	sig, err := chainbind.DecodeSignatureValue(p.Signature.Value)
	if err != nil {
		t.Fatalf("DecodeSignatureValue: %v", err)
	}

	if !local.Verify(pub, view, sig) {
		t.Fatal("signature does not verify against the reconstructed signing view")
	}
	if p.Issuer.Kid != p.Signature.Kid {
		t.Fatalf("issuer.kid %q != signature.kid %q", p.Issuer.Kid, p.Signature.Kid)
	}
}

func TestSeal_CNFJKTMatchesThumbprintOfAudienceKey(t *testing.T) {
	audA, _ := newTestAudience(t, "alpha")
	audB, _ := newTestAudience(t, "bravo")
	req := baseSealRequest(audA, audB)

	p, err := chainbind.Seal(context.Background(), req, newTestSigner(t), x25519.Wrapper{}, newTestVerifier(t))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	for _, aud := range []chainbind.Audience{audA, audB} {
		want, err := x25519.Thumbprint(aud.PublicKey)
		if err != nil {
			t.Fatalf("Thumbprint(%q): %v", aud.Name, err)
		}
		got, ok := p.CNF[aud.Name]
		if !ok {
			t.Fatalf("cnf missing audience %q", aud.Name)
		}
		if got.JKT != want {
			t.Fatalf("cnf[%q].jkt = %q, want %q", aud.Name, got.JKT, want)
		}
	}
}
