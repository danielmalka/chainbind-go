package chainbind_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	mathrand "math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/danielmalka/chainbind-go/internal/adapters/keywrap/x25519"
	"github.com/danielmalka/chainbind-go/internal/adapters/signer/local"
	"github.com/danielmalka/chainbind-go/pkg/chainbind"
)

// genX25519Keypair generates a fresh X25519 keypair from crypto/rand — real
// entropy for key material, never math/rand/v2 (that is reserved for the
// property test's *structural* choices: audience counts, names, payload
// shapes — so a failure reproduces from its seed).
func genX25519Keypair(t *testing.T) (pub, priv []byte) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("generate x25519 key: %v", err)
	}
	return k.PublicKey().Bytes(), k.Bytes()
}

// randomJSONValue returns a JSON-encodable value of a random small shape,
// driven entirely by r (the property test's seeded, reproducible source of
// structural randomness).
func randomJSONValue(r *mathrand.Rand) any {
	switch r.IntN(4) {
	case 0:
		return fmt.Sprintf("v%d", r.IntN(1000))
	case 1:
		return r.IntN(100000)
	case 2:
		return r.IntN(2) == 0
	default:
		return nil
	}
}

// randomPayload returns a small, JSON-marshalled object with 0-3 extra keys
// of randomly varied shape, plus a mandatory "_case" key set to tag — the
// per-audience unique marker that guarantees two audiences in the same case
// never produce byte-identical plaintext by chance (e.g. two audiences both
// rolling zero extra keys would otherwise both serialize to the same empty
// object, making the cross-audience non-leak assertion below meaningless
// for that pair).
func randomPayload(t *testing.T, r *mathrand.Rand, tag string) []byte {
	t.Helper()
	n := r.IntN(4)
	obj := make(map[string]any, n+1)
	obj["_case"] = tag
	for i := 0; i < n; i++ {
		obj[fmt.Sprintf("k%d", i)] = randomJSONValue(r)
	}
	raw, err := chainbind.JCS(obj)
	if err != nil {
		t.Fatalf("JCS(payload): %v", err)
	}
	return raw
}

// caseSpec is one property-test case's structural shape, drawn serially from
// the seeded generator before any subtest runs. math/rand/v2's *Rand is not
// safe for concurrent use, and the cases below run in parallel — so all
// structural randomness is consumed here, in a fixed order, and a failing
// case still reproduces from the same seed.
type caseSpec struct {
	names    []string
	payloads [][]byte
}

// TestProperty_SealVerifyOpen_RoundTrips runs 1000 Seal -> Verify -> Open
// cases over a randomly generated audience set and payload shape per case.
// Structural randomness (audience count, names, payload shape) comes from a
// fixed-seed math/rand/v2 generator so a failing case reproduces; key
// material always comes from crypto/rand (genX25519Keypair). One signer and
// one mock authority are reused across all 1000 cases — local.Signer is
// stateless and mock.Verifier guards its map with an RWMutex, so both are
// safe to share across parallel subtests.
//
// The cases run in parallel because they are independent and there are a
// thousand of them: serially this test alone cost 27s of every
// `make check-strict` under -race, which is a tax on every commit for no
// added evidence.
func TestProperty_SealVerifyOpen_RoundTrips(t *testing.T) {
	const cases = 1000
	//nolint:gosec // math/rand/v2 is deliberate: it seeds this test's structural choices
	// (audience count, names, payload shape) reproducibly, so a failure reproduces from the
	// fixed seed. It never touches key material — every key comes from crypto/rand via
	// genX25519Keypair.
	r := mathrand.New(mathrand.NewPCG(1, 2))

	specs := make([]caseSpec, cases)
	for i := range specs {
		n := r.IntN(4) + 1 // 1..4 audiences
		spec := caseSpec{names: make([]string, n), payloads: make([][]byte, n)}
		for j := 0; j < n; j++ {
			spec.names[j] = fmt.Sprintf("aud-%d-%d-%d", i, j, r.IntN(1_000_000))
			spec.payloads[j] = randomPayload(t, r, spec.names[j])
		}
		specs[i] = spec
	}

	issuerPub, issuerSigner := newIssuerKeypair(t)
	iv := newTestVerifier(t)
	wrapper := x25519.Wrapper{}

	opt := chainbind.VerifyOptions{
		IssuerKey: func(string, string) (ed25519.PublicKey, bool) { return issuerPub, true },
		Intent:    iv,
	}

	for i, spec := range specs {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()

			type auInfo struct {
				aud     chainbind.Audience
				priv    []byte
				payload []byte
			}
			aus := make([]auInfo, 0, len(spec.names))
			segments := make(map[string][]byte, len(spec.names))
			order := make([]string, 0, len(spec.names))

			for j, name := range spec.names {
				pubKey, privKey := genX25519Keypair(t)
				aus = append(aus, auInfo{
					aud:     chainbind.Audience{Name: name, PublicKey: pubKey, Kid: name + "-key"},
					priv:    privKey,
					payload: spec.payloads[j],
				})
				segments[name] = spec.payloads[j]
				order = append(order, name)
			}

			audiences := make([]chainbind.Audience, len(aus))
			for j, a := range aus {
				audiences[j] = a.aud
			}

			req := chainbind.SealRequest{
				Segments:     segments,
				SegmentOrder: order,
				Audiences:    audiences,
				IntentRef:    "intent:allow-example",
				Authority:    "https://intent-authority.local/v1",
				Projection:   map[string]any{"region": "us", "limit": 100},
				Issuer:       "property-test",
				IssuedAt:     time.Now().UTC(),
				TenantID:     "property-tenant",
				Environment:  "property-env",
			}

			p, err := chainbind.Seal(ctx, req, issuerSigner, wrapper, iv)
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}

			report, err := chainbind.Verify(ctx, p, opt)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !report.OK() {
				t.Fatalf("report.OK() = false: %+v", report)
			}

			// Every holder opens exactly its own segment, byte-identical.
			for _, a := range aus {
				gotName, gotPlain, err := chainbind.Open(ctx, p, a.priv, wrapper, opt)
				if err != nil {
					t.Fatalf("Open(%q): %v", a.aud.Name, err)
				}
				if gotName != a.aud.Name {
					t.Fatalf("Open(%q's key) returned audience %q", a.aud.Name, gotName)
				}
				if !bytes.Equal(gotPlain, a.payload) {
					t.Fatalf("Open(%q) plaintext mismatch", a.aud.Name)
				}
			}

			// There is deliberately no pairwise non-holder loop here. Opening
			// with audience b's key while thinking about audience a is the
			// same call as opening with b's key — Open takes no segment
			// name, so there is nothing for a to vary. The holder loop above
			// already asserts that b's key yields exactly b's name and b's
			// bytes; a pairwise loop re-runs that identical assertion n-1
			// more times per audience, and its "did it return a's plaintext"
			// check can never fire, because the _case tag makes every
			// payload distinct. It cost O(n²) Opens per case and proved
			// nothing the line above did not.
			//
			// The real non-holder is the stranger below: a key belonging to
			// no audience at all.

			// A key belonging to no audience at all must fail, not silently
			// return someone else's segment.
			_, strangerPriv := genX25519Keypair(t)
			_, _, err = chainbind.Open(ctx, p, strangerPriv, wrapper, opt)
			if !errors.Is(err, chainbind.ErrDecryptionFailed) {
				t.Fatalf("Open(stranger key) error = %v, want ErrDecryptionFailed", err)
			}
		})
	}
}

// TestProfile_OwnsEveryCheckoutName pins architecture invariant 9: the core
// carries no checkout vocabulary. It globs *.go in this package's own
// directory — non-recursive, so profile/ is excluded by construction, not
// by an exclusion list — and greps every non-test file, case-insensitively,
// for checkout/merchant/gateway/payment/transaction.
//
// It cannot match itself: the keyword list lives in this _test.go file,
// which the walk skips (no go:embed, no reading its own source). And it
// cannot pass vacuously: if the glob or the exclusion ever left nothing to
// scan, the >5 assertion below fails loudly instead of the test going green
// for the wrong reason.
func TestProfile_OwnsEveryCheckoutName(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob *.go: %v", err)
	}

	keywords := []string{"checkout", "merchant", "gateway", "payment", "transaction"}
	scanned := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		scanned++

		raw, err := os.ReadFile(f) //nolint:gosec // f comes from filepath.Glob("*.go") in this package's own directory, not external input
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		lines := strings.Split(string(raw), "\n")
		for lineNo, line := range lines {
			lower := strings.ToLower(line)
			for _, kw := range keywords {
				if strings.Contains(lower, kw) {
					t.Errorf("%s:%d contains core-forbidden domain vocabulary %q: %s", f, lineNo+1, kw, strings.TrimSpace(line))
				}
			}
		}
	}

	if scanned <= 5 {
		t.Fatalf("scanned only %d non-test .go files in pkg/chainbind; want more than 5 — a test that greps an empty (or near-empty) file list passes vacuously", scanned)
	}
}

// malformedCase is one row of TestVerify_MalformedPackages_AbortAtL1_1.
//
// resignable says whether the mutated package can be re-signed so that its
// signature is valid over the malformed content. Every structural mutation
// can; the one that empties signature.signed_fields cannot, because the
// signing view is reconstructed *from* signed_fields.
type malformedCase struct {
	name       string
	mutate     func(p *chainbind.Package)
	resignable bool
	wantFault  chainbind.StructuralFault
}

// sealAndSign seals a package and returns it together with the issuer's
// public key and the signer that produced it, so a test can mutate the
// package and then re-sign it with verify_test.go's resign helper.
// sealTestPackage discards the signer.
func sealAndSign(t *testing.T, audiences ...chainbind.Audience) (*chainbind.Package, ed25519.PublicKey, *local.Signer) {
	t.Helper()
	pub, signer := newIssuerKeypair(t)
	p, err := chainbind.Seal(context.Background(), baseSealRequest(audiences...), signer, x25519.Wrapper{}, newTestVerifier(t))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return p, pub, signer
}

// TestVerify_MalformedPackages_AbortAtL1_1 covers parsePackage's
// currently-untested defensive branches (verify.go's parsePackage), each of
// which sits on the L1.1 abort path — the first thing hostile input
// touches. Each case asserts the *specific* StructuralFault the mutation
// produces, not merely that Level 1 failed — before TASK-001-16, one boolean
// covered every one of these branches, so swapping two of their return sites
// broke nothing the suite could see.
//
// Verify does NOT return a Go error for any of these: parsePackage's fault
// value is written straight into report.Structural (verify.go). A malformed
// package is Verify's *answer*, not a failure to process the request
// (architecture invariant 3) — the same contract TestVerify_RejectsUnknownSpecVersion
// and friends already rely on. So this table asserts the actual contract:
// Verify returns a nil error, SpecVersionSupported stays true (spec_version
// itself was never touched), and the report never reaches L1.4 —
// CipherHashes stays nil, Level1() is false, and OK() is false. It does not
// assert errors.Is(err, chainbind.ErrMalformedPackage) against Verify's
// return, because Verify never surfaces that error to begin with.
//
// **Every resignable case re-signs the mutated package**, and that is the
// whole point. Mutating the manifest invalidates the issuer signature, so an
// un-resigned package is rejected at L1.2 whether or not L1.1 exists at all:
// deleting the structural check from Verify leaves such a table green, and it
// did, when this test was first written. Re-signing means the only remaining
// grounds for rejection are structural, so removing L1.1 makes Verify sail
// past it into L1.4 and populate CipherHashes — which the assertions below
// catch.
//
// Two cases are not resignable, for two different reasons, both explained at
// their own table entry: emptying signature.signed_fields makes the signing
// view unreconstructible regardless of whether it runs, and corrupting
// signature.value would simply be undone by resign overwriting it with a
// fresh, valid encoding.
func TestVerify_MalformedPackages_AbortAtL1_1(t *testing.T) {
	cases := []malformedCase{
		{
			name: "empty signature.signed_fields",
			mutate: func(p *chainbind.Package) {
				p.Signature.SignedFields = nil
			},
			resignable: false,
			wantFault:  chainbind.FaultEmptySignedFields,
		},
		{
			name: "empty manifest.segment_order",
			mutate: func(p *chainbind.Package) {
				p.Manifest.SegmentOrder = nil
			},
			resignable: true,
			wantFault:  chainbind.FaultEmptySegmentOrder,
		},
		{
			name: "manifest.segments count != segment_order count",
			mutate: func(p *chainbind.Package) {
				delete(p.Manifest.Segments, "bravo")
			},
			resignable: true,
			wantFault:  chainbind.FaultSegmentCountMismatch,
		},
		{
			name: "audience listed twice in segment_order",
			mutate: func(p *chainbind.Package) {
				p.Manifest.SegmentOrder = []string{"alpha", "alpha"}
			},
			resignable: true,
			wantFault:  chainbind.FaultDuplicateAudience,
		},
		{
			name: "audience in segment_order with no manifest.segments entry",
			mutate: func(p *chainbind.Package) {
				p.Manifest.SegmentOrder = []string{"alpha", "charlie"}
			},
			resignable: true,
			wantFault:  chainbind.FaultManifestSegmentMissing,
		},
		{
			name: "audience in segment_order with no segments entry",
			mutate: func(p *chainbind.Package) {
				seg := p.Manifest.Segments["alpha"]
				seg.Audience = "charlie"
				delete(p.Manifest.Segments, "bravo")
				p.Manifest.Segments["charlie"] = seg
				p.Manifest.SegmentOrder = []string{"alpha", "charlie"}
				// p.Segments (the sealed wire segments) is left untouched:
				// it has "alpha" and "bravo", never "charlie".
			},
			resignable: true,
			wantFault:  chainbind.FaultSealedSegmentMissing,
		},
		{
			name: "signed_fields names a bogus field",
			mutate: func(p *chainbind.Package) {
				p.Signature.SignedFields = append(append([]string{}, p.Signature.SignedFields[1:]...), "bogus_field")
			},
			// Unlike the empty-signed_fields case, resign here works fine:
			// resign rebuilds the signing view from the fixed nine
			// RequiredSignedFields (signview.go's BuildSigningView), never
			// from p.Signature.SignedFields, so it does not depend on this
			// mutation at all. Resigning proves the rejection is really
			// about the bogus name in signed_fields, not a stale signature.
			resignable: true,
			wantFault:  chainbind.FaultSignedFieldsInvalid,
		},
		{
			name: "signature.value is not base64url",
			mutate: func(p *chainbind.Package) {
				p.Signature.Value = "not valid base64url!!"
			},
			// Not resignable: resign overwrites signature.value with a
			// freshly encoded (and therefore valid) signature, which would
			// undo the only mutation this case makes. Nothing else about
			// the package is touched, so there is nothing for a stale
			// signature to invalidate anyway.
			resignable: false,
			wantFault:  chainbind.FaultSignatureUndecodable,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			audA, _ := newTestAudience(t, "alpha")
			audB, _ := newTestAudience(t, "bravo")
			p, pub, signer := sealAndSign(t, audA, audB)

			tc.mutate(p)
			if tc.resignable {
				resign(t, signer, p)
			}

			report, err := chainbind.Verify(context.Background(), p, verifyOpts(pub, newTestVerifier(t)))
			if err != nil {
				t.Fatalf("Verify returned a non-nil error %v; the real contract is a nil error and a failing report", err)
			}
			if !report.SpecVersionSupported {
				t.Fatal("SpecVersionSupported = false; spec_version itself was never mutated by this case")
			}
			if report.Signature {
				t.Fatal("Signature = true: L1.1 must abort before L1.2 ever runs, even on a validly re-signed package")
			}
			if report.CipherHashes != nil {
				t.Fatalf("CipherHashes = %v, want nil: L1.1 must abort before L1.4 ever runs", report.CipherHashes)
			}
			if report.Structural != tc.wantFault {
				t.Fatalf("Structural = %v, want %v", report.Structural, tc.wantFault)
			}
			if report.Level1() {
				t.Fatal("Level1() = true for a structurally malformed package")
			}
			if report.OK() {
				t.Fatal("OK() = true for a structurally malformed package")
			}
		})
	}
}
