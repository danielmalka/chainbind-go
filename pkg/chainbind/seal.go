package chainbind

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// gcmTagSize is the length in bytes of the AES-256-GCM authentication tag
// crypto/cipher appends to every Encrypt call's output (crypto.go's default
// GCM construction). Seal needs it to split the combined ciphertext-plus-
// tag Encrypt returns into the wire format's separate ciphertext and tag
// fields — after hashing the combined form, since cipher_hash covers both.
const gcmTagSize = 16

// packageIDBytes is the crypto/rand entropy behind a package_id (128 bits):
// enough that two calls sealing identical input still produce distinct,
// unpredictable identifiers.
const packageIDBytes = 16

// segmentAlg and segmentWrapAlg are the fixed algorithm identifiers this
// build stamps into every manifest segment entry.
const (
	segmentAlg     = "AES-256-GCM"
	segmentWrapAlg = "ECDH-ES+A256KW"
)

// signatureAlg is the fixed algorithm identifier for the issuer signature.
const signatureAlg = "EdDSA"

// manifestSchema and manifestCanonicalization are fixed wire constants
// (testdata/package-example-v1.json).
const (
	manifestSchema           = "chainbind-package/v1"
	manifestHashAlg          = "SHA-256"
	manifestCanonicalization = "RFC8785"
)

// Sentinel errors specific to Seal's request validation. Static strings
// only.
var (
	// ErrNoAudiences is returned when a SealRequest names no audiences. A
	// package with no segments would be a signed statement about nothing.
	ErrNoAudiences = errors.New("chainbind: seal requires at least one audience")

	// ErrDuplicateAudience is returned when two entries in
	// SealRequest.Audiences share the same name.
	ErrDuplicateAudience = errors.New("chainbind: seal: duplicate audience name")

	// ErrSegmentMissing is returned when SealRequest.Segments has no
	// plaintext entry for a named audience.
	ErrSegmentMissing = errors.New("chainbind: seal: missing segment plaintext for audience")
)

// Audience is one named recipient a package is sealed to. The core places
// no meaning on Name beyond using it as a map/manifest key; callers and
// profiles choose their own vocabulary.
type Audience struct {
	// Name identifies the audience across cnf, manifest.segments and
	// segments. Must be unique within a SealRequest.
	Name string
	// PublicKey is the audience's X25519 public key (32 bytes) — the key
	// its segment's data-encryption key is wrapped to.
	PublicKey []byte
	// Kid identifies, for the audience's own bookkeeping, which key this
	// is. Recorded verbatim in manifest.segments[a].kid and cnf[a].kid;
	// the core never interprets it.
	Kid string
}

// SealRequest is the input to Seal. By the time it reaches Seal the payload
// has already been split into per-audience plaintext segments — the split
// itself is a profile's job and out of scope here.
type SealRequest struct {
	// Segments holds the plaintext for each audience, keyed by
	// Audience.Name.
	Segments map[string][]byte
	// SegmentOrder fixes the order segments_root commits to. Must name
	// exactly the audiences in Audiences/Segments, each once.
	SegmentOrder []string
	// Audiences are the named recipients the package is sealed to. Must
	// be non-empty (ErrNoAudiences otherwise).
	Audiences []Audience

	// IntentRef identifies the immutable authorization version this
	// execution is checked, and later bound, against.
	IntentRef string
	// Authority is recorded verbatim in intent.authority: an
	// informational identifier for which authority IntentRef is checked
	// against (e.g. its base URL). The core never dials it; iv does.
	Authority string
	// Projection is what Seal sends to IntentVerifier.Check: only the
	// fields the authority's policy needs. Building it from a domain
	// payload is a profile's job; the core forwards it opaquely.
	Projection any

	// Issuer identifies who is sealing the package (issuer.iss). The
	// signing key's kid is filled in by Seal from Signer.Sign.
	Issuer string
	// IssuedAt is stamped into the package and into the signing view.
	IssuedAt time.Time

	// TenantID and Environment are the caller-supplied half of the AAD
	// context; Seal fills in package_id itself.
	TenantID    string
	Environment string

	// Profile names which profile shaped Segments, for the wire
	// "profile" field. Empty for core-only use.
	Profile string
	// BindingSpecs are additional, profile-supplied bindings computed
	// and attached under bindings.Extra. Nil for core-only use.
	BindingSpecs []BindingSpec
}

// Seal turns req into a signed *Package.
//
// It asks iv whether the execution is authorized before generating any
// data-encryption key or encrypting any byte: a denial surfaces the
// authority's own reason (wrapped in ErrIntentDenied), and an unreachable
// authority fails closed with no package returned and no fallback — the
// deliberate asymmetric counterpart of Verify's "indeterminate" outcome.
//
// Every audience's segment is then encrypted under its own fresh DEK,
// wrapped to its own public key, and the whole manifest, bindings, cnf and
// package id are signed together as one unit.
func Seal(ctx context.Context, req SealRequest, s Signer, w KeyWrapper, iv IntentVerifier) (*Package, error) {
	if len(req.Audiences) == 0 {
		return nil, ErrNoAudiences
	}
	if err := checkAudiences(req); err != nil {
		return nil, err
	}

	// The authority is consulted before any DEK exists or any byte is
	// encrypted. A denial and an unreachable authority are both refusals
	// to seal; neither ever falls back to sealing unverified.
	decision, err := iv.Check(ctx, req.IntentRef, req.Projection)
	if err != nil {
		return nil, fmt.Errorf("chainbind: seal: intent authority unreachable: %w", err)
	}
	if !decision.Allowed {
		return nil, fmt.Errorf("chainbind: seal: %w: %s", ErrIntentDenied, decision.Reason)
	}

	// constraints_hash comes from the authority, never from the request:
	// it is what intent_commitment binds to, and it too is fetched before
	// any ciphertext exists.
	constraintsHash, err := iv.ConstraintsHash(ctx, req.IntentRef)
	if err != nil {
		return nil, fmt.Errorf("chainbind: seal: intent authority unreachable: %w", err)
	}

	packageID, err := newPackageID()
	if err != nil {
		return nil, fmt.Errorf("chainbind: seal: %w", err)
	}

	aadCtx := AADContext{
		PackageID:   packageID,
		TenantID:    req.TenantID,
		Environment: req.Environment,
	}

	plainHash := make(map[string]string, len(req.Audiences))
	manifestSegments := make(map[string]Segment, len(req.Audiences))
	sealedSegments := make(map[string]SealedSegment, len(req.Audiences))
	cnf := make(CNF, len(req.Audiences))

	for _, aud := range req.Audiences {
		seg, sealed, ph, err := sealSegment(ctx, w, aadCtx, aud, req.Segments[aud.Name])
		if err != nil {
			return nil, fmt.Errorf("chainbind: seal: audience %q: %w", aud.Name, err)
		}

		jkt, err := w.Thumbprint(aud.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("chainbind: seal: audience %q: %w", aud.Name, err)
		}

		plainHash[aud.Name] = ph
		manifestSegments[aud.Name] = seg
		sealedSegments[aud.Name] = sealed
		cnf[aud.Name] = KeyConfirmation{Kid: aud.Kid, JKT: jkt, Method: "jwk-thumbprint"}
	}

	segmentsRoot, err := SegmentsRoot(req.SegmentOrder, plainHash)
	if err != nil {
		return nil, fmt.Errorf("chainbind: seal: %w", err)
	}
	intentCommitment, err := IntentCommitment(req.IntentRef, constraintsHash, segmentsRoot)
	if err != nil {
		return nil, fmt.Errorf("chainbind: seal: %w", err)
	}

	extra, err := ComputeBindings(BindingContext{
		PlainHash:       plainHash,
		IntentRef:       req.IntentRef,
		ConstraintsHash: constraintsHash,
		SegmentsRoot:    segmentsRoot,
	}, req.BindingSpecs)
	if err != nil {
		return nil, fmt.Errorf("chainbind: seal: %w", err)
	}

	p := Package{
		SpecVersion: SupportedSpecVersion,
		Profile:     req.Profile,
		PackageID:   packageID,
		IssuedAt:    req.IssuedAt,
		Issuer:      Issuer{Iss: req.Issuer},
		Intent: Intent{
			IntentRef:       req.IntentRef,
			Authority:       req.Authority,
			ConstraintsHash: constraintsHash,
		},
		CNF: cnf,
		Bindings: Bindings{
			SegmentsRoot:     segmentsRoot,
			IntentCommitment: intentCommitment,
			Extra:            extra,
		},
		Manifest: Manifest{
			Schema:           manifestSchema,
			HashAlg:          manifestHashAlg,
			Canonicalization: manifestCanonicalization,
			SegmentOrder:     req.SegmentOrder,
			AADContext:       aadCtx,
			Segments:         manifestSegments,
		},
		Segments: sealedSegments,
	}

	if err := signPackage(ctx, s, &p); err != nil {
		return nil, fmt.Errorf("chainbind: seal: %w", err)
	}

	return &p, nil
}

// checkAudiences validates SealRequest.Audiences/Segments before any DEK is
// generated: every name is unique, and every audience has a plaintext
// segment to encrypt.
func checkAudiences(req SealRequest) error {
	seen := make(map[string]struct{}, len(req.Audiences))
	for _, aud := range req.Audiences {
		if _, dup := seen[aud.Name]; dup {
			return fmt.Errorf("%w: %q", ErrDuplicateAudience, aud.Name)
		}
		seen[aud.Name] = struct{}{}

		if _, ok := req.Segments[aud.Name]; !ok {
			return fmt.Errorf("%w: %q", ErrSegmentMissing, aud.Name)
		}
	}
	return nil
}

// sealSegment encrypts one audience's plaintext and wraps its DEK, and
// returns the manifest entry, the wire segment, and the plaintext hash.
func sealSegment(ctx context.Context, w KeyWrapper, aadCtx AADContext, aud Audience, plaintext []byte) (Segment, SealedSegment, string, error) {
	dek, err := NewDEK()
	if err != nil {
		return Segment{}, SealedSegment{}, "", err
	}
	defer zero(dek)

	aad, err := AAD(aadCtx, aud.Name, SupportedSpecVersion)
	if err != nil {
		return Segment{}, SealedSegment{}, "", err
	}

	combined, nonce, err := Encrypt(dek, plaintext, aad)
	if err != nil {
		return Segment{}, SealedSegment{}, "", err
	}
	if len(combined) < gcmTagSize {
		return Segment{}, SealedSegment{}, "", ErrDecryptionFailed
	}
	// cipher_hash covers the combined ciphertext-plus-tag Encrypt
	// produced — hashed before it is split into the wire format's
	// separate ciphertext and tag fields below.
	cipherHash := H(combined)
	ciphertext := combined[:len(combined)-gcmTagSize]
	tag := combined[len(combined)-gcmTagSize:]

	canonPlain, err := JCS(plaintext)
	if err != nil {
		return Segment{}, SealedSegment{}, "", err
	}
	plainHash := H(canonPlain)

	wrapped, epk, err := w.Wrap(ctx, aud.PublicKey, dek)
	if err != nil {
		return Segment{}, SealedSegment{}, "", err
	}

	seg := Segment{
		Audience:   aud.Name,
		Kid:        aud.Kid,
		Alg:        segmentAlg,
		WrapAlg:    segmentWrapAlg,
		PlainHash:  plainHash,
		CipherHash: cipherHash,
	}
	sealed := SealedSegment{
		EPK: EPK{
			Kty: "OKP",
			Crv: "X25519",
			X:   base64.RawURLEncoding.EncodeToString(epk),
		},
		DEKWrapped: base64.RawURLEncoding.EncodeToString(wrapped),
		Nonce:      base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext),
		Tag:        base64.RawURLEncoding.EncodeToString(tag),
	}
	return seg, sealed, plainHash, nil
}

// signPackage fills p.Issuer.Kid and p.Signature. The kid is asked for
// before the view is built, because issuer.kid sits inside the view and the
// signature must commit to the identity of the key that produced it. Sign
// is called exactly once, over exactly the bytes the package claims were
// signed.
func signPackage(ctx context.Context, s Signer, p *Package) error {
	kid, err := s.Kid(ctx)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	p.Issuer.Kid = kid

	view, err := BuildSigningView(*p)
	if err != nil {
		return err
	}

	sig, err := s.Sign(ctx, view)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}

	p.Signature = Signature{
		Alg:          signatureAlg,
		Kid:          kid,
		SignedFields: RequiredSignedFields,
		Value:        EncodeSignatureValue(sig),
	}
	return nil
}

// newPackageID generates a fresh, unpredictable package_id from
// crypto/rand — never a counter, never derived from the current time.
func newPackageID() (string, error) {
	buf := make([]byte, packageIDBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate package_id: %w", err)
	}
	return "pkg_" + hex.EncodeToString(buf), nil
}

// zero overwrites b in place. Best-effort hygiene for a DEK once Seal is
// done with it; it does not defend against a copy the Go runtime may have
// made (e.g. during a GC move), which is a limitation of doing this in Go
// at all rather than something this call papers over.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
