package chainbind

import (
	"context"
	"encoding/base64"
)

// Open recovers exactly one segment's plaintext, given the recipient's own
// X25519 private key. It is the recipient's own act: possession of priv is
// the only gate, and there is no parameter naming which segment to open —
// the audience is derived by matching the thumbprint of priv's public half
// against cnf[a].jkt. There is deliberately no way to ask Open to open a
// segment by name.
//
// Open runs entirely offline: it depends on w alone, never dials a network,
// and opt.Intent — the live authorization check Verify's Level 2 would run
// — is ignored. A caller who also wants to know the package is bound to a
// live authorization runs Verify itself and reads Report.OK(). opt.IssuerKey
// and opt.BindingSpecs are still used: Open must verify the package's
// integrity in full, exactly as Verify's Level 1 does, before it recovers
// any data key.
//
// A wrong key, a tampered ciphertext, a spliced segment and a mismatched
// AAD are indistinguishable to the caller: every failure from the point
// priv's audience is being resolved onward returns the same
// ErrDecryptionFailed sentinel. Only two failures are reported more
// specifically, and neither leaks anything a wrong key could not already
// tell an attacker just by trying: ErrIntegrityCheckFailed when Level 1 did
// not pass at all, and ErrHashMismatch when the recovered plaintext does not
// match the signed plain_hash — a check only Open, holding the plaintext,
// can make.
//
// On any failure Open returns ("", nil, err): never a DEK, never an epk,
// never another segment's anything.
func Open(ctx context.Context, p *Package, priv []byte, w KeyWrapper, opt VerifyOptions) (string, []byte, error) {
	report, err := Verify(ctx, p, VerifyOptions{
		IssuerKey:    opt.IssuerKey,
		BindingSpecs: opt.BindingSpecs,
	})
	if err != nil {
		return "", nil, err
	}
	if !report.Level1() {
		return "", nil, ErrIntegrityCheckFailed
	}

	// From here on, p is known non-nil and structurally sound (Level 1
	// passed), but the audience match itself is not a authorization
	// decision: it is a cryptographic fact about which key was supplied.
	audience, ok := matchingAudience(p.CNF, w, priv)
	if !ok {
		return "", nil, ErrDecryptionFailed
	}

	seg, ok := p.Manifest.Segments[audience]
	if !ok {
		return "", nil, ErrDecryptionFailed
	}
	sealed, ok := p.Segments[audience]
	if !ok {
		return "", nil, ErrDecryptionFailed
	}

	wire, err := decodeSealedSegment(sealed)
	if err != nil {
		return "", nil, ErrDecryptionFailed
	}

	dek, err := w.Unwrap(ctx, priv, wire.epk, wire.wrapped)
	if err != nil {
		return "", nil, ErrDecryptionFailed
	}
	defer zero(dek)

	aad, err := AAD(p.Manifest.AADContext, audience, p.SpecVersion)
	if err != nil {
		return "", nil, ErrDecryptionFailed
	}

	// crypto.go's Decrypt expects GCM's combined ciphertext-plus-tag form,
	// the same shape Encrypt returned at Seal — recombine before opening.
	combined := make([]byte, 0, len(wire.ciphertext)+len(wire.tag))
	combined = append(combined, wire.ciphertext...)
	combined = append(combined, wire.tag...)

	plaintext, err := Decrypt(dek, wire.nonce, combined, aad)
	if err != nil {
		return "", nil, ErrDecryptionFailed
	}

	// plain_hash is the one check only Open can make, because it needs the
	// plaintext. Recomputed exactly as sealSegment computed it:
	// H(JCS(plaintext)).
	canonPlain, err := JCS(plaintext)
	if err != nil {
		return "", nil, ErrHashMismatch
	}
	if H(canonPlain) != seg.PlainHash {
		return "", nil, ErrHashMismatch
	}

	return audience, plaintext, nil
}

// matchingAudience derives priv's public half and its thumbprint through w,
// then finds the single audience in cnf whose jkt equals it. There is no
// segment-name parameter anywhere in this call chain — a caller that could
// name its segment would turn a cryptographic match into an access-control
// decision. Zero matches and more than one match — a malformed
// package with two audiences sharing a thumbprint — both fail the same way:
// neither is treated as more informative than the other.
func matchingAudience(cnf CNF, w KeyWrapper, priv []byte) (string, bool) {
	pub, err := w.PublicKey(priv)
	if err != nil {
		return "", false
	}
	jkt, err := w.Thumbprint(pub)
	if err != nil {
		return "", false
	}

	match := ""
	found := 0
	for name, conf := range cnf {
		if conf.JKT == jkt {
			match = name
			found++
		}
	}
	if found != 1 {
		return "", false
	}
	return match, true
}

// sealedSegmentWire holds sealed's fields decoded from base64, grouped into
// one value so decodeSealedSegment stays under gocritic's result-count
// limit.
type sealedSegmentWire struct {
	epk        []byte
	wrapped    []byte
	nonce      []byte
	ciphertext []byte
	tag        []byte
}

// decodeSealedSegment base64-decodes every field of sealed that Open needs
// to unwrap the data key and reopen the ciphertext.
func decodeSealedSegment(sealed SealedSegment) (sealedSegmentWire, error) {
	epk, err := base64.RawURLEncoding.DecodeString(sealed.EPK.X)
	if err != nil {
		return sealedSegmentWire{}, err
	}
	wrapped, err := base64.RawURLEncoding.DecodeString(sealed.DEKWrapped)
	if err != nil {
		return sealedSegmentWire{}, err
	}
	nonce, err := base64.RawURLEncoding.DecodeString(sealed.Nonce)
	if err != nil {
		return sealedSegmentWire{}, err
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(sealed.Ciphertext)
	if err != nil {
		return sealedSegmentWire{}, err
	}
	tag, err := base64.RawURLEncoding.DecodeString(sealed.Tag)
	if err != nil {
		return sealedSegmentWire{}, err
	}
	return sealedSegmentWire{epk: epk, wrapped: wrapped, nonce: nonce, ciphertext: ciphertext, tag: tag}, nil
}
