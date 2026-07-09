package chainbind

import (
	"encoding/base64"
	"fmt"
)

// RequiredSignedFields are the nine field names TECHSPEC-001 §6.4 defines
// for this spec version's signing view, in the order stated there:
//
//	signing_view = JCS({spec_version, profile, package_id, issued_at,
//	                    issuer, intent, cnf, bindings, manifest})
//
// JCS sorts object keys, so this Go slice order has no effect on the
// resulting bytes; it exists for readability and as the value Seal (a
// later task) stamps into signature.signed_fields.
var RequiredSignedFields = []string{
	"spec_version", "profile", "package_id", "issued_at",
	"issuer", "intent", "cnf", "bindings", "manifest",
}

// signingViewFields maps every signing-view field name this spec version
// knows to the value it names in p. It is the single place BuildSigningView
// and ReconstructSigningView reach into Package, so adding a signed field
// later is one map entry instead of two. segments is deliberately absent:
// the ciphertexts are covered only transitively through
// manifest.segments[a].cipher_hash (architecture invariant 2).
func signingViewFields(p Package) map[string]any {
	return map[string]any{
		"spec_version": p.SpecVersion,
		"profile":      p.Profile,
		"package_id":   p.PackageID,
		"issued_at":    p.IssuedAt,
		"issuer":       p.Issuer,
		"intent":       p.Intent,
		"cnf":          p.CNF,
		"bindings":     p.Bindings,
		"manifest":     p.Manifest,
	}
}

// BuildSigningView builds the canonical signing view for p: JCS over
// exactly the nine fields TECHSPEC-001 §6.4 names. Callers sign the
// returned bytes with a Signer and stamp RequiredSignedFields into
// signature.signed_fields (Seal, a later task).
func BuildSigningView(p Package) ([]byte, error) {
	view := selectFields(signingViewFields(p), RequiredSignedFields)
	canon, err := JCS(view)
	if err != nil {
		return nil, fmt.Errorf("chainbind: signing view: %w", err)
	}
	return canon, nil
}

// ReconstructSigningView rebuilds the signing view a verifier checks a
// signature against. It is driven by p.Signature.SignedFields, not by a
// hardcoded list (TECHSPEC-001 §6.5 L1.2), but it first rejects any
// signed_fields that is not exactly the nine required names in some order:
// one missing, one repeated, or one unrecognised. Without that check an
// attacker could drop a name (e.g. bindings) from signed_fields and the
// signature would verify over a view that silently omits it.
func ReconstructSigningView(p Package) ([]byte, error) {
	if err := checkSignedFields(p.Signature.SignedFields); err != nil {
		return nil, err
	}
	view := selectFields(signingViewFields(p), p.Signature.SignedFields)
	canon, err := JCS(view)
	if err != nil {
		return nil, fmt.Errorf("chainbind: signing view: %w", err)
	}
	return canon, nil
}

// checkSignedFields reports ErrMalformedPackage unless names is exactly a
// permutation of RequiredSignedFields, with no name missing, repeated, or
// unrecognised.
func checkSignedFields(names []string) error {
	if len(names) != len(RequiredSignedFields) {
		return fmt.Errorf("%w: signed_fields has %d names, want %d", ErrMalformedPackage, len(names), len(RequiredSignedFields))
	}

	required := make(map[string]struct{}, len(RequiredSignedFields))
	for _, n := range RequiredSignedFields {
		required[n] = struct{}{}
	}

	seen := make(map[string]struct{}, len(names))
	for _, n := range names {
		if _, ok := required[n]; !ok {
			return fmt.Errorf("%w: signed_fields contains unrecognised name %q", ErrMalformedPackage, n)
		}
		if _, dup := seen[n]; dup {
			return fmt.Errorf("%w: signed_fields lists %q more than once", ErrMalformedPackage, n)
		}
		seen[n] = struct{}{}
	}
	return nil
}

// selectFields returns the subset of fields named by names, keyed by name.
// The result is a map, so its own key order is irrelevant to the caller;
// json.Marshal sorts map[string]any keys, and JCS sorts them again per RFC
// 8785 regardless. This is what makes signed_fields order-insensitive: a
// permutation of the same nine names selects the same map and therefore
// produces byte-identical signing-view output.
func selectFields(fields map[string]any, names []string) map[string]any {
	out := make(map[string]any, len(names))
	for _, n := range names {
		out[n] = fields[n]
	}
	return out
}

// EncodeSignatureValue encodes an Ed25519 signature as base64url, unpadded
// (RFC 4648 §5), matching JOSE and TECHSPEC-001 §6.4's
// signature.value = base64url(Ed25519.Sign(issuer_sk, signing_view)).
func EncodeSignatureValue(sig []byte) string {
	return base64.RawURLEncoding.EncodeToString(sig)
}

// DecodeSignatureValue decodes a signature.value string produced by
// EncodeSignatureValue back into raw Ed25519 signature bytes.
func DecodeSignatureValue(s string) ([]byte, error) {
	sig, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("chainbind: decode signature value: %w", err)
	}
	return sig, nil
}
