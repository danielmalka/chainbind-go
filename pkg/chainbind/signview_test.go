package chainbind

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// samplePackage returns a Package with every signing-view field populated
// with distinct, non-zero values, so a mutation test can tell fields
// apart. segments (ciphertext) is populated too, precisely so tests can
// prove it does NOT affect the signing view.
func samplePackage() Package {
	return Package{
		SpecVersion: SupportedSpecVersion,
		Profile:     "test-profile/v1",
		PackageID:   "pkg_test_0001",
		IssuedAt:    time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC),
		Issuer:      Issuer{Iss: "chainbind-go", Kid: "issuer-key-1"},
		Intent: Intent{
			IntentRef:       "int_0001",
			Authority:       "https://authority.local/v1",
			ConstraintsHash: "sha256:aaaa",
		},
		CNF: CNF{
			"a": {Kid: "key-a", JKT: "jkt-a", Method: "jwk-thumbprint"},
			"b": {Kid: "key-b", JKT: "jkt-b", Method: "jwk-thumbprint"},
		},
		Bindings: Bindings{
			SegmentsRoot:     "sha256:bbbb",
			IntentCommitment: "ctx:sha256:cccc",
		},
		Manifest: Manifest{
			Schema:           "chainbind-package/v1",
			HashAlg:          "SHA-256",
			Canonicalization: "RFC8785",
			SegmentOrder:     []string{"a", "b"},
			AADContext:       AADContext{PackageID: "pkg_test_0001", TenantID: "t1", Environment: "dev"},
			Segments: map[string]Segment{
				"a": {Audience: "a", Kid: "key-a", Alg: "AES-256-GCM", WrapAlg: "ECDH-ES+A256KW", PlainHash: "sha256:1111", CipherHash: "sha256:2222"},
				"b": {Audience: "b", Kid: "key-b", Alg: "AES-256-GCM", WrapAlg: "ECDH-ES+A256KW", PlainHash: "sha256:3333", CipherHash: "sha256:4444"},
			},
		},
		Segments: map[string]SealedSegment{
			"a": {EPK: EPK{Kty: "OKP", Crv: "X25519", X: "epk-a"}, DEKWrapped: "dek-a", Nonce: "nonce-a", Ciphertext: "cipher-a", Tag: "tag-a"},
			"b": {EPK: EPK{Kty: "OKP", Crv: "X25519", X: "epk-b"}, DEKWrapped: "dek-b", Nonce: "nonce-b", Ciphertext: "cipher-b", Tag: "tag-b"},
		},
		Signature: Signature{
			Alg:          "EdDSA",
			Kid:          "issuer-key-1",
			SignedFields: append([]string(nil), RequiredSignedFields...),
		},
	}
}

func TestBuildSigningView_ContainsExactlyNineFieldsNotSegments(t *testing.T) {
	p := samplePackage()

	view, err := BuildSigningView(p)
	if err != nil {
		t.Fatalf("BuildSigningView: %v", err)
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(view, &obj); err != nil {
		t.Fatalf("unmarshal signing view: %v", err)
	}

	if len(obj) != len(RequiredSignedFields) {
		t.Fatalf("signing view has %d top-level fields, want %d: %v", len(obj), len(RequiredSignedFields), keysOf(obj))
	}
	for _, name := range RequiredSignedFields {
		if _, ok := obj[name]; !ok {
			t.Fatalf("signing view missing required field %q", name)
		}
	}
	if _, ok := obj["segments"]; ok {
		t.Fatalf("signing view contains segments, which must be excluded (architecture invariant 2)")
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestBuildSigningView_DeterministicAcrossCalls(t *testing.T) {
	p := samplePackage()

	first, err := BuildSigningView(p)
	if err != nil {
		t.Fatalf("BuildSigningView (first): %v", err)
	}
	second, err := BuildSigningView(p)
	if err != nil {
		t.Fatalf("BuildSigningView (second): %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("signing view not byte-identical across two builds of the same package")
	}
}

func TestBuildSigningView_ChangesWhenSignedFieldMutates(t *testing.T) {
	base := samplePackage()
	baseView, err := BuildSigningView(base)
	if err != nil {
		t.Fatalf("BuildSigningView(base): %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Package)
	}{
		{"spec_version", func(p *Package) { p.SpecVersion = "9.9.9" }},
		{"profile", func(p *Package) { p.Profile = "other-profile/v1" }},
		{"package_id", func(p *Package) { p.PackageID = "pkg_other" }},
		{"issued_at", func(p *Package) { p.IssuedAt = p.IssuedAt.Add(time.Hour) }},
		{"issuer", func(p *Package) { p.Issuer.Kid = "other-key" }},
		{"intent", func(p *Package) { p.Intent.ConstraintsHash = "sha256:zzzz" }},
		{"cnf", func(p *Package) {
			p.CNF["a"] = KeyConfirmation{Kid: "changed", JKT: "changed", Method: "jwk-thumbprint"}
		}},
		{"bindings", func(p *Package) { p.Bindings.SegmentsRoot = "sha256:changed" }},
		{"manifest (segment_order)", func(p *Package) { p.Manifest.SegmentOrder = []string{"b", "a"} }},
		{"manifest (a segment's plain_hash)", func(p *Package) {
			seg := p.Manifest.Segments["a"]
			seg.PlainHash = "sha256:changed"
			p.Manifest.Segments["a"] = seg
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := samplePackage()
			tt.mutate(&p)

			view, err := BuildSigningView(p)
			if err != nil {
				t.Fatalf("BuildSigningView: %v", err)
			}
			if bytes.Equal(view, baseView) {
				t.Fatalf("mutating %s did not change the signing view", tt.name)
			}
		})
	}
}

func TestBuildSigningView_SegmentsMutationDoesNotChangeView(t *testing.T) {
	base := samplePackage()
	baseView, err := BuildSigningView(base)
	if err != nil {
		t.Fatalf("BuildSigningView(base): %v", err)
	}

	mutated := samplePackage()
	seg := mutated.Segments["a"]
	seg.Ciphertext = "totally-different-ciphertext"
	seg.Tag = "totally-different-tag"
	mutated.Segments["a"] = seg

	mutatedView, err := BuildSigningView(mutated)
	if err != nil {
		t.Fatalf("BuildSigningView(mutated): %v", err)
	}
	if !bytes.Equal(mutatedView, baseView) {
		t.Fatalf("mutating segments changed the signing view; segments must be excluded (architecture invariant 2)")
	}
}

func TestReconstructSigningView_MatchesBuildSigningView(t *testing.T) {
	p := samplePackage()

	built, err := BuildSigningView(p)
	if err != nil {
		t.Fatalf("BuildSigningView: %v", err)
	}
	reconstructed, err := ReconstructSigningView(p)
	if err != nil {
		t.Fatalf("ReconstructSigningView: %v", err)
	}
	if !bytes.Equal(built, reconstructed) {
		t.Fatalf("ReconstructSigningView produced different bytes than BuildSigningView")
	}
}

// TestReconstructSigningView_OrderInsensitive proves signature.signed_fields
// order does not matter: JCS sorts object keys, and selectFields builds a
// Go map (itself unordered) before handing it to JCS, so any permutation of
// the same nine names must reconstruct byte-identical output. This is safe
// precisely because JCS's key sort is exactly what makes struct/field
// ordering irrelevant everywhere else in this codebase (canonical.go).
func TestReconstructSigningView_OrderInsensitive(t *testing.T) {
	forward := samplePackage()
	forward.Signature.SignedFields = []string{
		"spec_version", "profile", "package_id", "issued_at",
		"issuer", "intent", "cnf", "bindings", "manifest",
	}

	reversed := samplePackage()
	reversed.Signature.SignedFields = []string{
		"manifest", "bindings", "cnf", "intent", "issuer",
		"issued_at", "package_id", "profile", "spec_version",
	}

	forwardView, err := ReconstructSigningView(forward)
	if err != nil {
		t.Fatalf("ReconstructSigningView(forward): %v", err)
	}
	reversedView, err := ReconstructSigningView(reversed)
	if err != nil {
		t.Fatalf("ReconstructSigningView(reversed): %v", err)
	}
	if !bytes.Equal(forwardView, reversedView) {
		t.Fatalf("permuting signed_fields changed the reconstructed view")
	}
}

func TestReconstructSigningView_RejectsBadSignedFields(t *testing.T) {
	tests := []struct {
		name         string
		signedFields []string
	}{
		{
			name:         "missing a required name (bindings dropped)",
			signedFields: []string{"spec_version", "profile", "package_id", "issued_at", "issuer", "intent", "cnf", "manifest"},
		},
		{
			name:         "unknown name added",
			signedFields: append(append([]string(nil), RequiredSignedFields...), "segments"),
		},
		{
			name:         "unknown name replaces a required one",
			signedFields: []string{"spec_version", "profile", "package_id", "issued_at", "issuer", "intent", "cnf", "bindings", "segments"},
		},
		{
			name:         "empty",
			signedFields: nil,
		},
		{
			name:         "a required name repeated instead of another",
			signedFields: []string{"spec_version", "spec_version", "package_id", "issued_at", "issuer", "intent", "cnf", "bindings", "manifest"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := samplePackage()
			p.Signature.SignedFields = tt.signedFields

			_, err := ReconstructSigningView(p)
			if err == nil {
				t.Fatalf("ReconstructSigningView with signed_fields=%v: got nil error, want one", tt.signedFields)
			}
			if !errors.Is(err, ErrMalformedPackage) {
				t.Fatalf("ReconstructSigningView error = %v, want errors.Is ErrMalformedPackage", err)
			}
		})
	}
}

func TestEncodeDecodeSignatureValue_RoundTrips(t *testing.T) {
	sig := []byte{0x00, 0x01, 0xff, 0x10, 0x20, 0x30}

	encoded := EncodeSignatureValue(sig)
	if encoded != "" && encoded[len(encoded)-1] == '=' {
		t.Fatalf("EncodeSignatureValue produced padded output: %q", encoded)
	}

	decoded, err := DecodeSignatureValue(encoded)
	if err != nil {
		t.Fatalf("DecodeSignatureValue: %v", err)
	}
	if !bytes.Equal(decoded, sig) {
		t.Fatalf("DecodeSignatureValue(EncodeSignatureValue(sig)) = %v, want %v", decoded, sig)
	}
}
