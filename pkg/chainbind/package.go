package chainbind

import (
	"encoding/json"
	"fmt"
	"time"
)

// SupportedSpecVersion is the only package format version this build
// understands. Seal stamps it; Verify refuses anything else at its first
// gate.
const SupportedSpecVersion = "1.0.0"

// CheckSpecVersion reports ErrUnsupportedSpecVersion if v is not the
// version this build recognises. It is the version-gate half of Verify's
// L1.1 check, usable in isolation before the rest of a package is parsed.
func CheckSpecVersion(v string) error {
	if v != SupportedSpecVersion {
		return fmt.Errorf("%w: %q", ErrUnsupportedSpecVersion, v)
	}
	return nil
}

// Package is the sealed wire format: one issuer signature over a manifest
// that carries every hash a verifier needs, plus one encrypted segment per
// audience. Field names and JSON tags match docs/package-example-v1.json.
type Package struct {
	SpecVersion string                   `json:"spec_version"`
	Profile     string                   `json:"profile"`
	PackageID   string                   `json:"package_id"`
	IssuedAt    time.Time                `json:"issued_at"`
	Issuer      Issuer                   `json:"issuer"`
	Intent      Intent                   `json:"intent"`
	CNF         CNF                      `json:"cnf"`
	Bindings    Bindings                 `json:"bindings"`
	Manifest    Manifest                 `json:"manifest"`
	Segments    map[string]SealedSegment `json:"segments"`
	Signature   Signature                `json:"signature"`
}

// Issuer identifies who signed the package and which key they used.
type Issuer struct {
	Iss string `json:"iss"`
	Kid string `json:"kid"`
}

// Intent links the package to the authorization that permitted it.
type Intent struct {
	IntentRef       string `json:"intent_ref"`
	Authority       string `json:"authority"`
	ConstraintsHash string `json:"constraints_hash"`
}

// KeyConfirmation ("cnf") lets Open find which audience a private key
// belongs to, by comparing the key's thumbprint against jkt.
type KeyConfirmation struct {
	Kid    string `json:"kid"`
	JKT    string `json:"jkt"`
	Method string `json:"method"`
}

// CNF maps an arbitrary, caller-supplied audience name to its key
// confirmation. The core places no restriction on the names used here.
type CNF map[string]KeyConfirmation

// Bindings carries the two core, data-driven commitments every package
// signs: segments_root and intent_commitment. A profile may attach further
// named aliases; those ride in Extra and are flattened into the same JSON
// object on the wire, so the core never has to name them.
type Bindings struct {
	SegmentsRoot     string
	IntentCommitment string
	Extra            map[string]string
}

const (
	bindingsFieldSegmentsRoot     = "segments_root"
	bindingsFieldIntentCommitment = "intent_commitment"
)

// MarshalJSON flattens the core fields and Extra into one JSON object. A
// profile-supplied Extra key named segments_root or intent_commitment is
// rejected rather than silently overwritten or dropped: those two names are
// core bindings, and a signed package whose segments_root came from an
// untrusted profile map would be a real vulnerability, not a quirk.
func (b Bindings) MarshalJSON() ([]byte, error) {
	if _, collides := b.Extra[bindingsFieldSegmentsRoot]; collides {
		return nil, fmt.Errorf("%w: %q", ErrBindingCollision, bindingsFieldSegmentsRoot)
	}
	if _, collides := b.Extra[bindingsFieldIntentCommitment]; collides {
		return nil, fmt.Errorf("%w: %q", ErrBindingCollision, bindingsFieldIntentCommitment)
	}

	m := make(map[string]string, len(b.Extra)+2)
	for k, v := range b.Extra {
		m[k] = v
	}
	m[bindingsFieldSegmentsRoot] = b.SegmentsRoot
	m[bindingsFieldIntentCommitment] = b.IntentCommitment

	out, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("chainbind: marshal bindings: %w", err)
	}
	return out, nil
}

// UnmarshalJSON splits the core fields out of the object; every other key
// lands in Extra.
func (b *Bindings) UnmarshalJSON(data []byte) error {
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("chainbind: unmarshal bindings: %w", err)
	}

	b.SegmentsRoot = m[bindingsFieldSegmentsRoot]
	b.IntentCommitment = m[bindingsFieldIntentCommitment]
	delete(m, bindingsFieldSegmentsRoot)
	delete(m, bindingsFieldIntentCommitment)

	if len(m) > 0 {
		b.Extra = m
	} else {
		b.Extra = nil
	}
	return nil
}

// AADContext is the caller-supplied part of the additional authenticated
// data every segment's AES-256-GCM seal is bound to.
type AADContext struct {
	PackageID   string `json:"package_id"`
	TenantID    string `json:"tenant_id"`
	Environment string `json:"environment"`
}

// Segment is one audience's entry in manifest.segments: the metadata a
// verifier checks without holding any key.
type Segment struct {
	Audience   string `json:"audience"`
	Kid        string `json:"kid"`
	Alg        string `json:"alg"`
	WrapAlg    string `json:"wrap_alg"`
	PlainHash  string `json:"plain_hash"`
	CipherHash string `json:"cipher_hash"`
}

// Manifest is the signed description of every segment: how they were
// produced, in what order, and under what AAD context.
type Manifest struct {
	Schema           string             `json:"schema"`
	HashAlg          string             `json:"hash_alg"`
	Canonicalization string             `json:"canonicalization"`
	SegmentOrder     []string           `json:"segment_order"`
	AADContext       AADContext         `json:"aad_context"`
	Segments         map[string]Segment `json:"segments"`
	// Disclosures is an empty region owned by feature 002. It already
	// lives inside the signed view so a later feature can populate it
	// without changing the view's shape or breaking existing verifiers.
	// It always serializes as [], never null.
	Disclosures []any `json:"disclosures"`
}

// MarshalJSON defaults Disclosures to [] so a zero-value Manifest still
// serializes the empty region correctly.
func (m Manifest) MarshalJSON() ([]byte, error) {
	type alias Manifest
	a := alias(m)
	if a.Disclosures == nil {
		a.Disclosures = []any{}
	}

	out, err := json.Marshal(a)
	if err != nil {
		return nil, fmt.Errorf("chainbind: marshal manifest: %w", err)
	}
	return out, nil
}

// EPK is the ephemeral public key used to wrap one segment's DEK.
type EPK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
}

// SealedSegment is one audience's encrypted payload: the top-level
// "segments" entry, distinct from its manifest metadata in Segment.
type SealedSegment struct {
	EPK        EPK    `json:"epk"`
	DEKWrapped string `json:"dek_wrapped"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	Tag        string `json:"tag"`
}

// Signature is the issuer's Ed25519 signature over the signing view built
// from the fields named in SignedFields.
type Signature struct {
	Alg          string   `json:"alg"`
	Kid          string   `json:"kid"`
	SignedFields []string `json:"signed_fields"`
	Value        string   `json:"value"`
}
