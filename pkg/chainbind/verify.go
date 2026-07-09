package chainbind

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
)

// IntentResult is the outcome of Level 2 — the authority-backed check
// (TECHSPEC-001 §6.5). Evaluated reports whether the authority was reached
// at all; Valid reports whether its answer matched the package's claim.
// Reason explains a false Valid or a false Evaluated, and — like every
// string this package produces — never carries a plaintext, a DEK, a key,
// or a ciphertext byte (architecture invariant 10).
type IntentResult struct {
	Evaluated bool
	Valid     bool
	Reason    string
}

// StructuralFault names the single reason Level 1 rejected a package before
// the signature was checked (TECHSPEC-001 §6.5, L1.1). It is a closed set:
// no value carries a byte from the package (architecture invariant 10).
type StructuralFault uint8

const (
	// FaultNone means L1.1 passed: the package parsed.
	FaultNone StructuralFault = iota
	// FaultEmptySignedFields means signature.signed_fields was empty.
	FaultEmptySignedFields
	// FaultEmptySegmentOrder means manifest.segment_order was empty.
	FaultEmptySegmentOrder
	// FaultSegmentCountMismatch means manifest.segments had a different
	// number of entries than manifest.segment_order.
	FaultSegmentCountMismatch
	// FaultDuplicateAudience means an audience was listed twice in
	// manifest.segment_order.
	FaultDuplicateAudience
	// FaultManifestSegmentMissing means an audience in segment_order had no
	// corresponding manifest.segments entry.
	FaultManifestSegmentMissing
	// FaultSealedSegmentMissing means an audience in segment_order had no
	// corresponding sealed segments entry.
	FaultSealedSegmentMissing
	// FaultSignedFieldsInvalid means signature.signed_fields does not name
	// the nine required fields exactly once each: a name is missing,
	// repeated, or unrecognised.
	FaultSignedFieldsInvalid
	// FaultSigningViewUnbuildable means signature.signed_fields was valid
	// but the signing view could not be canonicalized — for instance a
	// package whose bindings.Extra shadows a core binding name, which
	// Bindings.MarshalJSON refuses to encode.
	//
	// It is separate from FaultSignedFieldsInvalid because collapsing the
	// two would make Verify say "signed_fields is invalid" about a package
	// whose signed_fields is perfectly well formed. That is the same
	// species of lie this type exists to stop telling.
	FaultSigningViewUnbuildable
	// FaultSignatureUndecodable means signature.value was not valid
	// base64url.
	FaultSignatureUndecodable
)

// String returns a static, constant description of f. Every branch is a
// string literal — never a formatted package byte — so a Report is always
// safe to render (architecture invariant 10).
func (f StructuralFault) String() string {
	switch f {
	case FaultNone:
		return "no structural fault"
	case FaultEmptySignedFields:
		return "signature.signed_fields is empty"
	case FaultEmptySegmentOrder:
		return "manifest.segment_order is empty"
	case FaultSegmentCountMismatch:
		return "manifest.segments count does not match segment_order count"
	case FaultDuplicateAudience:
		return "an audience is listed twice in segment_order"
	case FaultManifestSegmentMissing:
		return "an audience in segment_order has no manifest.segments entry"
	case FaultSealedSegmentMissing:
		return "an audience in segment_order has no sealed segments entry"
	case FaultSignedFieldsInvalid:
		return "signature.signed_fields does not name the required fields"
	case FaultSigningViewUnbuildable:
		return "the signing view could not be canonicalized"
	case FaultSignatureUndecodable:
		return "signature value could not be decoded"
	default:
		return "unknown structural fault"
	}
}

// Report is Verify's complete answer: every check TECHSPEC-001 §6.5 defines,
// each recorded independently so a caller can tell which one failed. A field
// left at its zero value after an L1.1/L1.2 abort means "never evaluated",
// not "passed" — CipherHashes and ProfileBindings are nil maps, not empty
// ones, precisely so a caller can tell the difference.
type Report struct {
	SpecVersionSupported bool
	// Structural is FaultNone when L1.1 (the structural parse) passed. A
	// non-FaultNone value means every field below is unevaluated, not
	// failed — the same contract CipherHashes == nil already carries. It is
	// never set alongside a completed Signature check: L1.1 aborts before
	// L1.2 runs.
	Structural           StructuralFault
	Signature            bool
	AADContextConsistent bool
	// CipherHashes is keyed by audience name. It is nil when Level 1
	// aborted before L1.4 ran (a bad spec_version, a structural failure,
	// or an invalid signature).
	CipherHashes map[string]bool
	SegmentsRoot bool
	// ProfileBindings is keyed by BindingSpec.Name. It is nil when no
	// BindingSpecs were supplied to Verify, or when Level 1 aborted before
	// L1.6 ran.
	ProfileBindings map[string]bool
	Intent          IntentResult
}

// OK reports whether p verified completely: every Level 1 check passed,
// every supplied cipher hash and profile binding matched, and Level 2
// evaluated the intent authority and found it valid. There is no other path
// to true — in particular, an unevaluated intent level (a nil or
// unreachable authority) always makes OK false, never silently true
// (architecture invariant 5, D-011).
func (r *Report) OK() bool {
	if r == nil {
		return false
	}
	return level1Passed(r) && r.Intent.Evaluated && r.Intent.Valid
}

// Level1 reports whether every structural check passed: version, signature,
// AAD context, ciphertext hashes and bindings. It is what Open requires
// before it will recover a data key, and it is deliberately separate from
// OK: opening is offline, and the intent level is not an integrity property.
// A recipient who also wants to know the package is bound to a live
// authorization runs Verify and reads OK.
func (r *Report) Level1() bool {
	if r == nil {
		return false
	}
	return level1Passed(r)
}

// level1Passed reports whether every Level 1 check in r succeeded,
// including that CipherHashes was actually populated (non-nil, non-empty)
// rather than left at its post-abort zero value. It gates whether Level 2
// runs at all, and is also the non-intent half of Report.OK.
func level1Passed(r *Report) bool {
	// Redundant for any Report Verify produces: a structural fault makes
	// Verify return before CipherHashes is ever allocated, so the nil check
	// below already answers. It is here for the Report a caller builds
	// itself — every field of Report is exported — where a fault could
	// otherwise sit beside a full set of passing checks and be ignored.
	// Nothing on the Verify path exercises this branch; the test that pins
	// it hand-builds a Report, and says so.
	if r.Structural != FaultNone {
		return false
	}
	if !r.SpecVersionSupported || !r.Signature || !r.AADContextConsistent || !r.SegmentsRoot {
		return false
	}
	if len(r.CipherHashes) == 0 {
		return false
	}
	for _, ok := range r.CipherHashes {
		if !ok {
			return false
		}
	}
	for _, ok := range r.ProfileBindings {
		if !ok {
			return false
		}
	}
	return true
}

// VerifyOptions configures Verify.
type VerifyOptions struct {
	// IssuerKey resolves the issuer's public key from the caller's own
	// trust store. iss and kid are the values a package under
	// verification claims for itself (Package.Issuer.Iss/Kid) —
	// attacker-controlled input, not a source of trust. Verify passes
	// them through unchanged and uses only what IssuerKey returns; there
	// is no path by which a key travels from inside a Package to the
	// verification of that same package's signature. A false ok means the
	// key is not trusted, which is indistinguishable from — and handled
	// identically to — a bad signature.
	IssuerKey func(iss, kid string) (ed25519.PublicKey, bool)

	// Intent is the authority Level 2 checks against. A nil Intent means
	// the caller chose not to, or could not, reach an authority: Level 2
	// reports the intent level as unevaluated rather than being skipped
	// silently (architecture invariant 6).
	Intent IntentVerifier

	// BindingSpecs are the profile bindings L1.6 recomputes and compares
	// against Bindings.Extra. Nil for core-only use.
	BindingSpecs []BindingSpec
}

// Verify checks p against the two-level procedure in TECHSPEC-001 §6.5. It
// never decrypts, never opens a segment, and never touches a private key
// (architecture invariant 1) — Level 1 needs only the issuer's public key,
// and Level 2 needs only a reachable authority.
//
// Verify returns a non-nil error only when p cannot be processed at all (a
// nil package). Every other outcome — an unsupported spec_version, a bad
// signature, a mismatched hash, an unreachable authority — is a fully
// formed *Report with OK() == false and a nil error: failing verification
// is an answer, not an error.
func Verify(ctx context.Context, p *Package, opt VerifyOptions) (*Report, error) {
	if p == nil {
		return nil, ErrNilPackage
	}

	report := &Report{}

	// L1.1 — spec_version and structural parse. Abort on failure: before
	// the signature, every field is attacker-controlled, and there is
	// nothing gained by checking further (architecture invariant 3). Verify
	// never propagates these as a Go error — a malformed package is an
	// answer (an unverified *Report), not a failure to process the
	// request — so the checks below are boolean/enum-valued, not
	// error-returning. The reason a package failed to parse is now
	// reported, not discarded: report.Structural names exactly which
	// structural check failed.
	if !specVersionSupported(p.SpecVersion) {
		return report, nil
	}
	report.SpecVersionSupported = true

	view, sig, fault := parsePackage(*p)
	if fault != FaultNone {
		report.Structural = fault
		return report, nil
	}

	// L1.2 — trust and verify. Nothing here can fail structurally: parsing
	// already happened above.
	pub, trusted := resolveIssuerKey(opt.IssuerKey, p.Issuer.Iss, p.Issuer.Kid)
	if !trusted {
		return report, nil
	}
	if !verifyEd25519(pub, view, sig) {
		return report, nil
	}
	report.Signature = true

	// Everything from here on accumulates: the content is now attested by
	// the issuer, so Verify reports every divergence instead of stopping
	// at the first.

	// L1.3 — structural AAD consistency.
	report.AADContextConsistent = p.Manifest.AADContext.PackageID == p.PackageID

	// L1.4 — per-audience cipher_hash over the raw decoded ciphertext and
	// tag.
	plainHash := make(map[string]string, len(p.Manifest.SegmentOrder))
	report.CipherHashes = make(map[string]bool, len(p.Manifest.SegmentOrder))
	for _, a := range p.Manifest.SegmentOrder {
		seg := p.Manifest.Segments[a]
		plainHash[a] = seg.PlainHash
		report.CipherHashes[a] = checkCipherHash(seg, p.Segments[a])
	}

	// L1.5 — recomputed segments_root against the signed bindings value.
	// SegmentsRoot can only fail on a duplicate audience in segment_order, a
	// plain_hash missing for an audience in segment_order, or a plain_hash
	// entry absent from segment_order (bindings.go) — and parsePackage has
	// already rejected all three by the time this line runs: a duplicate is
	// FaultDuplicateAudience, and every audience in segment_order is
	// guaranteed a manifest.Segments entry (FaultManifestSegmentMissing),
	// which is exactly what populates plainHash above, one entry per
	// segment_order member, keyed by the same names — so plainHash's key set
	// is always exactly segment_order's, with no member of either missing
	// from the other. err is therefore unreachable here; this is not a
	// second copy of L1.1's check, only its provable consequence.
	recomputedRoot, err := SegmentsRoot(p.Manifest.SegmentOrder, plainHash)
	report.SegmentsRoot = err == nil && recomputedRoot == p.Bindings.SegmentsRoot

	// L1.6 — recomputed profile bindings, from signed manifest values,
	// against the signed bindings.Extra values.
	if len(opt.BindingSpecs) > 0 {
		bctx := BindingContext{
			PlainHash:       plainHash,
			IntentRef:       p.Intent.IntentRef,
			ConstraintsHash: p.Intent.ConstraintsHash,
			SegmentsRoot:    recomputedRoot,
		}
		report.ProfileBindings = make(map[string]bool, len(opt.BindingSpecs))
		for _, spec := range opt.BindingSpecs {
			v, computeErr := spec.Compute(bctx)
			report.ProfileBindings[spec.Name] = computeErr == nil && v == p.Bindings.Extra[spec.Name]
		}
	}

	// Level 2 runs only if every Level 1 check passed.
	if !level1Passed(report) {
		return report, nil
	}
	verifyIntent(ctx, p, opt.Intent, report)
	return report, nil
}

// specVersionSupported reports whether v is this build's recognised
// spec_version. It exists as a boolean, not a passthrough of
// CheckSpecVersion's error, because an unsupported version is not a failure
// to process the Verify request — it is the request's answer.
func specVersionSupported(v string) bool {
	return CheckSpecVersion(v) == nil
}

// parsePackage is the whole of L1.1: every check that can be made on a
// package before anything about it is trusted. Required sections present
// (signature.signed_fields, a non-empty segment_order), exactly one manifest
// entry and one sealed segment per declared audience — no fewer, no more, no
// duplicate — signature.signed_fields naming a valid signing view, and
// signature.value decoding as base64url. It returns the reconstructed
// signing view and the decoded signature because producing them *is* the
// parse — a package whose signed_fields cannot name a view, or whose
// signature.value is not base64url, has failed to parse, not failed to
// verify. fault is FaultNone on success, in which case view and sig are the
// exact inputs L1.2 needs.
func parsePackage(p Package) (view, sig []byte, fault StructuralFault) {
	if len(p.Signature.SignedFields) == 0 {
		return nil, nil, FaultEmptySignedFields
	}
	if len(p.Manifest.SegmentOrder) == 0 {
		return nil, nil, FaultEmptySegmentOrder
	}
	if len(p.Manifest.Segments) != len(p.Manifest.SegmentOrder) {
		return nil, nil, FaultSegmentCountMismatch
	}

	seen := make(map[string]struct{}, len(p.Manifest.SegmentOrder))
	for _, a := range p.Manifest.SegmentOrder {
		if _, dup := seen[a]; dup {
			return nil, nil, FaultDuplicateAudience
		}
		seen[a] = struct{}{}

		if _, ok := p.Manifest.Segments[a]; !ok {
			return nil, nil, FaultManifestSegmentMissing
		}
		if _, ok := p.Segments[a]; !ok {
			return nil, nil, FaultSealedSegmentMissing
		}
	}

	// checkSignedFields runs first, on its own, so the two ways
	// ReconstructSigningView can fail stay distinguishable. Asking
	// ReconstructSigningView and blaming signed_fields for whatever it
	// returns would misreport a package whose signed_fields is valid but
	// whose bindings.Extra shadows a core binding name — a package the
	// caller built in memory, since Bindings.UnmarshalJSON rejects that
	// collision on the way in.
	if err := checkSignedFields(p.Signature.SignedFields); err != nil {
		return nil, nil, FaultSignedFieldsInvalid
	}

	view, err := ReconstructSigningView(p)
	if err != nil {
		return nil, nil, FaultSigningViewUnbuildable
	}
	sig, err = DecodeSignatureValue(p.Signature.Value)
	if err != nil {
		return nil, nil, FaultSignatureUndecodable
	}
	return view, sig, FaultNone
}

// resolveIssuerKey calls resolve with the package's claimed iss/kid and
// returns exactly what it answers. A nil resolve is treated as "no key
// trusted", never as an implicit pass.
func resolveIssuerKey(resolve func(iss, kid string) (ed25519.PublicKey, bool), iss, kid string) (ed25519.PublicKey, bool) {
	if resolve == nil {
		return nil, false
	}
	return resolve(iss, kid)
}

// verifyEd25519 reports whether sig is a valid Ed25519 signature over
// message under pub. The length guards matter here specifically: pub comes
// from a caller's IssuerKey resolver keyed on attacker-controlled iss/kid,
// so a resolver bug or a deliberately malformed trust-store entry can hand
// Verify a public key of the wrong size. crypto/ed25519.Verify panics on
// that input, and this is the verification path — the one place chainbind
// exists to process hostile artifacts without falling over.
func verifyEd25519(pub ed25519.PublicKey, message, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, message, sig)
}

// checkCipherHash reports whether seg.CipherHash matches H(ciphertext ‖
// tag) over sealed's raw decoded bytes (TECHSPEC-001 §6.5 L1.4). A malformed
// base64 encoding is a mismatch, not a separate error class — the report
// has no field for "unparseable", only "invalid".
func checkCipherHash(seg Segment, sealed SealedSegment) bool {
	ciphertext, err := base64.RawURLEncoding.DecodeString(sealed.Ciphertext)
	if err != nil {
		return false
	}
	tag, err := base64.RawURLEncoding.DecodeString(sealed.Tag)
	if err != nil {
		return false
	}

	combined := make([]byte, 0, len(ciphertext)+len(tag))
	combined = append(combined, ciphertext...)
	combined = append(combined, tag...)
	return H(combined) == seg.CipherHash
}

// verifyIntent runs Level 2 (L2.1–L2.4) and writes the outcome into
// report.Intent. It is only called once Level 1 has passed completely.
//
// The constraints_hash used in L2.4 comes from iv — the authority — never
// from p.Intent.ConstraintsHash. The value inside p is signed, but it is
// only the issuer's claim about what the authority said; recomputing the
// commitment from that claim would compare the issuer's assertion against
// itself; a forging issuer controls both sides and the check would always
// pass (architecture invariant 7).
func verifyIntent(ctx context.Context, p *Package, iv IntentVerifier, report *Report) {
	if iv == nil {
		report.Intent = IntentResult{Reason: "intent authority not configured"}
		return
	}

	authoritativeHash, err := iv.ConstraintsHash(ctx, p.Intent.IntentRef)
	if err != nil {
		report.Intent = IntentResult{Reason: "intent authority unreachable"}
		return
	}
	report.Intent.Evaluated = true

	if authoritativeHash != p.Intent.ConstraintsHash {
		report.Intent.Reason = "constraints_hash does not match the authority"
		return
	}

	commitment, err := IntentCommitment(p.Intent.IntentRef, authoritativeHash, p.Bindings.SegmentsRoot)
	if err != nil {
		report.Intent.Reason = "failed to recompute intent commitment"
		return
	}
	if commitment != p.Bindings.IntentCommitment {
		report.Intent.Reason = "intent commitment does not match"
		return
	}

	report.Intent.Valid = true
}
