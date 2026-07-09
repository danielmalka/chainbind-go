package chainbind

import "errors"

// Sentinel errors returned by the core. Every message here is a static
// string: none is ever built from plaintext, a data-encryption key, or
// private-key bytes (see the security section of TECHSPEC-001 §7). Wrap
// these with fmt.Errorf("...: %w", err) for context; never format secret
// bytes into an error message.
var (
	// ErrUnsupportedSpecVersion is returned when a package declares a
	// spec_version this build does not recognise.
	ErrUnsupportedSpecVersion = errors.New("chainbind: unsupported spec_version")

	// ErrMalformedPackage is returned when a package fails structural
	// validation (missing sections, mismatched segment counts, an invalid
	// signature.signed_fields set, ...). Verify never returns this: since
	// TASK-001-16, a structurally malformed package is reported through
	// Report.Structural, a StructuralFault, with a nil error — the same
	// contract every other Verify outcome follows (architecture invariant
	// 3). This error still reaches callers who go around Verify: SegmentsRoot
	// and checkSignedFields return it directly to their own callers, and
	// ReconstructSigningView is exported, so a caller reconstructing a
	// signing view directly (rather than through Verify) still sees it.
	ErrMalformedPackage = errors.New("chainbind: malformed package")

	// ErrSignatureInvalid is returned when the issuer signature does not
	// verify against the reconstructed signing view.
	ErrSignatureInvalid = errors.New("chainbind: signature invalid")

	// ErrHashMismatch is returned when a recomputed hash does not match
	// the value recorded in the signed manifest or bindings.
	ErrHashMismatch = errors.New("chainbind: hash mismatch")

	// ErrBindingMismatch is returned when a recomputed binding (profile
	// or core) does not match the signed value.
	ErrBindingMismatch = errors.New("chainbind: binding mismatch")

	// ErrIntentNotEvaluated is returned when the intent authority could
	// not be reached, leaving the intent level unevaluated.
	ErrIntentNotEvaluated = errors.New("chainbind: intent not evaluated")

	// ErrIntentDenied is returned by Seal when the authority reports the
	// execution falls outside the referenced authorization. Callers wrap
	// it with the authority's own reason, which is the caller's own
	// authorization data and not another party's (PRD Story 2 AC-2).
	ErrIntentDenied = errors.New("chainbind: intent denied by authority")

	// ErrIntentInvalid is returned when the intent authority rejects the
	// package's claimed constraints or commitment.
	ErrIntentInvalid = errors.New("chainbind: intent invalid")

	// There is deliberately no ErrWrongRecipientKey. One was declared here
	// while the ports were being sketched, and Open made it dead: a key
	// matching no audience, a failed unwrap, a failed GCM tag and a
	// spliced segment all return ErrDecryptionFailed. Telling them apart
	// would answer questions an attacker is not entitled to ask — naming
	// the failure is the oracle.

	// ErrBindingCollision is returned when a profile's Extra binding
	// reuses a name reserved for a core binding (segments_root,
	// intent_commitment). A profile that shadows a core binding is a
	// bug, not a preference.
	ErrBindingCollision = errors.New("chainbind: binding name collision")

	// ErrNilPackage is returned by Verify when the package pointer itself
	// is nil — the one input Verify cannot process at all. Every other
	// failure is reported through *Report with OK() == false, not through
	// this error.
	ErrNilPackage = errors.New("chainbind: verify: package is nil")

	// ErrIntegrityCheckFailed is returned by Open when Verify's Level 1
	// checks do not all pass. Open does not unwrap a data key or touch a
	// ciphertext in that case (PRD Story 4 AC-1, AC-6).
	ErrIntegrityCheckFailed = errors.New("chainbind: open: integrity check failed")
)
