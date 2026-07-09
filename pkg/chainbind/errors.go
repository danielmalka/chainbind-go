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
	// validation (missing sections, mismatched segment counts, ...).
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

	// ErrWrongRecipientKey is returned when the private key supplied to
	// Open does not match any audience's key confirmation.
	ErrWrongRecipientKey = errors.New("chainbind: wrong recipient key")
)
