package http

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"

	"github.com/danielmalka/chainbind-go/pkg/chainbind"
	"github.com/danielmalka/chainbind-go/pkg/chainbind/profile/agenticcheckout"
)

// maxVerifyRequestBody caps the verify request body before JSON decoding.
// A Package is small (a handful of segments, none larger than a checkout
// payload); 1 MiB is generous headroom, not a throughput target.
const maxVerifyRequestBody = 1 << 20 // 1 MiB

// verifyOpts is what the verify handler needs from VerifyOptions, wired
// once at startup: the issuer key resolver and the intent authority.
// BindingSpecs is always agenticcheckout's — this shell only ever
// verifies packages sealed under that profile.
type verifyOpts struct {
	issuerKey func(iss, kid string) (ed25519.PublicKey, bool)
	intent    chainbind.IntentVerifier
}

// verifyHandler decodes a Package and runs chainbind.Verify, returning the
// Report as 200 in every case except a malformed body (400) or an
// unsupported spec_version (422) — never for a failing report.
//
// This is decision C from the task brief, and it is worth restating
// in-line because it is exactly the kind of thing a later "cleanup" gets
// wrong: a failing Report (bad signature, a hash mismatch, an
// unevaluated intent level) is Verify's *answer*, not a protocol error —
// the same reason Verify itself returns a nil Go error in every one of
// those cases (architecture invariant 3). Mapping !report.OK() to a
// non-200 status would turn a keyless verifier's completed, correct
// analysis of a bad package into an HTTP failure indistinguishable from
// "the server choked on your request" — which is a real bug this comment
// exists to keep out.
func verifyHandler(opts verifyOpts) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !hasJSONContentType(r) {
			writeProblem(w, http.StatusUnsupportedMediaType, typeUnsupportedMedia, "unsupported media type", "Content-Type must be application/json")
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxVerifyRequestBody)

		var pkg chainbind.Package
		if err := json.NewDecoder(r.Body).Decode(&pkg); err != nil {
			writeProblem(w, http.StatusBadRequest, typeMalformedRequest, "malformed request", "invalid or oversized package")
			return
		}

		report, err := chainbind.Verify(r.Context(), &pkg, chainbind.VerifyOptions{
			IssuerKey:    opts.issuerKey,
			Intent:       opts.intent,
			BindingSpecs: agenticcheckout.BindingSpecs(),
		})
		if err != nil {
			// Verify returns a non-nil error only for a nil package
			// pointer (chainbind.ErrNilPackage) — unreachable here, since
			// &pkg is always non-nil — but a decode error is handled the
			// same way any other malformed input is: 400, no error text.
			writeProblem(w, http.StatusBadRequest, typeMalformedRequest, "malformed request", "package could not be processed")
			return
		}

		if !report.SpecVersionSupported {
			writeProblem(w, http.StatusUnprocessableEntity, typeUnsupportedSpec, "unsupported spec_version", "this build does not recognise the package's spec_version")
			return
		}

		writeJSON(w, http.StatusOK, report)
	}
}
