package http

import (
	"context"
	"net/http"
)

// Prober is the port /ready checks a dependency through. It is defined
// here, in the consumer, per this repository's convention: the shell is
// what needs a health signal, so the shell names the method it needs.
//
// Ping must never do more than prove reachability. In particular the
// Vault signer's Ping re-fetches key metadata and signs nothing, and the
// intent authority's Ping calls a health endpoint and evaluates no
// intent_ref — a readiness probe is not a place to spend a signing key or
// consult a real authorization.
type Prober interface {
	Ping(ctx context.Context) error
}

// namedProber pairs a Prober with the static label /ready names it by on
// failure. The label is chosen by the caller wiring the router, never
// derived from configuration — so it can never be a URL or any other
// value worth withholding (architecture invariant 10).
type namedProber struct {
	name   string
	prober Prober
}

// readyHandler returns 200 {"status":"ready"} only once every prober in
// probers succeeds, in order, failing fast on the first that does not.
// Probers are a slice, not a map, so the dependency checked first — and
// therefore named on failure when more than one is down — is
// deterministic across requests and across test runs.
func readyHandler(probers []namedProber) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for _, np := range probers {
			if err := np.prober.Ping(r.Context()); err != nil {
				// np.name is a static label the caller chose when wiring
				// the router ("vault", "intent-authority") — never the
				// underlying error text and never a URL, so a down
				// dependency never leaks where it lives.
				writeProblem(w, http.StatusServiceUnavailable, typeServiceNotReady, "not ready", np.name)
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	}
}
