// Package http implements chainbind.IntentVerifier over HTTP against a
// configurable base URL. It is the adapter TASK-001-12/14 point at a real
// deployment; this task only stubs the wire shape and proves the adapter
// never fails open.
//
// Wire shape (this adapter's request/response contract with the authority):
//
//	POST {baseURL}/v1/intents/{intentRef}/check
//	  body:     {"projection": <projection>}
//	  200 body: {"allowed": bool, "reason": string}
//
//	GET {baseURL}/v1/intents/{intentRef}/constraints-hash
//	  200 body: {"constraints_hash": string}
//
//	GET {baseURL}/v1/health
//	  2xx: the authority is reachable. Ping (TASK-001-12) declares this
//	  endpoint as an extension of the wire shape above; TASK-001-14's
//	  compose authority is what serves it.
//
// Any non-200 status, a malformed body, a request that cannot be built, or a
// transport-level failure (including a context deadline) is an error. None
// of them is ever mistaken for an allow or for a valid hash — an
// unreachable or slow authority must surface as an error (D-005, invariant
// 6).
package http

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/danielmalka/chainbind-go/pkg/chainbind"
)

// maxResponseBody caps how much of an authority response this adapter will
// ever decode. The authority is a trusted external dependency, but an
// authority (or anyone between here and it) returning an unbounded body is
// an out-of-memory kill on the calling process, not a fail-open — every
// path through doJSON still yields an error, never an allow. Matches the
// Vault signer adapter's own cap and its reasoning.
const maxResponseBody = 1 << 20 // 1 MiB

// Sentinel errors. Static strings only — no projection value, no payload
// data, no response body ever appears in one of these (AGENTS.local.md
// invariant 10).
var (
	// ErrAuthorityUnreachable is returned when the request could not be
	// built or the transport failed (network error, timeout, closed
	// connection).
	ErrAuthorityUnreachable = errors.New("http: intent authority unreachable")

	// ErrAuthorityResponse is returned when the authority answered with a
	// non-2xx status or a body that does not match the wire shape.
	ErrAuthorityResponse = errors.New("http: intent authority returned an invalid response")
)

// Verifier calls a real Intent Authority over HTTP. It implements
// chainbind.IntentVerifier.
type Verifier struct {
	baseURL string
	client  *http.Client
	timeout time.Duration
}

// New returns a Verifier that calls baseURL. If client is nil,
// http.DefaultClient is used. timeout bounds every call with its own
// context deadline; a timeout <= 0 relies solely on the caller's context.
func New(baseURL string, client *http.Client, timeout time.Duration) *Verifier {
	if client == nil {
		client = http.DefaultClient
	}
	return &Verifier{baseURL: baseURL, client: client, timeout: timeout}
}

type checkRequest struct {
	Projection any `json:"projection"`
}

type checkResponse struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

// Check implements chainbind.IntentVerifier.
func (v *Verifier) Check(ctx context.Context, intentRef string, projection any) (chainbind.IntentDecision, error) {
	ctx, cancel := v.withDeadline(ctx)
	defer cancel()

	body, err := json.Marshal(checkRequest{Projection: projection})
	if err != nil {
		return chainbind.IntentDecision{}, fmt.Errorf("http: encode check request: %w", err)
	}

	endpoint := v.baseURL + "/v1/intents/" + url.PathEscape(intentRef) + "/check"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return chainbind.IntentDecision{}, fmt.Errorf("http: build check request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	var resp checkResponse
	if err := v.doJSON(req, &resp); err != nil {
		return chainbind.IntentDecision{}, fmt.Errorf("http: check: %w", err)
	}

	return chainbind.IntentDecision{Allowed: resp.Allowed, Reason: resp.Reason}, nil
}

type constraintsHashResponse struct {
	ConstraintsHash string `json:"constraints_hash"`
}

// ConstraintsHash implements chainbind.IntentVerifier.
func (v *Verifier) ConstraintsHash(ctx context.Context, intentRef string) (string, error) {
	ctx, cancel := v.withDeadline(ctx)
	defer cancel()

	endpoint := v.baseURL + "/v1/intents/" + url.PathEscape(intentRef) + "/constraints-hash"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return "", fmt.Errorf("http: build constraints hash request: %w", err)
	}

	var resp constraintsHashResponse
	if err := v.doJSON(req, &resp); err != nil {
		return "", fmt.Errorf("http: constraints hash: %w", err)
	}
	if resp.ConstraintsHash == "" {
		return "", fmt.Errorf("http: constraints hash: %w", ErrAuthorityResponse)
	}

	return resp.ConstraintsHash, nil
}

// withDeadline returns ctx bounded by v.timeout, if configured.
func (v *Verifier) withDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	if v.timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, v.timeout)
}

// doJSON executes req, requires a 2xx status, and decodes the JSON body into
// out. A network error, a non-2xx status, or an undecodable body is always
// an error — never a silent allow.
func (v *Verifier) doJSON(req *http.Request, out any) error {
	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrAuthorityUnreachable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%w: status %d", ErrAuthorityResponse, resp.StatusCode)
	}

	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBody)).Decode(out); err != nil {
		return fmt.Errorf("%w: %w", ErrAuthorityResponse, err)
	}

	return nil
}

// Ping implements the HTTP shell's Prober port: it requires a 2xx from
// {baseURL}/v1/health and decodes nothing, proving the authority is
// reachable without asking it anything about an intent_ref.
func (v *Verifier) Ping(ctx context.Context) error {
	ctx, cancel := v.withDeadline(ctx)
	defer cancel()

	endpoint := v.baseURL + "/v1/health"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return fmt.Errorf("http: build health request: %w", err)
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrAuthorityUnreachable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%w: status %d", ErrAuthorityResponse, resp.StatusCode)
	}
	return nil
}
