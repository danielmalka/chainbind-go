package http

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/danielmalka/chainbind-go/internal/adapters/auth/keycloak"
	"github.com/danielmalka/chainbind-go/internal/adapters/keywrap/x25519"
	"github.com/danielmalka/chainbind-go/pkg/chainbind"
)

// These sentinels stand in for the two kinds of secret this package must
// never echo: a high-entropy value that could be a DEK, a private key, or
// plaintext, and a value shaped like a credential. The denial reason in
// this test is deliberately built without either, so a body that does
// contain one proves a real leak, not a false positive from the one
// allowed echo (the authority's own denial reason, TECHSPEC-001 §5).
const (
	plaintextSentinel = "SENTINEL-7f3a9c2e1b8d4f60-plaintext-should-never-appear"
	vaultTokenLike    = "s.SENTINEL-fake-vault-token-9d8c7b6a5e4f3210" //nolint:gosec // test fixture, not a real credential
)

// TestProblemJSON_NeverLeaksSecrets drives every error path this package
// defines with a payload carrying plaintextSentinel and an error carrying
// vaultTokenLike, and asserts neither ever appears in a response body.
func TestProblemJSON_NeverLeaksSecrets(t *testing.T) {
	signer := newSealSigner(t)
	auds, err := LoadAudiences(testAudiencesFile(t))
	if err != nil {
		t.Fatalf("LoadAudiences: %v", err)
	}

	payload := validCheckoutPayload()
	payload.Subject.Email = plaintextSentinel

	cases := []struct {
		name    string
		method  string
		path    string
		body    []byte
		ct      string
		bearer  string
		authz   Authorizer
		intent  chainbind.IntentVerifier
		vault   error
		wantMin int // minimum acceptable status, just to sanity-check the case fires
	}{
		{
			name:   "seal 401 no token",
			method: http.MethodPost, path: "/v1/packages/seal",
			body: marshalOrFatal(t, payload), ct: "application/json",
			authz: &fakeAuthorizer{err: keycloak.ErrUnauthorized}, intent: allowingIntentVerifier(),
			wantMin: http.StatusUnauthorized,
		},
		{
			name:   "seal 403 missing role",
			method: http.MethodPost, path: "/v1/packages/seal",
			body: marshalOrFatal(t, payload), ct: "application/json", bearer: "token",
			authz: &fakeAuthorizer{err: keycloak.ErrForbidden}, intent: allowingIntentVerifier(),
			wantMin: http.StatusForbidden,
		},
		{
			name:   "seal 422 intent denied",
			method: http.MethodPost, path: "/v1/packages/seal",
			body: marshalOrFatal(t, payload), ct: "application/json", bearer: "token",
			authz: &fakeAuthorizer{},
			intent: &fakeIntentVerifier{
				checkFn: func(context.Context, string, any) (chainbind.IntentDecision, error) {
					return chainbind.IntentDecision{Allowed: false, Reason: "amount exceeds authorized limit"}, nil
				},
			},
			wantMin: http.StatusUnprocessableEntity,
		},
		{
			name:   "seal 502 authority unreachable",
			method: http.MethodPost, path: "/v1/packages/seal",
			body: marshalOrFatal(t, payload), ct: "application/json", bearer: "token",
			authz: &fakeAuthorizer{},
			intent: &fakeIntentVerifier{
				checkFn: func(context.Context, string, any) (chainbind.IntentDecision, error) {
					return chainbind.IntentDecision{}, errSentinelWithToken()
				},
			},
			wantMin: http.StatusBadGateway,
		},
		{
			name:   "seal 400 malformed",
			method: http.MethodPost, path: "/v1/packages/seal",
			body: []byte(`{"subject":{"email":"` + plaintextSentinel + `"` /* truncated */), ct: "application/json", bearer: "token",
			authz: &fakeAuthorizer{}, intent: allowingIntentVerifier(),
			wantMin: http.StatusBadRequest,
		},
		{
			name:   "seal 415 wrong content type",
			method: http.MethodPost, path: "/v1/packages/seal",
			body: marshalOrFatal(t, payload), ct: "text/plain", bearer: "token",
			authz: &fakeAuthorizer{}, intent: allowingIntentVerifier(),
			wantMin: http.StatusUnsupportedMediaType,
		},
		{
			name:   "verify 400 malformed",
			method: http.MethodPost, path: "/v1/packages/verify",
			body: []byte(`{"issuer":{"iss":"` + plaintextSentinel + `"` /* truncated */), ct: "application/json",
			authz: &fakeAuthorizer{}, intent: allowingIntentVerifier(),
			wantMin: http.StatusBadRequest,
		},
		{
			name:   "verify 415 wrong content type",
			method: http.MethodPost, path: "/v1/packages/verify",
			body: []byte(`{}`), ct: "text/plain",
			authz: &fakeAuthorizer{}, intent: allowingIntentVerifier(),
			wantMin: http.StatusUnsupportedMediaType,
		},
		{
			name:   "verify 422 unsupported spec_version",
			method: http.MethodPost, path: "/v1/packages/verify",
			body: mustMarshalPackage(t, plaintextSentinel), ct: "application/json",
			authz: &fakeAuthorizer{}, intent: allowingIntentVerifier(),
			wantMin: http.StatusUnprocessableEntity,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := NewHandler(HandlerConfig{
				Authorizer:      tc.authz,
				Signer:          signer.signer,
				KeyWrapper:      x25519.Wrapper{},
				Audiences:       auds,
				IntentVerifier:  tc.intent,
				IssuerKey:       issuerKeyResolver(signer.kid, signer.pub),
				VaultProber:     &fakeProber{err: tc.vault},
				AuthorityProber: &fakeProber{},
			})

			req := httptest.NewRequest(tc.method, tc.path, bytes.NewReader(tc.body))
			if tc.ct != "" {
				req.Header.Set("Content-Type", tc.ct)
			}
			if tc.bearer != "" {
				req.Header.Set("Authorization", "Bearer "+tc.bearer)
			}

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code < tc.wantMin {
				t.Fatalf("status = %d, want >= %d (case did not fire as intended)", rec.Code, tc.wantMin)
			}

			out := rec.Body.String()
			if strings.Contains(out, plaintextSentinel) {
				t.Fatalf("response body leaks the plaintext sentinel: %s", out)
			}
			if strings.Contains(out, vaultTokenLike) {
				t.Fatalf("response body leaks the vault-token-like sentinel: %s", out)
			}
		})
	}
}

// TestProblemJSON_ReadyNeverLeaksVaultToken drives /ready with a prober
// error whose text contains a vault-token-like sentinel, and confirms the
// 503 body carries only the static "vault" label.
func TestProblemJSON_ReadyNeverLeaksVaultToken(t *testing.T) {
	h := readyTestServer(errSentinelWithToken(), nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ready", http.NoBody))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	out := rec.Body.String()
	if strings.Contains(out, vaultTokenLike) {
		t.Fatalf("503 body leaks the vault-token-like sentinel: %s", out)
	}
}

func marshalOrFatal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func mustMarshalPackage(t *testing.T, sentinelInIssuer string) []byte {
	t.Helper()
	pkg := chainbind.Package{SpecVersion: "9.9.9", Issuer: chainbind.Issuer{Iss: sentinelInIssuer}}
	b, err := json.Marshal(pkg)
	if err != nil {
		t.Fatalf("marshal package: %v", err)
	}
	return b
}

// errSentinelWithToken is an error whose text names vaultTokenLike — the
// shape a careless error path (interpolating an underlying error string
// into a problem detail) would leak. Handlers must map it to a static
// label instead.
func errSentinelWithToken() error {
	return errSentinel("upstream rejected credential " + vaultTokenLike)
}
