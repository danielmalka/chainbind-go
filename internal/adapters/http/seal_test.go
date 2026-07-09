package http

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/danielmalka/chainbind-go/internal/adapters/auth/keycloak"
	"github.com/danielmalka/chainbind-go/internal/adapters/keywrap/x25519"
	"github.com/danielmalka/chainbind-go/pkg/chainbind"
)

// sealTestServer builds a full NewHandler wired with a fake authorizer and
// intent verifier the caller controls, plus a real signer/key
// wrapper/audience roster so a happy-path request actually seals.
func sealTestServer(t *testing.T, authz Authorizer, intent chainbind.IntentVerifier) http.Handler {
	t.Helper()
	signer, pub := testSigner(t)
	audiences, err := LoadAudiences(testAudiencesFile(t))
	if err != nil {
		t.Fatalf("LoadAudiences: %v", err)
	}

	return NewHandler(HandlerConfig{
		Authorizer:      authz,
		IssuerID:        testIssuerID,
		Signer:          signer,
		KeyWrapper:      x25519.Wrapper{},
		Audiences:       audiences,
		IntentVerifier:  intent,
		IssuerKey:       issuerKeyResolver("unused", pub),
		VaultProber:     &fakeProber{},
		AuthorityProber: &fakeProber{},
	})
}

func sealRequest(t *testing.T, body []byte, bearer, contentType string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/packages/seal", bytes.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return req
}

func TestSealHandler_NoBearerToken_401(t *testing.T) {
	h := sealTestServer(t, &fakeAuthorizer{err: keycloak.ErrUnauthorized}, allowingIntentVerifier())
	body, _ := json.Marshal(validCheckoutPayload())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, sealRequest(t, body, "", "application/json"))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	assertProblemContentType(t, rec)
}

func TestSealHandler_InvalidBearerToken_401(t *testing.T) {
	h := sealTestServer(t, &fakeAuthorizer{err: keycloak.ErrUnauthorized}, allowingIntentVerifier())
	body, _ := json.Marshal(validCheckoutPayload())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, sealRequest(t, body, "not-a-real-token", "application/json"))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestSealHandler_ValidTokenMissingRole_403(t *testing.T) {
	h := sealTestServer(t, &fakeAuthorizer{err: keycloak.ErrForbidden}, allowingIntentVerifier())
	body, _ := json.Marshal(validCheckoutPayload())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, sealRequest(t, body, "valid-but-no-role", "application/json"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	assertProblemContentType(t, rec)
}

func TestSealHandler_HappyPath_200(t *testing.T) {
	h := sealTestServer(t, &fakeAuthorizer{}, allowingIntentVerifier())
	body, _ := json.Marshal(validCheckoutPayload())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, sealRequest(t, body, "valid-token", "application/json"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var pkg chainbind.Package
	if err := json.Unmarshal(rec.Body.Bytes(), &pkg); err != nil {
		t.Fatalf("decode Package: %v", err)
	}
	if len(pkg.Segments) != 3 {
		t.Fatalf("Package has %d segments, want 3", len(pkg.Segments))
	}
}

func TestSealHandler_IntentDenied_422CarriesAuthorityReason(t *testing.T) {
	const reason = "spending limit exceeded for merchant-1"
	intent := &fakeIntentVerifier{
		checkFn: func(context.Context, string, any) (chainbind.IntentDecision, error) {
			return chainbind.IntentDecision{Allowed: false, Reason: reason}, nil
		},
	}
	h := sealTestServer(t, &fakeAuthorizer{}, intent)
	body, _ := json.Marshal(validCheckoutPayload())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, sealRequest(t, body, "valid-token", "application/json"))

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422, body=%s", rec.Code, rec.Body.String())
	}
	var p problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if p.Detail != reason {
		t.Fatalf("detail = %q, want the authority's reason %q verbatim", p.Detail, reason)
	}
}

func TestSealHandler_AuthorityUnreachable_502(t *testing.T) {
	intent := &fakeIntentVerifier{
		checkFn: func(context.Context, string, any) (chainbind.IntentDecision, error) {
			return chainbind.IntentDecision{}, errUnreachableSentinel
		},
	}
	h := sealTestServer(t, &fakeAuthorizer{}, intent)
	body, _ := json.Marshal(validCheckoutPayload())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, sealRequest(t, body, "valid-token", "application/json"))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502, body=%s", rec.Code, rec.Body.String())
	}
}

func TestSealHandler_MalformedPayload_400(t *testing.T) {
	h := sealTestServer(t, &fakeAuthorizer{}, allowingIntentVerifier())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, sealRequest(t, []byte("{not json"), "valid-token", "application/json"))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
	assertProblemContentType(t, rec)
}

func TestSealHandler_WrongContentType_415(t *testing.T) {
	h := sealTestServer(t, &fakeAuthorizer{}, allowingIntentVerifier())
	body, _ := json.Marshal(validCheckoutPayload())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, sealRequest(t, body, "valid-token", "text/plain"))

	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415, body=%s", rec.Code, rec.Body.String())
	}
	assertProblemContentType(t, rec)
}

func assertProblemContentType(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); ct != problemContentType {
		t.Fatalf("Content-Type = %q, want %q", ct, problemContentType)
	}
}

// errUnreachableSentinel stands in for whatever transport error a real
// IntentVerifier surfaces; the seal handler must map any non-denial Seal
// failure to 502 without inspecting it further.
var errUnreachableSentinel = errSentinel("authority unreachable in test")

type errSentinel string

func (e errSentinel) Error() string { return string(e) }

// testIssuerID is the operator-configured issuer identity the seal handler
// stamps into issuer.iss. It is deliberately unlike anything the test
// payload carries in request_context.issued_by, so a handler that sourced
// the identity from the body instead of from configuration would fail
// TestSealHandler_IssuerComesFromConfigNotBody.
const testIssuerID = "did:chainbind:operator-configured-issuer"

// TestSealHandler_IssuerComesFromConfigNotBody pins that the caller cannot
// choose who sealed. The shell holds the Vault signing key, so the shell is
// the issuer (D-002); issuer.iss must be the operator's configured identity,
// never a string lifted from the request body. A caller who could set it
// would place an attacker-chosen identity inside the signed view, over the
// operator's key.
func TestSealHandler_IssuerComesFromConfigNotBody(t *testing.T) {
	h := sealTestServer(t, &fakeAuthorizer{}, allowingIntentVerifier())

	payload := validCheckoutPayload()
	payload.RequestContext.IssuedBy = "did:attacker:i-picked-this"
	body, _ := json.Marshal(payload)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, sealRequest(t, body, "valid-token", "application/json"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	var pkg chainbind.Package
	if err := json.Unmarshal(rec.Body.Bytes(), &pkg); err != nil {
		t.Fatalf("decode Package: %v", err)
	}
	if pkg.Issuer.Iss != testIssuerID {
		t.Fatalf("issuer.iss = %q, want %q — the request body must not choose the issuer", pkg.Issuer.Iss, testIssuerID)
	}
	if pkg.Issuer.Iss == "did:attacker:i-picked-this" {
		t.Fatal("the request body's issued_by became issuer.iss: a caller can forge the issuer identity")
	}
}
