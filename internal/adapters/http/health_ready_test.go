package http

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/danielmalka/chainbind-go/internal/adapters/keywrap/x25519"
)

func readyTestServer(vault, authority error) http.Handler {
	return NewHandler(HandlerConfig{
		Authorizer:      &fakeAuthorizer{},
		Signer:          nil,
		KeyWrapper:      x25519.Wrapper{},
		IntentVerifier:  allowingIntentVerifier(),
		VaultProber:     &fakeProber{err: vault},
		AuthorityProber: &fakeProber{err: authority},
	})
}

func TestHealthHandler_Always200(t *testing.T) {
	h := readyTestServer(nil, nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", http.NoBody))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("status field = %q, want %q", body["status"], "ok")
	}
}

func TestReadyHandler_AllProbersPass_200(t *testing.T) {
	h := readyTestServer(nil, nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ready", http.NoBody))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}

func TestReadyHandler_VaultDown_503(t *testing.T) {
	h := readyTestServer(errors.New("connection refused to https://vault.internal:8200"), nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ready", http.NoBody))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503, body=%s", rec.Code, rec.Body.String())
	}
	assertReadyBodyNamesDependencyNoURL(t, rec, "vault")
}

func TestReadyHandler_AuthorityDown_503(t *testing.T) {
	h := readyTestServer(nil, errors.New("dial tcp 10.0.0.5:443: connection refused"))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ready", http.NoBody))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503, body=%s", rec.Code, rec.Body.String())
	}
	assertReadyBodyNamesDependencyNoURL(t, rec, "intent-authority")
}

func assertReadyBodyNamesDependencyNoURL(t *testing.T, rec *httptest.ResponseRecorder, wantLabel string) {
	t.Helper()
	assertProblemContentType(t, rec)

	var p problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if p.Detail != wantLabel {
		t.Fatalf("detail = %q, want static label %q", p.Detail, wantLabel)
	}
	if strings.Contains(rec.Body.String(), "://") {
		t.Fatalf("503 body names a URL, want a static label only: %s", rec.Body.String())
	}
}
