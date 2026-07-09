package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danielmalka/chainbind-go/internal/adapters/intent/mock"
)

// seededHandler builds the mock-authority handler over a mock.Verifier seeded
// with one allowing authorization, ref "intent:ok".
func seededHandler(t *testing.T) http.Handler {
	t.Helper()
	dir := t.TempDir()
	doc := `{"ref":"intent:ok","version":1,"rules":{"currency":{"equals":["BRL"]}}}`
	if err := os.WriteFile(filepath.Join(dir, "ok.json"), []byte(doc), 0o600); err != nil {
		t.Fatalf("write seed: %v", err)
	}
	v, err := mock.New(dir)
	if err != nil {
		t.Fatalf("mock.New: %v", err)
	}
	return newHandler(v, discardLogger())
}

// TestCheck_UnknownRef_FailsClosed is the security-critical case: an unknown
// intent_ref must be a 5xx, never a fabricated allow. The HTTP intent adapter
// treats any non-2xx as an error and never mistakes it for an allow (D-005,
// invariant 6); this test locks the authority end of that contract.
func TestCheck_UnknownRef_FailsClosed(t *testing.T) {
	h := seededHandler(t)

	body := strings.NewReader(`{"projection":{"currency":"BRL"}}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/intents/intent:does-not-exist/check", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code < 500 {
		t.Fatalf("unknown ref returned status %d, want 5xx — never an allow", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "allowed") {
		t.Fatalf("unknown ref response mentions an allow decision: %s", rec.Body.String())
	}
}

// TestConstraintsHash_UnknownRef_FailsClosed: an unknown ref must not yield a
// fabricated (or empty) constraints_hash, which the adapter would otherwise
// treat as the authority's word.
func TestConstraintsHash_UnknownRef_FailsClosed(t *testing.T) {
	h := seededHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/intents/intent:does-not-exist/constraints-hash", http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code < 500 {
		t.Fatalf("unknown ref returned status %d, want 5xx", rec.Code)
	}
}

// TestCheck_KnownRef_AllowsAndDenies confirms the wire shape for the two real
// answers: a matching projection is allowed at 200, a non-matching one is
// denied at 200 (a real deny, not an error). Neither is a 5xx.
func TestCheck_KnownRef_AllowsAndDenies(t *testing.T) {
	h := seededHandler(t)

	for _, tc := range []struct {
		name       string
		projection string
		want       bool
	}{
		{"matching currency allowed", `{"currency":"BRL"}`, true},
		{"wrong currency denied", `{"currency":"USD"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := strings.NewReader(`{"projection":` + tc.projection + `}`)
			req := httptest.NewRequest(http.MethodPost, "/v1/intents/intent:ok/check", body)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			var resp struct {
				Allowed bool `json:"allowed"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if resp.Allowed != tc.want {
				t.Fatalf("allowed = %v, want %v", resp.Allowed, tc.want)
			}
		})
	}
}

// TestHealth_OK confirms /v1/health is a plain 200 — the readiness probe the
// shell's /ready depends on, which asks nothing about an intent_ref.
func TestHealth_OK(t *testing.T) {
	h := seededHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/health", http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("health status = %d, want 200", rec.Code)
	}
}

// discardLogger returns a slog.Logger that writes nowhere, so tests do not
// spew the handler's warn lines.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}
