package http

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCheck_AllowedDecodesResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(checkResponse{Allowed: true})
	}))
	defer srv.Close()

	v := New(srv.URL, srv.Client(), time.Second)
	decision, err := v.Check(context.Background(), "intent:ref", map[string]any{"region": "us"})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !decision.Allowed {
		t.Fatal("Check: got Allowed=false, want true")
	}
}

func TestCheck_DeniedCarriesReasonVerbatim(t *testing.T) {
	const reason = "region eu is not authorized"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(checkResponse{Allowed: false, Reason: reason})
	}))
	defer srv.Close()

	v := New(srv.URL, srv.Client(), time.Second)
	decision, err := v.Check(context.Background(), "intent:ref", map[string]any{})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if decision.Allowed {
		t.Fatal("Check: got Allowed=true, want denied")
	}
	if decision.Reason != reason {
		t.Fatalf("Check: reason = %q, want %q verbatim", decision.Reason, reason)
	}
}

func TestCheck_ClosedServerErrorsNeverAllows(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	url := srv.URL
	srv.Close() // server is now unreachable

	v := New(url, nil, time.Second)
	decision, err := v.Check(context.Background(), "intent:ref", map[string]any{})
	if err == nil {
		t.Fatal("Check against closed server: got nil error, want an error")
	}
	if !errors.Is(err, ErrAuthorityUnreachable) {
		t.Fatalf("Check against closed server: error = %v, want ErrAuthorityUnreachable", err)
	}
	if decision.Allowed {
		t.Fatal("Check against closed server: got Allowed=true, must never fail open")
	}
}

func TestCheck_ExpiredContextErrorsNeverAllows(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(checkResponse{Allowed: true})
	}))
	defer srv.Close()

	v := New(srv.URL, srv.Client(), time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)

	decision, err := v.Check(ctx, "intent:ref", map[string]any{})
	if err == nil {
		t.Fatal("Check with expired context: got nil error, want an error")
	}
	if decision.Allowed {
		t.Fatal("Check with expired context: got Allowed=true, must never fail open")
	}
}

func TestCheck_ServerErrorNeverAllows(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	v := New(srv.URL, srv.Client(), time.Second)
	decision, err := v.Check(context.Background(), "intent:ref", map[string]any{})
	if err == nil {
		t.Fatal("Check against 500: got nil error, want an error")
	}
	if !errors.Is(err, ErrAuthorityResponse) {
		t.Fatalf("Check against 500: error = %v, want ErrAuthorityResponse", err)
	}
	if decision.Allowed {
		t.Fatal("Check against 500: got Allowed=true, must never fail open")
	}
}

func TestCheck_MalformedBodyNeverAllows(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{not json"))
	}))
	defer srv.Close()

	v := New(srv.URL, srv.Client(), time.Second)
	decision, err := v.Check(context.Background(), "intent:ref", map[string]any{})
	if err == nil {
		t.Fatal("Check with malformed body: got nil error, want an error")
	}
	if !errors.Is(err, ErrAuthorityResponse) {
		t.Fatalf("Check with malformed body: error = %v, want ErrAuthorityResponse", err)
	}
	if decision.Allowed {
		t.Fatal("Check with malformed body: got Allowed=true, must never fail open")
	}
}

func TestConstraintsHash_DecodesResponse(t *testing.T) {
	const hash = "sha256:deadbeef"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(constraintsHashResponse{ConstraintsHash: hash})
	}))
	defer srv.Close()

	v := New(srv.URL, srv.Client(), time.Second)
	got, err := v.ConstraintsHash(context.Background(), "intent:ref")
	if err != nil {
		t.Fatalf("ConstraintsHash: %v", err)
	}
	if got != hash {
		t.Fatalf("ConstraintsHash = %q, want %q", got, hash)
	}
}

func TestConstraintsHash_ServerErrorErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	v := New(srv.URL, srv.Client(), time.Second)
	_, err := v.ConstraintsHash(context.Background(), "intent:ref")
	if !errors.Is(err, ErrAuthorityResponse) {
		t.Fatalf("ConstraintsHash against 500: error = %v, want ErrAuthorityResponse", err)
	}
}

func TestConstraintsHash_ClosedServerErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	url := srv.URL
	srv.Close()

	v := New(url, nil, time.Second)
	_, err := v.ConstraintsHash(context.Background(), "intent:ref")
	if !errors.Is(err, ErrAuthorityUnreachable) {
		t.Fatalf("ConstraintsHash against closed server: error = %v, want ErrAuthorityUnreachable", err)
	}
}

// TestCheck_OversizedBodyErrorsRatherThanAllocating proves the
// io.LimitReader cap on doJSON: an authority (or anyone between here and
// it) returning far more than maxResponseBody bytes must fail to decode,
// not be read in full and OOM the calling process. The body below is
// valid JSON if read whole, so a failure here can only come from the
// reader being cut off mid-stream by the cap.
func TestCheck_OversizedBodyErrorsRatherThanAllocating(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// One real field, then padding well past maxResponseBody inside a
		// JSON string value, so the whole body parses if read in full but
		// is truncated mid-string once capped.
		_, _ = w.Write([]byte(`{"allowed":true,"reason":"`))
		_, _ = w.Write([]byte(strings.Repeat("x", maxResponseBody+1)))
		_, _ = w.Write([]byte(`"}`))
	}))
	defer srv.Close()

	v := New(srv.URL, srv.Client(), 5*time.Second)
	decision, err := v.Check(context.Background(), "intent:ref", map[string]any{})
	if err == nil {
		t.Fatal("Check with an oversized body: got nil error, want an error")
	}
	if !errors.Is(err, ErrAuthorityResponse) {
		t.Fatalf("Check with an oversized body: error = %v, want ErrAuthorityResponse", err)
	}
	if decision.Allowed {
		t.Fatal("Check with an oversized body: got Allowed=true, must never fail open")
	}
}

func TestPing_ReachableHealthEndpointSucceeds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/health" {
			t.Errorf("Ping requested %q, want /v1/health", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	v := New(srv.URL, srv.Client(), time.Second)
	if err := v.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestPing_NonTwoXXErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	v := New(srv.URL, srv.Client(), time.Second)
	if err := v.Ping(context.Background()); !errors.Is(err, ErrAuthorityResponse) {
		t.Fatalf("Ping against 503: error = %v, want ErrAuthorityResponse", err)
	}
}

func TestPing_ClosedServerErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	url := srv.URL
	srv.Close()

	v := New(url, nil, time.Second)
	if err := v.Ping(context.Background()); !errors.Is(err, ErrAuthorityUnreachable) {
		t.Fatalf("Ping against closed server: error = %v, want ErrAuthorityUnreachable", err)
	}
}

func TestConstraintsHash_EmptyValueErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(constraintsHashResponse{ConstraintsHash: ""})
	}))
	defer srv.Close()

	v := New(srv.URL, srv.Client(), time.Second)
	_, err := v.ConstraintsHash(context.Background(), "intent:ref")
	if !errors.Is(err, ErrAuthorityResponse) {
		t.Fatalf("ConstraintsHash with empty hash: error = %v, want ErrAuthorityResponse", err)
	}
}
