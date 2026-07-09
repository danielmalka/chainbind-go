package http

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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
