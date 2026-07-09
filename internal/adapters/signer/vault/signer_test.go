package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

const testToken = "s.distinctive-test-vault-token-value"

// newKeysHandler serves the GET /v1/transit/keys/{name} response Vault
// would return for a key of the given type, version, and public key.
func newKeysHandler(t *testing.T, keyType string, version int, pub ed25519.PublicKey) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != testToken {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		body := map[string]any{
			"data": map[string]any{
				"latest_version": version,
				"type":           keyType,
				"keys": map[string]any{
					strconv.Itoa(version): map[string]any{
						"public_key": base64.StdEncoding.EncodeToString(pub),
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}
}

// newSigningServer serves both the key-metadata GET and the sign POST,
// routed by path. The sign handler verifies the caller passed
// key_version == wantVersion in the request body, signs the decoded
// input with priv (a real ed25519 key), and replies with Vault's
// "vault:vN:<b64sig>" format using respondVersion in the label (which the
// test can set to something other than wantVersion to simulate Vault
// ignoring key_version).
func newSigningServer(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey, wantVersion, respondVersion int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/transit/keys/test-key", newKeysHandler(t, "ed25519", wantVersion, pub))
	mux.HandleFunc("/v1/transit/sign/test-key", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != testToken {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var req signRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if req.KeyVersion != wantVersion {
			t.Fatalf("sign request key_version = %d, want %d", req.KeyVersion, wantVersion)
		}
		message, err := base64.StdEncoding.DecodeString(req.Input)
		if err != nil {
			t.Fatalf("sign request input is not valid base64: %v", err)
		}
		sig := ed25519.Sign(priv, message)
		resp := map[string]any{
			"data": map[string]any{
				"signature": "vault:v" + strconv.Itoa(respondVersion) + ":" + base64.StdEncoding.EncodeToString(sig),
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	return httptest.NewServer(mux)
}

func TestNew_PinsVersionAndPublicKey_KidFormatsNameVN(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	srv := httptest.NewServer(newKeysHandler(t, "ed25519", 3, pub))
	defer srv.Close()

	s, err := New(context.Background(), srv.URL, testToken, "test-key", srv.Client(), time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	kid, err := s.Kid(context.Background())
	if err != nil {
		t.Fatalf("Kid: %v", err)
	}
	if kid != "test-key:v3" {
		t.Fatalf("Kid = %q, want %q", kid, "test-key:v3")
	}
	if !s.PublicKey().Equal(pub) {
		t.Fatalf("PublicKey() does not match the key Vault reported")
	}
}

// TestSigner_KidMakesNoNetworkCall is the check that makes decision B
// (the version is pinned at construction) real: if Kid ever fell back to
// fetching metadata from Vault, this test would fail the moment the
// server is closed.
func TestSigner_KidMakesNoNetworkCall(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	srv := httptest.NewServer(newKeysHandler(t, "ed25519", 1, pub))

	s, err := New(context.Background(), srv.URL, testToken, "test-key", srv.Client(), time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	srv.Close() // Vault is now unreachable.

	kid, err := s.Kid(context.Background())
	if err != nil {
		t.Fatalf("Kid after server closed: %v, want success (Kid must not call the network)", err)
	}
	if kid != "test-key:v1" {
		t.Fatalf("Kid = %q, want %q", kid, "test-key:v1")
	}
}

// TestSign_RoundTripVerifiesAgainstPublicKey signs a real message with a
// real ed25519 key inside the fake handler, so the round trip through
// this package's wire parsing is genuine rather than a canned blob.
func TestSign_RoundTripVerifiesAgainstPublicKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	srv := newSigningServer(t, pub, priv, 3, 3)
	defer srv.Close()

	s, err := New(context.Background(), srv.URL, testToken, "test-key", srv.Client(), time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	message := []byte(`{"package_id":"pkg_test_0001"}`)
	sig, err := s.Sign(context.Background(), message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("Sign returned %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(s.PublicKey(), message, sig) {
		t.Fatal("signature returned by Sign does not verify against PublicKey()")
	}
}

func TestSign_RejectsVersionMismatch(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	// Vault pins/reports version 3 at metadata time but the sign response
	// claims version 9 — simulating Vault ignoring key_version.
	srv := newSigningServer(t, pub, priv, 3, 9)
	defer srv.Close()

	s, err := New(context.Background(), srv.URL, testToken, "test-key", srv.Client(), time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = s.Sign(context.Background(), []byte("message"))
	if err == nil {
		t.Fatal("Sign with mismatched response version: got nil error, want one")
	}
	if !errors.Is(err, ErrKeyVersionMismatch) {
		t.Fatalf("Sign error = %v, want errors.Is ErrKeyVersionMismatch", err)
	}
}

func TestNew_RejectsUnsupportedKeyType(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	srv := httptest.NewServer(newKeysHandler(t, "ecdsa-p256", 1, pub))
	defer srv.Close()

	_, err = New(context.Background(), srv.URL, testToken, "test-key", srv.Client(), time.Second)
	if err == nil {
		t.Fatal("New with ecdsa-p256 key: got nil error, want one")
	}
	if !errors.Is(err, ErrKeyTypeUnsupported) {
		t.Fatalf("New error = %v, want errors.Is ErrKeyTypeUnsupported", err)
	}
}

func TestNew_NonOKStatus_Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := New(context.Background(), srv.URL, testToken, "test-key", srv.Client(), time.Second)
	if !errors.Is(err, ErrVaultResponse) {
		t.Fatalf("New against 500: error = %v, want errors.Is ErrVaultResponse", err)
	}
}

func TestNew_MalformedJSON_Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{not json"))
	}))
	defer srv.Close()

	_, err := New(context.Background(), srv.URL, testToken, "test-key", srv.Client(), time.Second)
	if !errors.Is(err, ErrVaultResponse) {
		t.Fatalf("New with malformed JSON: error = %v, want errors.Is ErrVaultResponse", err)
	}
}

func TestNew_ClosedServer_Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	url := srv.URL
	srv.Close()

	_, err := New(context.Background(), url, testToken, "test-key", nil, time.Second)
	if !errors.Is(err, ErrVaultUnreachable) {
		t.Fatalf("New against closed server: error = %v, want errors.Is ErrVaultUnreachable", err)
	}
}

// signerAgainstSignHandler builds a Signer whose key metadata is valid
// (version 3, ed25519) but whose sign endpoint is replaced by h, to drive
// Sign's own failure paths independent of New.
func signerAgainstSignHandler(t *testing.T, h http.HandlerFunc) (*Signer, *httptest.Server) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/transit/keys/test-key", newKeysHandler(t, "ed25519", 3, pub))
	mux.HandleFunc("/v1/transit/sign/test-key", h)
	srv := httptest.NewServer(mux)

	s, err := New(context.Background(), srv.URL, testToken, "test-key", srv.Client(), time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s, srv
}

func writeSignatureJSON(w http.ResponseWriter, signature string) {
	w.Header().Set("Content-Type", "application/json")
	resp := map[string]any{"data": map[string]any{"signature": signature}}
	_ = json.NewEncoder(w).Encode(resp)
}

func TestSign_NonOKStatus_Errors(t *testing.T) {
	s, srv := signerAgainstSignHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer srv.Close()

	_, err := s.Sign(context.Background(), []byte("message"))
	if !errors.Is(err, ErrVaultResponse) {
		t.Fatalf("Sign against 500: error = %v, want errors.Is ErrVaultResponse", err)
	}
}

func TestSign_MalformedJSON_Errors(t *testing.T) {
	s, srv := signerAgainstSignHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{not json"))
	})
	defer srv.Close()

	_, err := s.Sign(context.Background(), []byte("message"))
	if !errors.Is(err, ErrVaultResponse) {
		t.Fatalf("Sign with malformed JSON: error = %v, want errors.Is ErrVaultResponse", err)
	}
}

func TestSign_MalformedSignaturePrefix_Errors(t *testing.T) {
	s, srv := signerAgainstSignHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		writeSignatureJSON(w, "not-the-vault-format")
	})
	defer srv.Close()

	_, err := s.Sign(context.Background(), []byte("message"))
	if !errors.Is(err, ErrVaultResponse) {
		t.Fatalf("Sign with malformed signature prefix: error = %v, want errors.Is ErrVaultResponse", err)
	}
}

func TestSign_WrongSignatureLength_Errors(t *testing.T) {
	s, srv := signerAgainstSignHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		short := base64.StdEncoding.EncodeToString([]byte("too-short"))
		writeSignatureJSON(w, "vault:v3:"+short)
	})
	defer srv.Close()

	_, err := s.Sign(context.Background(), []byte("message"))
	if !errors.Is(err, ErrVaultResponse) {
		t.Fatalf("Sign with wrong-length signature: error = %v, want errors.Is ErrVaultResponse", err)
	}
}

func TestSign_ClosedServer_Errors(t *testing.T) {
	s, srv := signerAgainstSignHandler(t, func(_ http.ResponseWriter, _ *http.Request) {})
	srv.Close()

	_, err := s.Sign(context.Background(), []byte("message"))
	if !errors.Is(err, ErrVaultUnreachable) {
		t.Fatalf("Sign against closed server: error = %v, want errors.Is ErrVaultUnreachable", err)
	}
}

// TestErrors_NeverLeakToken drives every failure path this package has
// with a distinctive token value and asserts the token never appears in
// any resulting error string (AGENTS.local.md invariant 10).
func TestErrors_NeverLeakToken(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	assertNoToken := func(t *testing.T, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		if strings.Contains(err.Error(), testToken) {
			t.Fatalf("error leaks the vault token: %q", err.Error())
		}
	}

	t.Run("New non-200", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Vault-Token") != testToken {
				t.Fatalf("request missing expected token header")
			}
			w.WriteHeader(http.StatusForbidden)
		}))
		defer srv.Close()
		_, err := New(context.Background(), srv.URL, testToken, "test-key", srv.Client(), time.Second)
		assertNoToken(t, err)
	})

	t.Run("New unreachable", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
		url := srv.URL
		srv.Close()
		_, err := New(context.Background(), url, testToken, "test-key", nil, time.Second)
		assertNoToken(t, err)
	})

	t.Run("New wrong key type", func(t *testing.T) {
		srv := httptest.NewServer(newKeysHandler(t, "ecdsa-p256", 1, pub))
		defer srv.Close()
		_, err := New(context.Background(), srv.URL, testToken, "test-key", srv.Client(), time.Second)
		assertNoToken(t, err)
	})

	t.Run("Sign version mismatch", func(t *testing.T) {
		srv := newSigningServer(t, pub, priv, 3, 9)
		defer srv.Close()
		s, err := New(context.Background(), srv.URL, testToken, "test-key", srv.Client(), time.Second)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		_, err = s.Sign(context.Background(), []byte("message"))
		assertNoToken(t, err)
	})

	t.Run("Sign non-200", func(t *testing.T) {
		s, srv := signerAgainstSignHandler(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})
		defer srv.Close()
		_, err := s.Sign(context.Background(), []byte("message"))
		assertNoToken(t, err)
	})

	t.Run("Sign closed server", func(t *testing.T) {
		s, srv := signerAgainstSignHandler(t, func(_ http.ResponseWriter, _ *http.Request) {})
		srv.Close()
		_, err := s.Sign(context.Background(), []byte("message"))
		assertNoToken(t, err)
	})
}

// TestNew_EscapesKeyNameInPath pins the URL construction. An unescaped key
// name walks out of the transit mount and appends a query string the adapter
// never meant to send: "../../sys/health?list=true" reached the server as
// path "/v1/transit/keys/../../sys/health" with query "list=true". The key
// name comes from an operator's environment, not an attacker's, so this is
// defence in depth — but the intent HTTP adapter already escapes its path
// segment, and an adapter that talks to the key store should not be the
// laxer of the two.
func TestNew_EscapesKeyNameInPath(t *testing.T) {
	const hostile = "../../sys/health?list=true"

	var gotURI, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// RequestURI is the wire form. r.URL.Path is the *decoded* form, in
		// which %2F has already become "/" again — asserting on it would
		// fail even against a correctly escaped request, and asserting on it
		// passing would prove nothing about what Vault receives.
		gotURI, gotQuery = r.RequestURI, r.URL.RawQuery
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, _ = New(context.Background(), srv.URL, "tok", hostile, nil, time.Second)

	if gotQuery != "" {
		t.Fatalf("key name injected a query string: %q", gotQuery)
	}
	prefix := "/v1/transit/keys/"
	if !strings.HasPrefix(gotURI, prefix) {
		t.Fatalf("request URI = %q, want it to stay under %q", gotURI, prefix)
	}
	if strings.ContainsAny(strings.TrimPrefix(gotURI, prefix), "/?") {
		t.Fatalf("key name was not escaped: request URI = %q", gotURI)
	}
}

// TestPublicKey_ReturnsACopy proves a caller cannot reach into the Signer and
// change the key it believes it signs under. Not a secrecy property — a
// public key is public — but a mutated slice would turn every later
// verification into an unexplained failure.
func TestPublicKey_ReturnsACopy(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	srv := newSigningServer(t, pub, priv, 3, 3)
	defer srv.Close()

	s, err := New(context.Background(), srv.URL, testToken, "test-key", nil, time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got := s.PublicKey()
	got[0] ^= 0xFF

	if !bytes.Equal(s.PublicKey(), pub) {
		t.Fatal("mutating the slice PublicKey returned changed the Signer's own key")
	}
}
