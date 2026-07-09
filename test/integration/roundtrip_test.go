//go:build integration

// Package integration drives a full seal -> verify -> open round trip against
// the running compose stack (TASK-001-14). It is kept out of the normal gate by
// the `integration` build tag: `make check-strict` never compiles it, and it is
// meaningless without `make up` having provisioned the stack first.
//
// It proves PRD Story 6: one command (`make up`) brings up a stack that
// completes the round trip with zero manual steps, and /ready reflects reachable
// dependencies. Opening happens here in the test process with the seeded
// recipient private keys — never on the server (D-002, invariant 1).
package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/danielmalka/chainbind-go/internal/adapters/keywrap/x25519"
	"github.com/danielmalka/chainbind-go/pkg/chainbind"
	"github.com/danielmalka/chainbind-go/pkg/chainbind/profile/agenticcheckout"
)

// Stack coordinates. Overridable by env so the test can point at a stack
// exposed on different host ports, but the defaults match docker-compose.yml.
func apiURL() string {
	return envOr("CHAINBIND_IT_API_URL", "http://localhost:8088")
}

func tokenURL() string {
	return envOr("CHAINBIND_IT_TOKEN_URL", "http://localhost:8080/realms/chainbind/protocol/openid-connect/token")
}

func secretsDir() string {
	return envOr("CHAINBIND_IT_SECRETS_DIR", filepath.FromSlash("../../deployments/secrets"))
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// payloadJSON is the checkout payload the round trip seals. Its intent_ref
// names testdata/authorizations/checkout-allow.json, whose rules the projected
// amount/currency satisfy, so the intent authority allows the seal.
const payloadJSON = `{
  "request_context": {"tenant_id":"demo-tenant","environment":"dev","request_id":"req-it-0001","correlation_id":"corr-it-0001","issued_by":"integration-test"},
  "intent": {"intent_ref":"intent:checkout-allow","authority":"http://authority:9000"},
  "subject": {"user_id":"usr_123","account_id":"acc_456","name":"Joao Silva","email":"joao.silva@example.com","roles":["role_user"],"permissions":["checkout:create"],"account_status":"active"},
  "checkout": {"checkout_id":"chk_789","merchant_id":"mer_001","merchant_name":"Tech Store BR","currency":"BRL","items":[{"sku":"SKU-123","name":"Notebook Pro 14","quantity":1,"unit_price":899900}],"subtotal":899900,"shipping":2500,"discount":10000,"total":892400},
  "payment": {"payment_id":"pay_001","payment_method":"pix","bank_account_masked":"***1234","bank_code":"341","payment_reference":"pix-it-0001","transaction_status":"pending","amount":892400}
}`

// TestRoundTrip_SealVerifyOpen is the real acceptance gate for TASK-001-14:
// against the live stack, obtain a token, seal, verify (OK must be true), and
// open every segment with its seeded key, asserting the recovered plaintext.
func TestRoundTrip_SealVerifyOpen(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// /ready must be 200 while the stack is up (PRD Story 6 AC-2).
	if code := getStatus(t, ctx, apiURL()+"/ready"); code != http.StatusOK {
		t.Fatalf("/ready = %d, want 200", code)
	}

	token := obtainToken(t, ctx)

	// Seal.
	pkgBytes := doJSON(t, ctx, http.MethodPost, apiURL()+"/v1/packages/seal", []byte(payloadJSON), token, http.StatusOK)
	var pkg chainbind.Package
	if err := json.Unmarshal(pkgBytes, &pkg); err != nil {
		t.Fatalf("decode sealed package: %v\nbody=%s", err, pkgBytes)
	}
	if len(pkg.Segments) == 0 {
		t.Fatalf("sealed package has no segments: %s", pkgBytes)
	}

	// Verify: the Report must be OK() (intent evaluated and valid).
	reportBytes := doJSON(t, ctx, http.MethodPost, apiURL()+"/v1/packages/verify", pkgBytes, "", http.StatusOK)
	var report chainbind.Report
	if err := json.Unmarshal(reportBytes, &report); err != nil {
		t.Fatalf("decode report: %v\nbody=%s", err, reportBytes)
	}
	if !report.OK() {
		t.Fatalf("verify report not OK: %s", reportBytes)
	}

	// Open every segment with its seeded recipient key and assert the
	// recovered plaintext equals exactly that audience's split segment.
	var payload agenticcheckout.Payload
	if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	wantSegments, err := agenticcheckout.Profile{}.Split(payload)
	if err != nil {
		t.Fatalf("split payload: %v", err)
	}

	issuerPub := readIssuerPub(t)
	opt := chainbind.VerifyOptions{
		IssuerKey:    func(string, string) (ed25519.PublicKey, bool) { return issuerPub, true },
		BindingSpecs: agenticcheckout.BindingSpecs(),
	}

	for _, name := range agenticcheckout.SegmentOrder() {
		priv := readRecipientKey(t, name)
		gotAud, plaintext, err := chainbind.Open(ctx, &pkg, priv, x25519.Wrapper{}, opt)
		if err != nil {
			t.Fatalf("open(%s): %v", name, err)
		}
		if gotAud != name {
			t.Errorf("open(%s): recovered audience %q, want %q", name, gotAud, name)
		}
		if !bytes.Equal(plaintext, wantSegments[name]) {
			t.Errorf("open(%s): plaintext = %s, want %s", name, plaintext, wantSegments[name])
		}
	}
}

// obtainToken runs a password grant against Keycloak and returns the raw access
// token. This is exactly how `make demo` and any client obtains one.
func obtainToken(t *testing.T, ctx context.Context) string {
	t.Helper()
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {"chainbind-api"},
		"username":   {"issuer"},
		"password":   {"issuer"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL(), strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token endpoint = %d: %s", resp.StatusCode, body)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.AccessToken == "" {
		t.Fatalf("decode token: %v\nbody=%s", err, body)
	}
	return tok.AccessToken
}

// doJSON POSTs/does body to url with an optional bearer token, requires want,
// and returns the response body.
func doJSON(t *testing.T, ctx context.Context, method, url string, body []byte, token string, want int) []byte {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build request %s: %v", url, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	got, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		t.Fatalf("%s %s = %d, want %d: %s", method, url, resp.StatusCode, want, got)
	}
	return got
}

// getStatus does a GET and returns the status code.
func getStatus(t *testing.T, ctx context.Context, url string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		t.Fatalf("build GET %s: %v", url, err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

// readIssuerPub reads the Vault issuer public key seeded by bootstrap-vault.sh.
func readIssuerPub(t *testing.T) ed25519.PublicKey {
	t.Helper()
	b := readB64URL(t, filepath.Join(secretsDir(), "issuer.pub"))
	if len(b) != ed25519.PublicKeySize {
		t.Fatalf("issuer.pub decoded to %d bytes, want %d", len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b)
}

// readRecipientKey reads a seeded X25519 private key for the named audience.
func readRecipientKey(t *testing.T, name string) []byte {
	t.Helper()
	b := readB64URL(t, filepath.Join(secretsDir(), "keys", name+".key"))
	if len(b) != 32 {
		t.Fatalf("%s.key decoded to %d bytes, want 32", name, len(b))
	}
	return b
}

func readB64URL(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (did `make up`/`make seed` run?)", path, err)
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("decode %s as base64url: %v", path, err)
	}
	return b
}
