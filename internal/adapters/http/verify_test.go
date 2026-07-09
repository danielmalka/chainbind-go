package http

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/danielmalka/chainbind-go/internal/adapters/keywrap/x25519"
	"github.com/danielmalka/chainbind-go/pkg/chainbind"
	"github.com/danielmalka/chainbind-go/pkg/chainbind/profile/agenticcheckout"
)

// verifyTestServer builds a NewHandler with a real signer, so verify can
// check a genuine signature, and a caller-controlled intent authority.
func verifyTestServer(t *testing.T, signer *sealSigner, intent chainbind.IntentVerifier) http.Handler {
	t.Helper()
	return NewHandler(HandlerConfig{
		Authorizer:      &fakeAuthorizer{},
		Signer:          signer.signer,
		KeyWrapper:      x25519.Wrapper{},
		Audiences:       nil,
		IntentVerifier:  intent,
		IssuerKey:       issuerKeyResolver(signer.kid, signer.pub),
		VaultProber:     &fakeProber{},
		AuthorityProber: &fakeProber{},
	})
}

// sealSigner bundles a signer with the kid/pub Verify needs to trust it —
// pinned once so seal and verify agree on exactly what Seal produced.
type sealSigner struct {
	signer chainbind.Signer
	kid    string
	pub    ed25519.PublicKey
}

func newSealSigner(t *testing.T) *sealSigner {
	t.Helper()
	s, pub := testSigner(t)
	kid, err := s.Kid(context.Background())
	if err != nil {
		t.Fatalf("Kid: %v", err)
	}
	return &sealSigner{signer: s, kid: kid, pub: pub}
}

// sealedPackage produces a real, validly signed Package by calling
// chainbind.Seal directly (bypassing the HTTP shell), so verify tests
// exercise a genuine signature and genuine bindings — the same shape
// sealHandler itself builds, reproduced here so verify_test.go does not
// depend on driving the seal route first.
func sealedPackage(t *testing.T, s *sealSigner, intent chainbind.IntentVerifier) *chainbind.Package {
	t.Helper()

	auds, err := LoadAudiences(testAudiencesFile(t))
	if err != nil {
		t.Fatalf("LoadAudiences: %v", err)
	}

	payload := validCheckoutPayload()
	profile := agenticcheckout.Profile{}
	segments, err := profile.Split(payload)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	projection, err := profile.Project(payload)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}

	req := chainbind.SealRequest{
		Segments:     segments,
		SegmentOrder: agenticcheckout.SegmentOrder(),
		Audiences:    auds,
		IntentRef:    payload.Intent.IntentRef,
		Authority:    payload.Intent.Authority,
		Projection:   projection,
		Issuer:       payload.RequestContext.IssuedBy,
		IssuedAt:     time.Now().UTC(),
		TenantID:     payload.RequestContext.TenantID,
		Environment:  payload.RequestContext.Environment,
		Profile:      agenticcheckout.Name,
		BindingSpecs: agenticcheckout.BindingSpecs(),
	}

	pkg, sealErr := chainbind.Seal(context.Background(), req, s.signer, x25519.Wrapper{}, intent)
	if sealErr != nil {
		t.Fatalf("Seal: %v", sealErr)
	}
	return pkg
}

func verifyPostRequest(t *testing.T, body []byte, contentType string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/packages/verify", bytes.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return req
}

func TestVerifyHandler_HappyPath_200_OKTrue(t *testing.T) {
	signer := newSealSigner(t)
	intent := allowingIntentVerifier()
	pkg := sealedPackage(t, signer, intent)

	h := verifyTestServer(t, signer, intent)
	body, _ := json.Marshal(pkg)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, verifyPostRequest(t, body, "application/json"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var report chainbind.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatalf("decode Report: %v", err)
	}
	if !report.OK() {
		t.Fatalf("Report.OK() = false, want true: %+v", report)
	}
}

// TestVerifyHandler_TamperedPackage_StillReturns200_OKFalse pins decision
// C: a package that fails verification is still a 200 carrying a Report
// with OK()==false, never a non-2xx status. This is the test a "helpful"
// later change most often breaks by mapping !OK() to 422.
func TestVerifyHandler_TamperedPackage_StillReturns200_OKFalse(t *testing.T) {
	signer := newSealSigner(t)
	intent := allowingIntentVerifier()
	pkg := sealedPackage(t, signer, intent)

	// Flip a byte in one segment's ciphertext: the signature (over the
	// manifest, not the segments) still verifies, but L1.4's cipher_hash
	// comparison now fails.
	for name, seg := range pkg.Segments {
		raw, err := base64.RawURLEncoding.DecodeString(seg.Ciphertext)
		if err != nil {
			t.Fatalf("decode ciphertext: %v", err)
		}
		if len(raw) == 0 {
			continue
		}
		raw[0] ^= 0xFF
		seg.Ciphertext = base64.RawURLEncoding.EncodeToString(raw)
		pkg.Segments[name] = seg
		break
	}

	h := verifyTestServer(t, signer, intent)
	body, _ := json.Marshal(pkg)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, verifyPostRequest(t, body, "application/json"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 even for a failing report, body=%s", rec.Code, rec.Body.String())
	}
	var report chainbind.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatalf("decode Report: %v", err)
	}
	if report.OK() {
		t.Fatal("Report.OK() = true for a tampered package, want false")
	}
}

func TestVerifyHandler_MalformedBody_400(t *testing.T) {
	signer := newSealSigner(t)
	h := verifyTestServer(t, signer, allowingIntentVerifier())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, verifyPostRequest(t, []byte("{not json"), "application/json"))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
	assertProblemContentType(t, rec)
}

func TestVerifyHandler_WrongContentType_415(t *testing.T) {
	signer := newSealSigner(t)
	h := verifyTestServer(t, signer, allowingIntentVerifier())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, verifyPostRequest(t, []byte(`{}`), "text/plain"))

	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415, body=%s", rec.Code, rec.Body.String())
	}
	assertProblemContentType(t, rec)
}

func TestVerifyHandler_UnsupportedSpecVersion_422(t *testing.T) {
	signer := newSealSigner(t)
	h := verifyTestServer(t, signer, allowingIntentVerifier())

	body, _ := json.Marshal(chainbind.Package{SpecVersion: "9.9.9"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, verifyPostRequest(t, body, "application/json"))

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422, body=%s", rec.Code, rec.Body.String())
	}
	assertProblemContentType(t, rec)
}

// TestVerifyHandler_StructuralRendersAsText pins that the verify response
// renders Report.Structural as its name, not as the ordinal of its iota
// block. encoding/json ignores fmt.Stringer, so before the core's
// StructuralFault.MarshalJSON a client reading this endpoint saw
// "Structural": 4 — a number with no legend. This test lands with the shell
// because it is the shell's response contract; it began passing only once
// the branch rebased onto the core fix.
//
// A structurally malformed package (empty segment_order) makes Level 1 abort
// at L1.1 with a non-FaultNone Structural, which is what puts a real fault
// value on the wire.
func TestVerifyHandler_StructuralRendersAsText(t *testing.T) {
	signer := newSealSigner(t)
	intent := allowingIntentVerifier()
	pkg := sealedPackage(t, signer, intent)

	pkg.Manifest.SegmentOrder = nil // structural fault at L1.1

	h := verifyTestServer(t, signer, intent)
	body, _ := json.Marshal(pkg)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, verifyPostRequest(t, body, "application/json"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	// Inspect the raw body, not a decoded Report: decoding into the struct
	// would hide the very thing under test, since Report.Structural
	// round-trips through the same MarshalJSON either way.
	var generic map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &generic); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if _, isNumber := generic["Structural"].(float64); isNumber {
		t.Fatalf("Structural rendered as a bare ordinal: %s", rec.Body.String())
	}
	got, ok := generic["Structural"].(string)
	if !ok || got == "" {
		t.Fatalf("Structural is not a non-empty string: %s", rec.Body.String())
	}
	if got != chainbind.FaultEmptySegmentOrder.String() {
		t.Fatalf("Structural = %q, want %q", got, chainbind.FaultEmptySegmentOrder.String())
	}
}
