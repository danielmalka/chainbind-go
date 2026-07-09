package keycloak

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

const (
	testKid      = "test-key-1"
	testIssuer   = "https://keycloak.example.test/realms/chainbind"
	testAudience = "chainbind-api"
)

// testRealm bundles a generated RSA keypair, the JWKS a Keycloak realm
// would publish for it, and an httptest server serving that JWKS — enough
// to build a Provider and sign tokens against it.
type testRealm struct {
	priv *rsa.PrivateKey
	srv  *httptest.Server
}

func newTestRealm(t *testing.T) *testRealm {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	pubJWK, err := jwk.Import(priv.Public())
	if err != nil {
		t.Fatalf("jwk.Import public key: %v", err)
	}
	if err := pubJWK.Set(jwk.KeyIDKey, testKid); err != nil {
		t.Fatalf("set kid: %v", err)
	}
	if err := pubJWK.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
		t.Fatalf("set alg: %v", err)
	}

	set := jwk.NewSet()
	if err := set.AddKey(pubJWK); err != nil {
		t.Fatalf("add key to set: %v", err)
	}

	body, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	return &testRealm{priv: priv, srv: srv}
}

func (r *testRealm) provider() *Provider {
	return New(r.srv.URL, testIssuer, testAudience, r.srv.Client())
}

// signToken builds a token with the given claims (merged over sane
// defaults: issuer, issued-at, one-hour expiry) and signs it RS256 under
// the realm's private key and kid — the "valid token" baseline every
// negative test starts from and mutates one field of.
func (r *testRealm) signToken(t *testing.T, claims map[string]any, roles []string) []byte {
	t.Helper()

	b := jwt.NewBuilder().
		Issuer(testIssuer).
		Audience([]string{testAudience}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour))
	if roles != nil {
		b = b.Claim("realm_access", map[string]any{"roles": roles})
	}
	for k, v := range claims {
		b = b.Claim(k, v)
	}
	tok, err := b.Build()
	if err != nil {
		t.Fatalf("build token: %v", err)
	}

	privJWK, err := jwk.Import(r.priv)
	if err != nil {
		t.Fatalf("jwk.Import private key: %v", err)
	}
	if err := privJWK.Set(jwk.KeyIDKey, testKid); err != nil {
		t.Fatalf("set kid: %v", err)
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), privJWK))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func TestAuthorize_ValidTokenWithRole_Nil(t *testing.T) {
	r := newTestRealm(t)
	tok := r.signToken(t, nil, []string{RoleIssuerAdmin})

	if err := r.provider().Authorize(context.Background(), string(tok)); err != nil {
		t.Fatalf("Authorize: %v, want nil", err)
	}
}

func TestAuthorize_ValidTokenMissingRole_Forbidden(t *testing.T) {
	r := newTestRealm(t)
	tok := r.signToken(t, nil, []string{"some-other-role"})

	err := r.provider().Authorize(context.Background(), string(tok))
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("Authorize with no role_issuer_admin: error = %v, want ErrForbidden", err)
	}
}

func TestAuthorize_NoRealmAccessClaim_Forbidden(t *testing.T) {
	r := newTestRealm(t)
	tok := r.signToken(t, nil, nil)

	err := r.provider().Authorize(context.Background(), string(tok))
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("Authorize with no realm_access claim: error = %v, want ErrForbidden", err)
	}
}

func TestAuthorize_EmptyBearer_Unauthorized(t *testing.T) {
	r := newTestRealm(t)

	err := r.provider().Authorize(context.Background(), "")
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Authorize with empty bearer: error = %v, want ErrUnauthorized", err)
	}
}

func TestAuthorize_ExpiredToken_Unauthorized(t *testing.T) {
	r := newTestRealm(t)

	privJWK, err := jwk.Import(r.priv)
	if err != nil {
		t.Fatalf("jwk.Import: %v", err)
	}
	if err := privJWK.Set(jwk.KeyIDKey, testKid); err != nil {
		t.Fatalf("set kid: %v", err)
	}

	tok, err := jwt.NewBuilder().
		Issuer(testIssuer).
		IssuedAt(time.Now().Add(-2*time.Hour)).
		Expiration(time.Now().Add(-time.Hour)).
		Claim("realm_access", map[string]any{"roles": []string{RoleIssuerAdmin}}).
		Build()
	if err != nil {
		t.Fatalf("build token: %v", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), privJWK))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	err = r.provider().Authorize(context.Background(), string(signed))
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Authorize with an expired token: error = %v, want ErrUnauthorized", err)
	}
}

func TestAuthorize_WrongIssuer_Unauthorized(t *testing.T) {
	r := newTestRealm(t)
	tok := r.signToken(t, map[string]any{"iss": "https://not-this-realm.example.test"}, []string{RoleIssuerAdmin})

	err := r.provider().Authorize(context.Background(), string(tok))
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Authorize with the wrong issuer: error = %v, want ErrUnauthorized", err)
	}
}

// TestAuthorize_AlgNone_Unauthorized is the classic JWT bypass: a token
// whose header claims {"alg":"none"} and carries no signature at all. If
// this were ever accepted, any caller could mint a token naming any role
// with no key at all. jwx refuses to build or verify one unless the
// caller explicitly opts in with jws.WithInsecureNoSignature — this
// package never does, so Parse must reject it before any key is
// consulted.
func TestAuthorize_AlgNone_Unauthorized(t *testing.T) {
	r := newTestRealm(t)

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(
		`{"iss":"` + testIssuer + `","realm_access":{"roles":["` + RoleIssuerAdmin + `"]},"exp":` +
			jsonInt(time.Now().Add(time.Hour).Unix()) + `}`,
	))
	forged := header + "." + payload + "."

	err := r.provider().Authorize(context.Background(), forged)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Authorize with alg=none: error = %v, want ErrUnauthorized", err)
	}
}

// TestAuthorize_HS256KeyedOnRSAPublicKey_Unauthorized is the other classic
// bypass: an attacker who knows the RSA public key (JWKS is public by
// design) resigns the token with HS256, using the public key's own bytes
// as the HMAC secret — a forgery that succeeds against any verifier naive
// enough to try every algorithm against every key it is holding. jwx's
// key-set provider selects the algorithm to attempt from the key's own
// declared "alg" (RS256, published in the JWKS), never from the token's
// header, so this must fail before any HMAC comparison ever runs.
func TestAuthorize_HS256KeyedOnRSAPublicKey_Unauthorized(t *testing.T) {
	r := newTestRealm(t)

	// The forged HMAC secret: the RSA public key's own modulus bytes,
	// which any holder of the JWKS already has.
	secret := r.priv.PublicKey.N.Bytes()

	hdrs := jws.NewHeaders()
	if err := hdrs.Set(jws.KeyIDKey, testKid); err != nil {
		t.Fatalf("set kid header: %v", err)
	}

	tok, err := jwt.NewBuilder().
		Issuer(testIssuer).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Claim("realm_access", map[string]any{"roles": []string{RoleIssuerAdmin}}).
		Build()
	if err != nil {
		t.Fatalf("build token: %v", err)
	}

	forged, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256(), secret, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Fatalf("sign forged HS256 token: %v", err)
	}

	err = r.provider().Authorize(context.Background(), string(forged))
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Authorize with HS256-on-RSA-public-key forgery: error = %v, want ErrUnauthorized", err)
	}
}

func jsonInt(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// TestAuthorize_WrongAudience_Unauthorized closes the gap a realm role
// leaves open: role_issuer_admin rides on a token minted for any client in
// the realm, so a correctly issued, correctly signed token naming a
// different "aud" must still be rejected.
func TestAuthorize_WrongAudience_Unauthorized(t *testing.T) {
	r := newTestRealm(t)
	tok := r.signToken(t, map[string]any{"aud": "some-other-client"}, []string{RoleIssuerAdmin})

	err := r.provider().Authorize(context.Background(), string(tok))
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Authorize with the wrong audience: error = %v, want ErrUnauthorized", err)
	}
}

// TestAuthorize_SlowJWKS_FailsClosedWithinTimeout proves keySet no longer
// holds p.mu across the network fetch: a JWKS endpoint that blocks well
// past fetchTimeout must still make Authorize return ErrUnauthorized
// (fail closed) within a bound comfortably under the blocking time, not
// after it.
func TestAuthorize_SlowJWKS_FailsClosedWithinTimeout(t *testing.T) {
	const blockFor = 2 * time.Second
	const testFetchTimeout = 100 * time.Millisecond
	const bound = 1 * time.Second

	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case <-release:
		case <-time.After(blockFor):
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	defer close(release)

	p := New(srv.URL, testIssuer, testAudience, srv.Client())
	p.fetchTimeout = testFetchTimeout

	start := time.Now()
	err := p.Authorize(context.Background(), "irrelevant-token")
	elapsed := time.Since(start)

	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Authorize against a slow JWKS: error = %v, want ErrUnauthorized", err)
	}
	if elapsed >= bound {
		t.Fatalf("Authorize against a slow JWKS took %v, want under %v (blocked %v)", elapsed, bound, blockFor)
	}
}

// TestAuthorize_NotYetValid_Unauthorized pins the "nbf" (not-before) guard:
// a token that has not yet become valid must not be accepted early.
func TestAuthorize_NotYetValid_Unauthorized(t *testing.T) {
	r := newTestRealm(t)
	tok := r.signToken(t, map[string]any{"nbf": time.Now().Add(time.Hour).Unix()}, []string{RoleIssuerAdmin})

	err := r.provider().Authorize(context.Background(), string(tok))
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Authorize with a not-yet-valid token: error = %v, want ErrUnauthorized", err)
	}
}

// TestAuthorize_SignedByUnknownKey_Unauthorized: the token's header names a
// kid the JWKS does recognize, but the signature was actually produced by
// a different RSA key entirely — the signature must fail to verify against
// the key the kid points to.
func TestAuthorize_SignedByUnknownKey_Unauthorized(t *testing.T) {
	r := newTestRealm(t)

	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	otherJWK, err := jwk.Import(other)
	if err != nil {
		t.Fatalf("jwk.Import other private key: %v", err)
	}
	if err := otherJWK.Set(jwk.KeyIDKey, testKid); err != nil {
		t.Fatalf("set kid: %v", err)
	}

	tok, err := jwt.NewBuilder().
		Issuer(testIssuer).
		Audience([]string{testAudience}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Claim("realm_access", map[string]any{"roles": []string{RoleIssuerAdmin}}).
		Build()
	if err != nil {
		t.Fatalf("build token: %v", err)
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), otherJWK))
	if err != nil {
		t.Fatalf("sign with unknown key: %v", err)
	}

	err = r.provider().Authorize(context.Background(), string(signed))
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Authorize signed by an unknown key: error = %v, want ErrUnauthorized", err)
	}
}

// TestAuthorize_UnknownKid_Unauthorized: the token's header names a kid
// absent from the JWKS entirely, so the verifier has no key to even
// attempt.
func TestAuthorize_UnknownKid_Unauthorized(t *testing.T) {
	r := newTestRealm(t)

	privJWK, err := jwk.Import(r.priv)
	if err != nil {
		t.Fatalf("jwk.Import: %v", err)
	}
	if err := privJWK.Set(jwk.KeyIDKey, "no-such-kid"); err != nil {
		t.Fatalf("set kid: %v", err)
	}

	tok, err := jwt.NewBuilder().
		Issuer(testIssuer).
		Audience([]string{testAudience}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Claim("realm_access", map[string]any{"roles": []string{RoleIssuerAdmin}}).
		Build()
	if err != nil {
		t.Fatalf("build token: %v", err)
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), privJWK))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	err = r.provider().Authorize(context.Background(), string(signed))
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Authorize with an unknown kid: error = %v, want ErrUnauthorized", err)
	}
}

// TestAuthorize_TamperedPayload_Unauthorized takes a validly signed token
// and swaps its payload segment for a re-encoded (and role-escalated)
// claim set, leaving the original signature untouched — the classic
// "cut and paste a different body" tamper. The signature was computed over
// the original payload, so it must not verify against the new one.
func TestAuthorize_TamperedPayload_Unauthorized(t *testing.T) {
	r := newTestRealm(t)
	tok := r.signToken(t, nil, []string{"some-other-role"})

	parts := strings.Split(string(tok), ".")
	if len(parts) != 3 {
		t.Fatalf("signed token has %d segments, want 3", len(parts))
	}

	forgedPayload := base64.RawURLEncoding.EncodeToString([]byte(
		`{"iss":"` + testIssuer + `","aud":"` + testAudience + `","realm_access":{"roles":["` + RoleIssuerAdmin + `"]},"exp":` +
			jsonInt(time.Now().Add(time.Hour).Unix()) + `}`,
	))
	tampered := parts[0] + "." + forgedPayload + "." + parts[2]

	err := r.provider().Authorize(context.Background(), tampered)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Authorize with a tampered payload: error = %v, want ErrUnauthorized", err)
	}
}
