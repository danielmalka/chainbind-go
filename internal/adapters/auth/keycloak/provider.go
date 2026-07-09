// Package keycloak validates the HTTP shell's Bearer tokens against a
// Keycloak realm's JWKS, using github.com/lestrrat-go/jwx/v3
// (TECHSPEC-001 §6.6 decision 5). It is the only place the shell decides
// who may seal a package; it has no part in opening one (D-002 — Keycloak's
// role shrinks to gating the shell).
//
// # Why jwt.WithKeySet is the whole defence
//
// jwt.Parse is called with jwt.WithKeySet(set) and nothing that widens it
// (no jws.WithInferAlgorithmFromKey, no per-key "use any algorithm"
// fallback). Every key this provider serves into that set carries an
// explicit "alg" (RS256, from Keycloak's own JWKS), and jwx's key-set
// provider selects an algorithm from the *key*, never from the token's own
// header, before attempting a verification. Two classical bypasses fall out
// of that for free, and both have a test:
//
//   - alg: none. jwx's jws.Verify refuses an unsecured JWS unless the
//     caller opts in with jws.WithInsecureNoSignature — an option this
//     package never passes. A token with `{"alg":"none"}` has no
//     signature to check against any key and is rejected before any key
//     is consulted.
//   - alg confusion (HS256 keyed on the RSA public key bytes). The
//     verifier only ever attempts RS256 against a key whose declared
//     algorithm is RS256; it never re-interprets that key as an HMAC
//     secret because the token's header says HS256. The mismatch between
//     the token's claimed algorithm and the key's declared algorithm is
//     rejected before any cryptographic comparison runs.
//
// jwt.Parse also validates the "aud" claim against the configured audience.
// RoleIssuerAdmin is a Keycloak *realm* role, so it rides on a token minted
// for any client registered in the realm — without an audience check, a
// token issued to an unrelated client but carrying that role would still
// pass.
//
// # Caching
//
// The JWKS is fetched with jwk.Fetch and cached in memory for a fixed TTL,
// keyed by the configured URL — not jwk.NewCache's background-refresh
// actor. A background actor needs its own lifecycle (start, shut down with
// the server) for a benefit this shell does not need: Keycloak's signing
// keys rotate on the order of days, not requests, so a request-time check
// against a short TTL is the simpler mechanism for the same guarantee.
package keycloak

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// RoleIssuerAdmin is the realm role required to call the seal route
// (TECHSPEC-001 §5, §7 "Role bypass on the shell").
const RoleIssuerAdmin = "role_issuer_admin"

// defaultCacheTTL bounds how long a fetched JWKS is reused before the next
// Authorize call re-fetches it. Keycloak's own key-rotation cadence is
// measured in days; a few minutes of staleness costs nothing a real
// deployment would notice, and it is the ceiling this cache trades away in
// exchange for never running a background goroutine.
const defaultCacheTTL = 5 * time.Minute

// defaultFetchTimeout bounds a single JWKS fetch. The caller's own request
// context has no deadline of its own (http.Server does not impose one), so
// without a bound here a slow or hung JWKS endpoint would stall the fetch
// for as long as the client is willing to wait — and, if the fetch held
// p.mu, every concurrent Authorize call behind it too.
const defaultFetchTimeout = 5 * time.Second

// Sentinel errors. Static strings only (architecture invariant 10): no
// token byte, no claim value, ever appears in one of these.
var (
	// ErrUnauthorized means no Bearer token was presented, or the token
	// presented does not verify: missing, malformed, wrong signature,
	// wrong issuer, expired, or not yet valid. The shell maps this to 401.
	ErrUnauthorized = errors.New("keycloak: unauthorized")

	// ErrForbidden means the token verified but its realm_access.roles
	// does not contain RoleIssuerAdmin. The shell maps this to 403.
	ErrForbidden = errors.New("keycloak: forbidden: missing " + RoleIssuerAdmin + " role")
)

// Provider validates Bearer tokens against one Keycloak realm's JWKS.
type Provider struct {
	jwksURL      string
	issuer       string
	audience     string
	client       *http.Client
	cacheTTL     time.Duration
	fetchTimeout time.Duration

	mu        sync.Mutex
	set       jwk.Set
	fetchedAt time.Time
}

// New returns a Provider that fetches jwksURL and requires the "iss" claim
// to equal issuer and the "aud" claim to contain audience. If client is
// nil, http.DefaultClient is used.
func New(jwksURL, issuer, audience string, client *http.Client) *Provider {
	if client == nil {
		client = http.DefaultClient
	}
	return &Provider{
		jwksURL:      jwksURL,
		issuer:       issuer,
		audience:     audience,
		client:       client,
		cacheTTL:     defaultCacheTTL,
		fetchTimeout: defaultFetchTimeout,
	}
}

// Authorize validates bearer (the raw token, with no "Bearer " prefix) and
// requires RoleIssuerAdmin among its realm_access.roles. It returns
// ErrUnauthorized for a missing/invalid token and ErrForbidden for a valid
// token lacking the role, so the shell can tell a 401 from a 403 without
// re-deriving the reason. bearer itself is never logged or wrapped into
// either error (architecture invariant 10 — this applies to token bytes
// exactly as it does to plaintext).
func (p *Provider) Authorize(ctx context.Context, bearer string) error {
	if bearer == "" {
		return ErrUnauthorized
	}

	set, err := p.keySet(ctx)
	if err != nil {
		return fmt.Errorf("%w: fetch jwks", ErrUnauthorized)
	}

	token, err := jwt.Parse(
		[]byte(bearer),
		jwt.WithKeySet(set),
		jwt.WithValidate(true),
		jwt.WithIssuer(p.issuer),
		jwt.WithAudience(p.audience),
	)
	if err != nil {
		return ErrUnauthorized
	}

	if !hasRole(token, RoleIssuerAdmin) {
		return ErrForbidden
	}
	return nil
}

// hasRole reports whether token's realm_access.roles contains role.
// Malformed or absent realm_access is treated as "no roles", never as an
// error — a token that carries no roles simply lacks the one required.
//
// realm_access is decoded into a bare map[string]any, not a typed struct:
// jwt.Token.Get assigns a private claim's already-decoded value via
// reflection (see blackmagic.AssignIfCompatible), and a nested JSON object
// is decoded as map[string]any — it is never re-marshalled through a
// struct's json tags, so a *struct destination is simply incompatible and
// Get would always fail.
func hasRole(token jwt.Token, role string) bool {
	var claim any
	if err := token.Get("realm_access", &claim); err != nil {
		return false
	}
	obj, ok := claim.(map[string]any)
	if !ok {
		return false
	}
	roles, ok := obj["roles"].([]any)
	if !ok {
		return false
	}
	for _, r := range roles {
		if s, ok := r.(string); ok && s == role {
			return true
		}
	}
	return false
}

// keySet returns the cached JWKS, re-fetching it if the cache is empty or
// older than cacheTTL.
//
// The network fetch runs with p.mu released: jwk.Fetch is bounded only by
// fetchTimeout, not by anything a caller controls, and holding the mutex
// across it would stall every concurrent Authorize behind whichever
// goroutine got there first — a single slow JWKS response becomes an
// availability outage for the whole shell. Releasing the lock means two
// goroutines can race to fetch when the cache is stale at the same moment;
// both fetch the same keys and the second write simply overwrites the
// first with an equivalent jwk.Set, which costs an extra HTTP round trip
// and nothing else.
func (p *Provider) keySet(ctx context.Context) (jwk.Set, error) {
	p.mu.Lock()
	set := p.set
	fresh := set != nil && time.Since(p.fetchedAt) < p.cacheTTL
	p.mu.Unlock()

	if fresh {
		return set, nil
	}

	fetchCtx, cancel := context.WithTimeout(ctx, p.fetchTimeout)
	defer cancel()

	fetched, err := jwk.Fetch(fetchCtx, p.jwksURL, jwk.WithHTTPClient(p.client))
	if err != nil {
		return nil, fmt.Errorf("keycloak: fetch jwks: %w", err)
	}

	p.mu.Lock()
	p.set = fetched
	p.fetchedAt = time.Now()
	p.mu.Unlock()

	return fetched, nil
}
