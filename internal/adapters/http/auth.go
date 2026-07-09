package http

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/danielmalka/chainbind-go/internal/adapters/auth/keycloak"
)

// Authorizer is the port the seal route gates on. Defined here, in the
// consumer, per this repository's convention (pkg/chainbind/ports.go does
// the same): the shell is what needs a Bearer check, so the shell names
// the one method it calls. keycloak.Provider satisfies it.
type Authorizer interface {
	Authorize(ctx context.Context, bearer string) error
}

// requireIssuerAdmin wraps next so it only runs once authz accepts the
// request's Bearer token and confirms it carries role_issuer_admin
// (TECHSPEC-001 §7 "Role bypass on the shell"). A missing or invalid
// token is 401; a valid token missing the role is 403 — the two are
// distinguished by which sentinel authz.Authorize returns, never by this
// function inspecting the token itself.
func requireIssuerAdmin(authz Authorizer, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bearer := bearerToken(r)
		err := authz.Authorize(r.Context(), bearer)
		switch {
		case err == nil:
			next(w, r)
		case errors.Is(err, keycloak.ErrForbidden):
			writeProblem(w, http.StatusForbidden, typeForbidden, "forbidden", "missing required role")
		default:
			writeProblem(w, http.StatusUnauthorized, typeUnauthorized, "unauthorized", "missing or invalid bearer token")
		}
	}
}

// bearerToken extracts the token from an "Authorization: Bearer <token>"
// header, or "" if the header is absent or not a Bearer scheme. The raw
// header value is never logged or echoed anywhere past this point
// (architecture invariant 10 applies to token bytes as it does to
// plaintext).
func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return ""
	}
	return strings.TrimPrefix(h, prefix)
}
