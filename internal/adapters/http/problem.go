// Package http implements the thin HTTP shell over pkg/chainbind
// (TECHSPEC-001 §5, §6.6 decision 6): stdlib net/http only, RFC 9457
// problem+json errors on every non-2xx response, and exactly the four
// routes the table names — no more.
//
// There is no decrypt endpoint here, and none is ever added: opening a
// segment happens only in the recipient's own process, via pkg/chainbind
// or cmd/chainbind open (D-002, architecture invariant 1). A handler that
// called chainbind.Open would be the single most serious regression this
// package could introduce.
package http

import (
	"encoding/json"
	"net/http"
)

// problemContentType is RFC 9457's media type. Every non-2xx response in
// this package is served under it.
const problemContentType = "application/problem+json"

// Stable, URN-like problem "type" values, one per error class. They never
// change once published: a caller may match on them.
const (
	typeMalformedRequest = "urn:chainbind:problem:malformed-request"
	typeUnsupportedMedia = "urn:chainbind:problem:unsupported-media-type"
	typeUnauthorized     = "urn:chainbind:problem:unauthorized"
	typeForbidden        = "urn:chainbind:problem:forbidden"
	typeIntentDenied     = "urn:chainbind:problem:intent-denied"
	typeAuthorityDown    = "urn:chainbind:problem:authority-unreachable"
	typeUnsupportedSpec  = "urn:chainbind:problem:unsupported-spec-version"
	typeServiceNotReady  = "urn:chainbind:problem:not-ready"
)

// problem is the RFC 9457 body: type, title, status, detail. Nothing else
// is ever added — in particular, never a stack trace, an underlying error
// string, a DEK, a private key, or a Vault token (architecture invariant
// 10, TECHSPEC-001 §5). The one field allowed to carry caller-supplied
// content is detail, and only on the intent-denied path, where it is the
// authority's own reason for the caller's own request (PRD Story 2 AC-2).
type problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
}

// writeProblem writes a problem+json response. detail must never be built
// from anything but a static label or the intent authority's own reason —
// see the package doc and problem's own comment.
func writeProblem(w http.ResponseWriter, status int, typ, title, detail string) {
	w.Header().Set("Content-Type", problemContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problem{Type: typ, Title: title, Status: status, Detail: detail})
}

// writeJSON writes a plain 2xx JSON body.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
