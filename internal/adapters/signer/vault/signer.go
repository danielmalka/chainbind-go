// Package vault implements chainbind.Signer against HashiCorp Vault's
// Transit secrets engine, using an `ed25519` key type, over plain
// net/http and encoding/json (TECHSPEC-001 §6.6 decision 6 — nothing
// here needs a client SDK). It is the deployed counterpart to
// internal/adapters/signer/local: TASK-001-04's Signer needs no server,
// this one needs Vault.
//
// # Verification never goes through Vault
//
// This package exposes the issuer's public key (PublicKey) so that
// chainbind.Verify can run ed25519.Verify locally; there is no Verify
// method here and no call to Vault Transit's transit/verify endpoint.
// Routing verification through Vault would turn an offline integrity
// check into an online oracle: Vault would learn which packages are
// being verified and by whom, verification would start failing whenever
// Vault is down — even though nothing about the package's signature
// changed — and TestVerify_RequiresNoKeys (PRD Story 3 AC-5) would stop
// describing reality, since a keyless verifier is exactly the case this
// package's design keeps possible. Ed25519 verification needs only a
// public key; Vault is only ever needed to produce a signature, never to
// check one.
//
// # The key version is pinned at construction
//
// Kid must return the version that will actually sign, before Sign runs,
// because issuer.kid sits inside the signing view (TECHSPEC-001 §6.4):
// the kid must be knowable before the bytes that commit to it exist.
// Vault Transit's sign endpoint uses the latest key version by default,
// so if a rotation happened between Kid and Sign, "latest" at Kid time
// and "latest" at Sign time could disagree — and the kid would then name
// a key that did not produce the signature.
//
// New therefore fetches transit/keys/{name} exactly once, reads
// data.latest_version, and pins it for the lifetime of the Signer:
//
//   - Kid always returns "{name}:v{pinned}" — the name:vN format
//     TECHSPEC-001 §10 open question 3 fixes — and never makes a network
//     call or signs anything to produce it.
//   - Sign passes "key_version": pinned explicitly in the request body,
//     so Vault signs with the exact key the kid names even if the key
//     was rotated in Vault in the meantime.
//   - Sign then asserts the version embedded in Vault's own
//     "vault:vN:<sig>" response equals the pinned version. If Vault
//     ignored key_version, this is the check that turns a silently
//     mislabelled signature into an error instead of a lie.
//
// A rotation is therefore never handled by an existing Signer: the
// caller must construct a new one. An issuer must not silently switch
// signing keys mid-process.
package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/danielmalka/chainbind-go/pkg/chainbind"
)

// maxResponseBody caps how much of a Vault response this package will
// ever decode. Vault is a trusted internal dependency in this
// deployment, but a misconfigured endpoint, a proxy gone wrong, or a
// compromised network path could still hand back an arbitrarily large or
// unbounded body; decoding that without a limit is an easy way to turn a
// slow Vault into an OOM. 1 MiB is far larger than any Transit response
// this adapter expects.
const maxResponseBody = 1 << 20 // 1 MiB

// Sentinel errors. Static strings only: a Vault token, a signature, or a
// response body must never appear in one of these (AGENTS.local.md
// invariant 10).
var (
	// ErrVaultUnreachable is returned when a request to Vault could not
	// be built or the transport failed (network error, timeout, closed
	// connection).
	ErrVaultUnreachable = errors.New("vault: unreachable")

	// ErrVaultResponse is returned when Vault answered with a non-2xx
	// status or a body that does not match the expected wire shape.
	ErrVaultResponse = errors.New("vault: invalid response")

	// ErrKeyTypeUnsupported is returned when the named Transit key is not
	// of type "ed25519".
	ErrKeyTypeUnsupported = errors.New("vault: unsupported key type")

	// ErrKeyVersionMismatch is returned when the version embedded in
	// Vault's signature response does not match the version this Signer
	// pinned at construction and requested via key_version. Vault
	// ignoring key_version is a contract violation, not a detail to
	// paper over by trusting whatever version Vault says it used.
	ErrKeyVersionMismatch = errors.New("vault: signature key version does not match pinned version")
)

// Signer implements chainbind.Signer against Vault Transit's ed25519 key
// type. Every field is fixed at construction; a Signer never rotates
// itself.
type Signer struct {
	addr    string
	token   string
	name    string
	client  *http.Client
	timeout time.Duration

	version int
	pub     ed25519.PublicKey
}

var _ chainbind.Signer = (*Signer)(nil)

// New fetches {addr}/v1/transit/keys/{name}, pins its latest_version and
// the public key published for that version, and returns a Signer bound
// to that pinned version for its lifetime. It rejects a key whose type
// is not "ed25519". If client is nil, http.DefaultClient is used.
// timeout bounds every call this Signer makes with its own context
// deadline; a timeout <= 0 relies solely on the caller's context.
func New(ctx context.Context, addr, token, keyName string, client *http.Client, timeout time.Duration) (*Signer, error) {
	if client == nil {
		client = http.DefaultClient
	}
	s := &Signer{addr: addr, token: token, name: keyName, client: client, timeout: timeout}

	ctx, cancel := s.withDeadline(ctx)
	defer cancel()

	var resp keysResponse
	if err := s.fetchKeyMetadata(ctx, &resp); err != nil {
		return nil, err
	}

	if resp.Data.Type != "ed25519" {
		// The type is not echoed into the error. It is a value Vault
		// controls, and every other error in this package is a static
		// string; a compromised or misconfigured endpoint should not get to
		// choose what lands in the operator's logs.
		return nil, ErrKeyTypeUnsupported
	}

	version := resp.Data.LatestVersion
	versionKey, ok := resp.Data.Keys[strconv.Itoa(version)]
	if !ok || versionKey.PublicKey == "" {
		return nil, fmt.Errorf("vault: fetch key metadata: %w", ErrVaultResponse)
	}

	pub, err := base64.StdEncoding.DecodeString(versionKey.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("vault: fetch key metadata: %w", ErrVaultResponse)
	}

	s.version = version
	s.pub = pub
	return s, nil
}

type keysResponse struct {
	Data struct {
		LatestVersion int                      `json:"latest_version"`
		Type          string                   `json:"type"`
		Keys          map[string]keyVersionKey `json:"keys"`
	} `json:"data"`
}

type keyVersionKey struct {
	PublicKey string `json:"public_key"`
}

// fetchKeyMetadata calls GET {addr}/v1/transit/keys/{name} and decodes the
// response into out. It is the request-building code New uses to pin a
// key version, extracted so Ping can reuse it to prove Vault is reachable
// without ever calling transit/sign.
func (s *Signer) fetchKeyMetadata(ctx context.Context, out *keysResponse) error {
	// url.PathEscape, not concatenation. keyName comes from an operator's
	// environment rather than from an attacker, but an unescaped segment
	// walks out of the transit mount ("../../sys/health") and can append a
	// query string the adapter never meant to send. The intent HTTP adapter
	// escapes its path segment; there is no reason this one should not.
	endpoint := s.addr + "/v1/transit/keys/" + url.PathEscape(s.name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return fmt.Errorf("vault: build key metadata request: %w", err)
	}
	req.Header.Set("X-Vault-Token", s.token)

	if err := s.doJSON(req, out); err != nil {
		return fmt.Errorf("vault: fetch key metadata: %w", err)
	}
	return nil
}

// Ping implements the HTTP shell's Prober port: it re-fetches
// transit/keys/{name} to prove Vault is reachable, and signs nothing. A
// readiness probe must never spend the signing key it is only checking
// for reachability.
func (s *Signer) Ping(ctx context.Context) error {
	ctx, cancel := s.withDeadline(ctx)
	defer cancel()

	var resp keysResponse
	return s.fetchKeyMetadata(ctx, &resp)
}

// Kid returns "{name}:v{pinned version}" from the state pinned at
// construction. It never makes a network call and never signs anything:
// Seal needs the kid before it can build the signing view that commits
// to it.
func (s *Signer) Kid(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("vault: %w", err)
	}
	return s.name + ":v" + strconv.Itoa(s.version), nil
}

type signRequest struct {
	Input      string `json:"input"`
	KeyVersion int    `json:"key_version"`
}

type signResponse struct {
	Data struct {
		Signature string `json:"signature"`
	} `json:"data"`
}

// Sign signs message using the pinned Transit key version and returns
// the raw Ed25519 signature bytes. It asserts that Vault's response
// names the pinned version and that the decoded signature is exactly
// ed25519.SignatureSize bytes; either mismatch is an error, never a
// silently mislabelled signature.
func (s *Signer) Sign(ctx context.Context, message []byte) ([]byte, error) {
	ctx, cancel := s.withDeadline(ctx)
	defer cancel()

	reqBody, err := json.Marshal(signRequest{
		Input:      base64.StdEncoding.EncodeToString(message),
		KeyVersion: s.version,
	})
	if err != nil {
		return nil, fmt.Errorf("vault: encode sign request: %w", err)
	}

	endpoint := s.addr + "/v1/transit/sign/" + url.PathEscape(s.name)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("vault: build sign request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", s.token)

	var resp signResponse
	if err := s.doJSON(req, &resp); err != nil {
		return nil, fmt.Errorf("vault: sign: %w", err)
	}

	version, sigB64, err := parseVaultSignature(resp.Data.Signature)
	if err != nil {
		return nil, fmt.Errorf("vault: sign: %w", err)
	}
	if version != s.version {
		return nil, fmt.Errorf("vault: sign: %w", ErrKeyVersionMismatch)
	}

	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("vault: sign: %w", ErrVaultResponse)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("vault: sign: %w", ErrVaultResponse)
	}

	return sig, nil
}

// parseVaultSignature parses Vault Transit's "vault:vN:<base64>" wire
// format, returning N and the base64 payload unchanged (still encoded,
// so the caller decodes it with the same base64.StdEncoding used
// throughout this package).
func parseVaultSignature(s string) (version int, b64Sig string, err error) {
	parts := strings.SplitN(s, ":", 3)
	if len(parts) != 3 || parts[0] != "vault" || !strings.HasPrefix(parts[1], "v") {
		return 0, "", ErrVaultResponse
	}
	version, err = strconv.Atoi(strings.TrimPrefix(parts[1], "v"))
	if err != nil {
		return 0, "", ErrVaultResponse
	}
	return version, parts[2], nil
}

// PublicKey returns a copy of the pinned version's public key, for
// building chainbind.VerifyOptions.IssuerKey. It makes no network call:
// the key was fetched once, at construction.
//
// The copy is not about secrecy — a public key is public. It is so a
// caller that mutates the slice it is handed cannot silently change the
// key this Signer believes it signed under, turning every later
// verification into an unexplained failure.
func (s *Signer) PublicKey() ed25519.PublicKey {
	return bytes.Clone(s.pub)
}

// withDeadline returns ctx bounded by s.timeout, if configured.
func (s *Signer) withDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	if s.timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, s.timeout)
}

// doJSON executes req, requires a 2xx status, and decodes the JSON body
// (capped at maxResponseBody) into out. A network error, a non-2xx
// status, or an undecodable body is always an error.
func (s *Signer) doJSON(req *http.Request, out any) error {
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrVaultUnreachable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%w: status %d", ErrVaultResponse, resp.StatusCode)
	}

	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBody)).Decode(out); err != nil {
		return fmt.Errorf("%w: %w", ErrVaultResponse, err)
	}

	return nil
}
