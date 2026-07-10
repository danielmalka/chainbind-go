# chainbind-go

[![CI](https://github.com/danielmalka/chainbind-go/actions/workflows/ci.yml/badge.svg)](https://github.com/danielmalka/chainbind-go/actions/workflows/ci.yml)
[![Security](https://github.com/danielmalka/chainbind-go/actions/workflows/security.yml/badge.svg)](https://github.com/danielmalka/chainbind-go/actions/workflows/security.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/danielmalka/chainbind-go.svg)](https://pkg.go.dev/github.com/danielmalka/chainbind-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/danielmalka/chainbind-go)](https://goreportcard.com/report/github.com/danielmalka/chainbind-go)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
![Go Version](https://img.shields.io/github/go-mod/go-version/danielmalka/chainbind-go)

Seal one payload into per-audience encrypted segments, each openable by exactly one recipient,
verifiable by anyone holding no key, and bound to the authorization it was issued under.

chainbind generalizes the flow of encrypted payloads and signed claims. The core library carries no
domain-specific vocabulary; the checkout case is one profile built on top of it.

> **Status: proof of concept.** This repository demonstrates a design. Read the
> [What is real, what is assumed, what is simulated](#what-is-real-what-is-assumed-what-is-simulated)
> section before drawing conclusions about production readiness — several components are deliberate
> substitutes.

## The problem it solves

You have one document and several parties who each need a different slice of it. A checkout, say: the
user's identity, the merchant's cart, the payment gateway's instrument. Three constraints usually
pull against each other:

1. **Each party opens only its own slice** — the merchant must not read the user's segment, even
   holding the whole package.
2. **Anyone can verify the package is authentic and untampered** — without holding any key, without
   decrypting anything.
3. **The package is bound to the authorization it was issued under** — you cannot swap the payload
   under a genuine authorization reference and have it still verify.

chainbind gives you all three at once:

- **(1) Confidentiality** is envelope encryption. Every segment gets its own fresh 256-bit
  data-encryption key (AES-256-GCM), and that key is wrapped to the recipient's X25519 public key
  (ECDH-ES + A256KW). Opening needs the recipient's private key and nothing else — there is no
  access-control code on the open path, so there is no access-control decision to get wrong. The
  wrong key simply fails to unwrap.
- **(2) Public verifiability** is an Ed25519 signature over a canonical view of the manifest, plus
  hashes. A verifier holding only the issuer's public key checks the signature, the ciphertext
  hashes, and the structural bindings — it never touches a plaintext or a data key.
- **(3) Binding** is `intent_commitment`, a hash tying the authorization reference and the
  authority's immutable `constraints_hash` to the ordered set of segments. Swapping the payload
  changes the segments, which changes the commitment, which a keyless verifier detects.

### What it costs

- **The issuer reads everything.** Sealing means holding every plaintext before encrypting it. There
  is no way around this — you cannot seal what you cannot read. If you run the HTTP shell and let it
  seal on your behalf, its operator becomes the issuer and sees every payload. This is the first
  entry in the [trade-offs](#trade-offs) and it is not a bug to be fixed; it is what sealing *is*.
- **The intent authority learns a projection.** To ask "is this execution authorized?", the issuer
  sends the authority the fields policy needs — amount, currency, merchant identifier — never the
  whole payload. That projection is, by definition, a small deliberate disclosure.
- **`constraints_hash` immutability is a requirement chainbind places on its upstream authority**, not
  something it can enforce on a third party. If your authority mutates an authorization in place
  instead of versioning it, the binding guarantee weakens and chainbind cannot stop that.

## Install

```
go get github.com/danielmalka/chainbind-go/pkg/chainbind
```

Requires Go 1.26+. The library's only dependency is
[`github.com/gowebpki/jcs`](https://github.com/gowebpki/jcs) (RFC 8785 canonical JSON). The HTTP
shell and CLI pull in one more, [`lestrrat-go/jwx/v3`](https://github.com/lestrrat-go/jwx), for
Keycloak JWT validation — a consumer importing only `pkg/chainbind` does not inherit it.

## Usage

The whole library is three functions: `Seal`, `Verify`, `Open`. This example seals one payload into
two segments, verifies it holding no key, and opens each segment with only its recipient key. It is
[a runnable test](pkg/chainbind/example_test.go), so it cannot drift from the API.

```go
issuerPub, issuerPriv, _ := ed25519.GenerateKey(rand.Reader)
signer, _ := local.New(issuerPriv, "issuer-key-1")

aliceKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
bobKey, _ := ecdh.X25519().GenerateKey(rand.Reader)

req := chainbind.SealRequest{
	Segments: map[string][]byte{
		"alice": []byte(`{"note":"for alice only"}`),
		"bob":   []byte(`{"note":"for bob only"}`),
	},
	SegmentOrder: []string{"alice", "bob"},
	Audiences: []chainbind.Audience{
		{Name: "alice", PublicKey: aliceKey.PublicKey().Bytes(), Kid: "alice-1"},
		{Name: "bob", PublicKey: bobKey.PublicKey().Bytes(), Kid: "bob-1"},
	},
	IntentRef:  "intent:example",
	Projection: map[string]any{"amount": 100},
	Issuer:     "did:example:issuer",
	IssuedAt:   time.Now().UTC(),
}

pkg, _ := chainbind.Seal(ctx, req, signer, x25519.Wrapper{}, authority)

report, _ := chainbind.Verify(ctx, pkg, chainbind.VerifyOptions{
	IssuerKey: func(string, string) (ed25519.PublicKey, bool) { return issuerPub, true },
	Intent:    authority,
})
// report.OK() == true

who, plaintext, _ := chainbind.Open(ctx, pkg, aliceKey.Bytes(), x25519.Wrapper{},
	chainbind.VerifyOptions{IssuerKey: keyResolver})
// who == "alice"; plaintext == {"note":"for alice only"}
```

Three things worth noticing in that code:

- **`Open` takes no segment name.** The audience is derived by matching the recipient key's
  thumbprint against the package's `cnf`. A caller cannot name which segment to open, so it cannot
  ask for one it has no key for.
- **`Verify` returns a `*Report`, not an error, for a bad package.** A failing package is an
  *answer*, not a processing failure. `report.OK()` is the verdict; `report.Structural`,
  `report.Signature`, `report.CipherHashes` and the rest say precisely what passed and what did not.
- **`Verify` with no `Intent` reports the intent level as *unevaluated*, and `OK()` is false.** A
  structural-only check never reads as full success. Reaching an authority is a separate act with a
  separate trust assumption, and the report keeps them distinct.

## Two verification levels

`Verify` has two levels because they need different things and prove different things.

| | Level 1 — structural | Level 2 — intent |
|---|---|---|
| Needs | the package + the issuer's public key | Level 1 + a reachable intent authority |
| Network | none | yes |
| Proves | the package is authentic, internally consistent, and unspliced | it is bound to the authorization it claims |
| Cannot prove | that the ciphertexts decrypt to the hashed plaintexts | — |

Level 1 is offline and keyless. It does **not** check `plain_hash` — proving a plaintext hash
describes the plaintext requires the plaintext, which only a recipient has. `Open` makes that check,
for the one party that can.

`Seal` and `Verify` are deliberately asymmetric about the authority: `Seal` **fails closed** if the
authority is unreachable (it will not mint an unverifiable claim), while `Verify` returns
*indeterminate* (`OK() == false`, but not an error). An unreachable authority is never mistaken for a
verified one.

## How the package maps onto JOSE

The format borrows JOSE's shapes without being JWE/JWS on the wire.

| chainbind | JOSE analogue | Divergence |
|---|---|---|
| Per-segment DEK, AES-256-GCM | JWE content encryption | One recipient per segment, not one payload many recipients. |
| `dek_wrapped` + `epk` (ECDH-ES + A256KW) | JWE `encrypted_key` with `alg: ECDH-ES+A256KW` | Standard key agreement; per-segment ephemeral key. |
| Ed25519 signature over the signing view | JWS over the manifest | Signs a canonical *view* of nine named fields, not the compact serialization. `segments` is not signed directly — ciphertexts are covered through `manifest.segments[a].cipher_hash`. |
| `cnf[a].jkt` | RFC 7638 JWK thumbprint in a `cnf` claim | Opening the segment *is* the proof of possession; nothing compares an identity to an allowlist. |
| AAD over `{package_id, segment, spec_version, tenant, environment}` | JWE protected header as AAD | The anti-splicing control: moving a segment to another package breaks the GCM tag on open. |
| `manifest.disclosures: []` | (reserved) | Empty in v1. See below. |

**What selective disclosure would add.** `disclosures` is reserved and ships empty. Envelope
encryption and selective disclosure (SD-JWT-style) solve *different* problems and are often confused:
encryption stops a party that holds the package from reading a segment; selective disclosure lets the
*holder of an opened segment* forward a subset onward while proving the rest, revealing nothing it
chooses to withhold. That is verifiable omission, not confidentiality — it cannot keep a holder from
reading what it was given. Feature 002 would make each opened segment an SD-JWT so its owner can
forward a subset; it composes *on top of* this format, does not replace it, and is a feature the size
of this one (decision D-006). Because `disclosures` is inside the signed view, feature 002 can
populate it without changing the view's shape or breaking existing verifiers.

## What is real, what is assumed, what is simulated

| Component | Status |
|---|---|
| `pkg/chainbind` — seal, verify, open, bindings, canonicalization, AAD, key wrap, signing view | **Real.** This is the product. |
| Ed25519 signing, X25519 ECDH-ES + A256KW, AES-256-GCM, RFC 8785 / 7638 | **Real**, standard primitives; A256KW (RFC 3394) is hand-implemented (Go stdlib has none) and pinned to the RFC test vectors. |
| Vault Transit signer | **Real** integration (dev-mode Vault in compose), talking to Transit over HTTP. |
| Keycloak JWT/JWKS auth on the shell's seal route | **Real** validation: issuer, audience, `role_issuer_admin`, and structural rejection of `alg:none` / RS→HS confusion. |
| The intent authority | **Simulated.** `mock-authority` wraps an in-memory verifier seeded from `testdata/`. A production authority is a third-party policy service chainbind does not ship. |
| `constraints_hash` immutability | **An assumption** chainbind places on that upstream authority (D-012); it cannot enforce it on a third party. |
| `transaction_id` | **Not a security control** (see below). |
| The HTTP shell as *the* way to seal | **An organizational choice with a consequence.** Its operator becomes the issuer and reads every payload. Seal with the library in your own process to avoid that. |
| Single-issuer trust, recipient key distribution | **Assumptions.** Key provisioning is static seed data (PRD A4); a trust list and key discovery are out of scope. |
| Replay / expiry | **Out of scope** (PRD non-goal). `issued_at` is issuer-asserted; there is no timestamping authority. |

### `transaction_id` is not a security control

The `agentic-checkout/v1` profile derives a `transaction_id` from the merchant and gateway segment
hashes. Both of its inputs already sit in the signed manifest, so any verifier recomputes it holding
no key and opening nothing — it adds no evidence the signature did not already provide. It exists to
be a stable, collision-resistant *name* for "this cart paid by this payment", for correlation and
idempotency. Treating it as protection is security theatre.

## Trade-offs

From the STRIDE analysis over the seal/verify/open paths (TECHSPEC §7). The ones that most often
surprise:

1. **The issuer reads everything, because the issuer seals.** Confidentiality is *between the issuer
   and each recipient*, never *from* the issuer. Using the HTTP shell to seal makes its operator the
   issuer.
2. **A compromised issuer signing key defeats the `cipher_hash` splicing control, but not the AAD
   one.** Splicing a segment between packages is caught two independent ways: at `Verify`, the
   spliced `cipher_hash` does not match the target's signed manifest, and rewriting the manifest
   breaks the signature; at `Open`, the GCM tag fails because the AAD binds the ciphertext to its
   `package_id` and segment name. The AAD control survives a key compromise the signature control
   does not.
3. **Verification proves authenticity and consistency, not correctness of the hidden content.** A
   keyless verifier cannot check that a segment decrypts to the plaintext its `plain_hash` claims. The
   recipient checks that at `Open`.
4. **Sealing is unavailable when the authority is down.** Deliberate: `Seal` fails closed rather than
   mint a claim it cannot back.

`Open` accepts a `VerifyOptions` and **ignores its `Intent` field**. Opening is offline and the intent
level is not an integrity property; the same `VerifyOptions` type is reused across `Verify` and `Open`
for convenience. A caller who passes a live authority to `Open` may assume it was consulted — it was
not. `Open` never touches the network.

## Run it

Docker and `docker compose` are required. From a clean clone:

```
make up                # build images, start Vault, Keycloak, the authority, and the shell
make seed              # provision keys and authorizations (also run by the init containers)
make demo              # drive a full seal -> verify -> open and write artifacts to examples/
make test-integration  # the round trip as a Go test against the running stack
make down              # tear everything down
```

`make up` returns only once the shell's `/ready` reports 200, which happens only after Vault, Keycloak
and the authority are reachable. The six artifacts under [`examples/`](examples/) are real captured
output from `make demo`, not hand-authored fixtures: the input payload, the sealed package, the
verification report, and one opened segment per audience.

The CLI is the only place `Open` runs outside the library — the shell never exposes it (there is no
decrypt endpoint):

```
chainbind seal   --payload p.json --audiences a.json --intent-ref intent:allow-example \
                 --signing-key issuer.key --issuer did:example:issuer --kid issuer-key-1 \
                 --authority-seed-dir testdata/authorizations --out package.json
chainbind verify --package package.json --issuer-key issuer.pub \
                 --authority-seed-dir testdata/authorizations
chainbind open   --package package.json --key alice.key --issuer-key issuer.pub
```

`chainbind verify` exits non-zero — and says the intent level was not evaluated — if you omit the
authority. It never prints success for a structural-only check.

## Layout

```
pkg/chainbind/                  the library: seal, verify, open, bindings, crypto, canonicalization
pkg/chainbind/profile/          agentic-checkout/v1 — the only place any checkout word appears
internal/adapters/              signer (local, Vault), keywrap (x25519), intent (mock, HTTP), auth (Keycloak)
internal/platform/              config, logger
cmd/chainbind/                  the CLI (seal/verify/open)
cmd/chainbind-api/              the HTTP shell (no open)
cmd/mock-authority/             the POC intent authority
deployments/, scripts/          compose, Dockerfiles, bootstrap
```
