# Security Policy

**Do not report a vulnerability in a public issue.** The issue *is* the exploit — a break in the
AAD, the key wrap, or the signing view is disclosed the moment it is filed in the tracker.

Report it privately through GitHub: open
[a new security advisory](https://github.com/danielmalka/chainbind-go/security/advisories/new).
This is a proof-of-concept maintained by one person — expect a best-effort acknowledgement, not a
guaranteed timeline or a fix SLA.

## Supported versions

Pre-1.0. Only `main` is supported; there is no release to back-port to and no support matrix. A fix
lands on `main` or nowhere.

## What is in scope

The cryptographic core, `pkg/chainbind`:

- `Seal`, `Verify`, `Open`, and the invariants they hold (see [`README.md`](README.md)).
- The AAD construction (anti-splicing) and its enforcement by the GCM tag at `Open`.
- The X25519 key wrap — ECDH-ES + Concat KDF + A256KW (RFC 3394).
- The signing view and its JCS (RFC 8785) canonicalisation.
- The bindings: `segments_root`, `intent_commitment`, `constraints_hash`, and profile bindings.

A report that shows any of these failing to hold — a segment opened by the wrong audience, a mutated
manifest that still verifies, a spliced package that `Open` accepts, plaintext recovered without the
recipient key — is in scope and wanted.

## What is out of scope, because it is documented design and not a defect

These are properties of the design, decided on the record. A report that one of them is "a bug" will
be closed with a pointer back here. If you think the *design* is wrong, that is a discussion, not a
vulnerability.

- **The issuer reads everything.** The issuer seals, so it holds every segment's plaintext before it
  is encrypted (D-002). Sealing through the HTTP shell makes *its operator* the issuer. Confidentiality
  is between recipients, never from the issuer.
- **`transaction_id` is not a security control.** It is a derivation, not an equality check (D-007);
  both of its inputs already sit in the signed manifest, so it adds no integrity a verifier does not
  already have.
- **A keyless verifier never checks `plain_hash`.** It cannot — that needs the plaintext. Only `Open`
  holds the plaintext and only `Open` checks it. `Verify` returning success does not attest the
  plaintext.
- **`constraints_hash` immutability is a requirement chainbind places on its upstream Intent
  Authority (D-012), not something chainbind enforces on a third party.** If the authority mints a
  mutable or re-used hash, that is the authority's break, not chainbind's.
- **The POC substitutes are not hardened.** The mock authority, the HTTP shell, the CLI's on-disk key
  files, and the Docker Compose environment exist to demonstrate the flow. They are not the reference
  deployment and their operational security is out of scope.
- **Replay and expiry are out of scope** — a non-goal of this POC. A package carries no freshness or
  expiry semantics; a replayed valid package verifies.

## What a good report contains

- A reproducer against `pkg/chainbind` — a minimal Go test or CLI invocation, not a description.
- The commit SHA it reproduces on.
- Which invariant you believe it breaks (see `README.md` and the doc comments in `pkg/chainbind`).
