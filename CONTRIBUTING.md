# Contributing to chainbind-go

Thanks for looking. This is a security library, so the bar is unusual in a few specific ways. The
mechanics are ordinary; the rules below them are what actually keep the guarantees true.

## Mechanics

1. Fork, and branch from `main` (`feat/…`, `fix/…`, `docs/…`).
2. `make check-strict` must be green before you open a PR. It runs `gofumpt`, `golangci-lint`,
   `go vet`, and the full race-enabled test suite. The pre-commit hook additionally runs
   `govulncheck`, and CI runs it as a separate workflow (`.github/workflows/security.yml`); a red
   gate — from either — is not reviewable.
3. Commit with [Conventional Commits](https://www.conventionalcommits.org) in English
   (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`, `perf:`, `build:`, `ci:`).
4. Never `git commit --no-verify` — the pre-commit hook *is* the local gate. Never `git push --force`
   without saying so and why.

## The rules that are not obvious from the outside

### No new dependency without asking first

Open an issue before adding one. The current surface is deliberately small:

- **The library, `pkg/chainbind`, has exactly one dependency:** `github.com/gowebpki/jcs` (RFC 8785
  canonicalisation). Importing the library pulls in nothing else.
- The HTTP shell and adapters (`cmd/`, `internal/adapters`) add `github.com/lestrrat-go/jwx/v3` for
  JWT/JWKS. That cost stays out of the library.
- `github.com/hashicorp/vault/api` is **approved but deliberately unused**: the Vault signer
  speaks Transit over `net/http` directly, so the shell does not inherit Vault's dependency tree. Do
  not add it back.

### A green test beside a check does not prove it tests that check

This is the review discipline for the whole repository. When you add or change a check, prove the new
test *bites*: break the thing under test, show the named test failing, then restore it. A test that
passes whether or not the code is correct is worse than no test — it is a false assurance.

Worked example from this repo. `TestProfile_TransactionID_KnownAnswer`
(`pkg/chainbind/profile/agenticcheckout/profile_test.go`) pins the exact `transaction_id` for fixed
inputs. To show it is load-bearing, change one input to the derivation (or the hash construction) and
run it — the known answer must change and the test must fail. If it still passes, the test is not
testing the derivation and the PR is not ready.

### Secrets, and why the scanner is only a backstop

- **No error string ever carries plaintext, a DEK, or private-key bytes.** Sentinels
  are static strings; wrap with `%w`, never format secret bytes into an error.
- **A published crypto test vector and a leaked private key are the same object to a scanner.** When a
  test needs a real key or a golden vector, exempt it per line with `// gitleaks:allow` — never by
  adding a rule to a `.gitleaks.toml`, which turns off detection wholesale.
- gitleaks is **keyword-driven**: it reads names, not entropy. A 32-byte hex constant named
  `goldenPrivHex` is invisible to it; rename it `goldenPrivateKeyHex` and it fires. So the scanner is
  a backstop that only catches conventionally-named things — **review is the control.** Prove every
  `// gitleaks:allow` is load-bearing: `gitleaks detect --ignore-gitleaks-allow -v` lists every
  exempted line; that list must stay short and each entry justifiable.

### House rules

- Files stay under 500 lines.
- No `panic()` outside `main`/`init` — the library returns errors.
- Validate input at trust boundaries.

## Reporting a vulnerability

Not here. See [`SECURITY.md`](SECURITY.md) — do not open a public issue for a security break.
