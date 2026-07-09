package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danielmalka/chainbind-go/internal/adapters/keywrap/x25519"
	"github.com/danielmalka/chainbind-go/pkg/chainbind"
)

// sentinelEmail is a distinctive, high-entropy value planted into the
// payload's Subject.Email — plaintext that must never surface in this
// binary's output under any failure path.
const sentinelEmail = "sentinel-9f3c7a1e4b2d8f60-do-not-leak@example.com"

// TestCLI_ErrorsNeverLeakSecrets drives every failure path this CLI has —
// a wrong-key open, a tampered package, a bad key file, an unreachable
// authority — with a payload carrying sentinelEmail and a recipient private
// key, and asserts neither the sentinel plaintext nor the raw private key
// bytes ever appear in stdout or stderr (AGENTS.local.md invariant 10).
func TestCLI_ErrorsNeverLeakSecrets(t *testing.T) {
	fx := newTestFixture(t, sentinelEmail)
	packagePath := fx.seal(t)

	userPrivRaw := readTestFile(t, fx.audiencePriv["user"])
	userPrivText := strings.TrimSpace(string(userPrivRaw))

	assertClean := func(t *testing.T, label, stdout, stderr string) {
		t.Helper()
		for _, s := range []string{stdout, stderr} {
			if strings.Contains(s, sentinelEmail) {
				t.Errorf("%s: output leaked the sentinel plaintext: %q", label, s)
			}
			if userPrivText != "" && strings.Contains(s, userPrivText) {
				t.Errorf("%s: output leaked the recipient private key: %q", label, s)
			}
		}
	}

	// 1. open with a key belonging to no audience.
	foreignPriv, _ := genX25519(t)
	foreignKeyPath := writeFile(t, fx.dir, "foreign.key", b64url(foreignPriv))
	_, stdout, stderr := runCLI(t, "open",
		"--package", packagePath, "--key", foreignKeyPath, "--issuer-key", fx.issuerPub)
	assertClean(t, "open/wrong-key", stdout, stderr)

	// 2. open with the correct key, but a wrong issuer public key (signature
	// fails, Level 1 fails, Open never reaches the plaintext) — must still
	// not leak the recipient key supplied on the command line.
	_, wrongIssuerPub, _ := genEd25519(t)
	wrongIssuerPubPath := writeFile(t, fx.dir, "wrong-issuer.pub", b64url(wrongIssuerPub))
	_, stdout, stderr = runCLI(t, "open",
		"--package", packagePath, "--key", fx.audiencePriv["user"], "--issuer-key", wrongIssuerPubPath)
	assertClean(t, "open/wrong-issuer-key", stdout, stderr)

	// 3. open successfully — the plaintext legitimately appears in stdout
	// (that is the whole point of the command), so this is not part of the
	// leak assertions. Verified separately by the round-trip test.

	// 4. verify without an authority: intent unevaluated, but still no leak.
	_, stdout, stderr = runCLI(t, "verify", "--package", packagePath, "--issuer-key", fx.issuerPub)
	assertClean(t, "verify/no-authority", stdout, stderr)

	// 5. a key file of the wrong length.
	shortKeyPath := writeFile(t, fx.dir, "short.key", b64url([]byte("x")))
	_, stdout, stderr = runCLI(t, "open",
		"--package", packagePath, "--key", shortKeyPath, "--issuer-key", fx.issuerPub)
	assertClean(t, "open/short-key", stdout, stderr)

	// 6. seal against an unreachable HTTP authority.
	_, stdout, stderr = runCLI(
		t, "seal",
		"--payload", fx.payloadPath,
		"--audiences", fx.audiencesPath,
		"--intent-ref", fx.intentRef,
		"--signing-key", fx.signingKey,
		"--issuer", "did:example:issuer",
		"--kid", "issuer-signing-key-1",
		"--tenant", "cli-tenant",
		"--environment", "test",
		"--authority-url", "chainbind-test-invalid-scheme://nope", // fails before any network call
	)
	assertClean(t, "seal/unreachable-authority", stdout, stderr)

	// 7. the one path where Open actually holds the recovered plaintext when
	// it fails: a plain_hash mismatch. Every other failure aborts before
	// decryption; this one decrypts, recomputes H(JCS(plaintext)), and finds
	// it does not match the signed plain_hash. If Open ever surfaced the
	// recovered bytes in that error, this is the only case that would catch
	// it — and the target is the user segment, which carries sentinelEmail.
	//
	// The mismatch is built the malicious-issuer way: re-encrypt the user
	// segment under a different plaintext with the same DEK and AAD, update
	// cipher_hash so Level 1 still passes, leave plain_hash stale, re-sign.
	tamperedPath := tamperUserPlainHash(t, fx, packagePath)
	_, stdout, stderr = runCLI(t, "open",
		"--package", tamperedPath, "--key", fx.audiencePriv["user"], "--issuer-key", fx.issuerPub)
	assertClean(t, "open/plain-hash-mismatch", stdout, stderr)
}

// tamperUserPlainHash produces a package that survives Level 1 but fails
// Open's plain_hash check on the user segment: re-encrypt that segment under
// a different plaintext with its own DEK and AAD, reconcile cipher_hash to
// the new bytes, leave plain_hash stale, and re-sign. It writes the result
// beside the original and returns its path.
func tamperUserPlainHash(t *testing.T, fx testFixture, packagePath string) string {
	t.Helper()

	raw, err := os.ReadFile(packagePath)
	if err != nil {
		t.Fatalf("read package: %v", err)
	}
	var pkg chainbind.Package
	if err := json.Unmarshal(raw, &pkg); err != nil {
		t.Fatalf("unmarshal package: %v", err)
	}

	userPriv, err := base64.RawURLEncoding.DecodeString(
		strings.TrimSpace(string(readTestFile(t, fx.audiencePriv["user"]))),
	)
	if err != nil {
		t.Fatalf("decode user key: %v", err)
	}

	aad, err := chainbind.AAD(pkg.Manifest.AADContext, "user", pkg.SpecVersion)
	if err != nil {
		t.Fatalf("AAD: %v", err)
	}
	sealed := pkg.Segments["user"]
	epk, _ := base64.RawURLEncoding.DecodeString(sealed.EPK.X)
	wrapped, _ := base64.RawURLEncoding.DecodeString(sealed.DEKWrapped)
	dek, err := (x25519.Wrapper{}).Unwrap(context.Background(), userPriv, epk, wrapped)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}

	// The substituted plaintext carries the sentinel on purpose: this is the
	// plaintext Open actually recovers on the plain_hash-mismatch path, so it
	// is what an Open that leaked recovered bytes would expose. Substituting a
	// sentinel-free plaintext here would make the leak assertion vacuous.
	substituted := []byte(`{"substituted":"` + sentinelEmail + `"}`)
	combined, nonce, err := chainbind.Encrypt(dek, substituted, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	ct, tag := combined[:len(combined)-16], combined[len(combined)-16:]
	sealed.Nonce = b64url(nonce)
	sealed.Ciphertext = b64url(ct)
	sealed.Tag = b64url(tag)
	pkg.Segments["user"] = sealed

	seg := pkg.Manifest.Segments["user"]
	seg.CipherHash = chainbind.H(combined)
	pkg.Manifest.Segments["user"] = seg

	seed, _ := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(readTestFile(t, fx.signingKey))))
	view, err := chainbind.BuildSigningView(pkg)
	if err != nil {
		t.Fatalf("BuildSigningView: %v", err)
	}
	pkg.Signature.Value = chainbind.EncodeSignatureValue(ed25519.Sign(ed25519.NewKeyFromSeed(seed), view))

	out, err := json.MarshalIndent(&pkg, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(fx.dir, "tampered-plainhash.json")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}
