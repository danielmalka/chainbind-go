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

	"github.com/danielmalka/chainbind-go/pkg/chainbind"
)

// TestOpen_RecomputesProfileBindings pins that `chainbind open` passes the
// profile's BindingSpecs into Open.
//
// Open runs Verify's Level 1 in full before it unwraps a data key, and L1.6
// recomputes only the bindings it is handed. With none, level1Passed's loop
// over ProfileBindings is vacuous, and a package whose bindings.transaction_id
// is garbage — re-signed by an issuer who controls the signing key — opens
// without complaint. The command must refuse it.
//
// The tamper is re-signed on purpose. Without that, the package would be
// rejected at L1.2 on the signature, and this test would pass while proving
// nothing about L1.6.
func TestOpen_RecomputesProfileBindings(t *testing.T) {
	fx := newTestFixture(t, "")
	packagePath := fx.seal(t)

	raw, err := os.ReadFile(packagePath)
	if err != nil {
		t.Fatalf("read package: %v", err)
	}
	var pkg chainbind.Package
	if err := json.Unmarshal(raw, &pkg); err != nil {
		t.Fatalf("unmarshal package: %v", err)
	}

	// A malicious issuer: rewrite one profile binding, then re-sign so the
	// signature is genuine over the tampered content.
	pkg.Bindings.Extra["transaction_id"] = "txn:sha256:" + strings.Repeat("0", 64)

	seed, err := os.ReadFile(fx.signingKey)
	if err != nil {
		t.Fatalf("read signing key: %v", err)
	}
	seedBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(seed)))
	if err != nil {
		t.Fatalf("decode signing key: %v", err)
	}
	view, err := chainbind.BuildSigningView(pkg)
	if err != nil {
		t.Fatalf("BuildSigningView: %v", err)
	}
	pkg.Signature.Value = chainbind.EncodeSignatureValue(
		ed25519.Sign(ed25519.NewKeyFromSeed(seedBytes), view),
	)

	tampered := filepath.Join(fx.dir, "tampered.json")
	out, err := json.MarshalIndent(&pkg, "", "  ")
	if err != nil {
		t.Fatalf("marshal package: %v", err)
	}
	if err := os.WriteFile(tampered, out, 0o600); err != nil {
		t.Fatalf("write tampered package: %v", err)
	}

	// Sanity: the tampered package is still validly signed, so only L1.6 can
	// reject it. Verify with no BindingSpecs would pass Level 1.
	report, err := chainbind.Verify(context.Background(), &pkg, chainbind.VerifyOptions{
		IssuerKey: func(string, string) (ed25519.PublicKey, bool) {
			pub, _ := loadIssuerPublicKey(fx.issuerPub)
			return pub, true
		},
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !report.Signature {
		t.Fatal("tampered package has an invalid signature; this test would pass at L1.2, not L1.6")
	}

	code, stdout, stderr := runCLI(
		t, "open",
		"--package", tampered,
		"--key", fx.audiencePriv["merchant"],
		"--issuer-key", fx.issuerPub,
	)
	if code != exitNegative {
		t.Fatalf("open exit = %d, want %d (integrity failure)\nstdout=%s\nstderr=%s", code, exitNegative, stdout, stderr)
	}
	if stdout != "" {
		t.Fatalf("open wrote plaintext despite a tampered binding: %q", stdout)
	}
	if !strings.Contains(stderr, chainbind.ErrIntegrityCheckFailed.Error()) {
		t.Fatalf("stderr = %q, want it to name ErrIntegrityCheckFailed", stderr)
	}
}
