package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danielmalka/chainbind-go/pkg/chainbind/profile/agenticcheckout"
)

// TestCLI_RoundTrip_SealVerifyOpen drives seal -> verify -> open entirely
// through the CLI's subcommand dispatcher, over a temp dir, with the mock
// authority seeded from a fixture directory this test writes itself
// (mirroring testdata/authorizations' shape). It is the acceptance test for
// the whole subcommand set: TASK-001-13's brief requires exactly this flow.
func TestCLI_RoundTrip_SealVerifyOpen(t *testing.T) {
	fx := newTestFixture(t, "")
	packagePath := fx.seal(t)

	// verify, with the authority reachable: OK() must be true.
	code, stdout, stderr := runCLI(
		t, "verify",
		"--package", packagePath,
		"--issuer-key", fx.issuerPub,
		"--authority-seed-dir", fx.seedDir,
	)
	if code != exitOK {
		t.Fatalf("verify exit = %d, want %d\nstdout=%s\nstderr=%s", code, exitOK, stdout, stderr)
	}
	if !strings.Contains(stdout, "result: PASS") {
		t.Errorf("verify stdout = %q, want it to report PASS", stdout)
	}

	// open each audience's key and check it recovers exactly that
	// audience's plaintext segment.
	var profile agenticcheckout.Profile
	payloadRaw := readTestFile(t, fx.payloadPath)
	var payload agenticcheckout.Payload
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	wantSegments, err := profile.Split(payload)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}

	for _, name := range agenticcheckout.SegmentOrder() {
		outPath := filepath.Join(fx.dir, name+".out.json")
		code, _, stderr := runCLI(
			t, "open",
			"--package", packagePath,
			"--key", fx.audiencePriv[name],
			"--issuer-key", fx.issuerPub,
			"--out", outPath,
		)
		if code != exitOK {
			t.Fatalf("open(%s) exit = %d, want %d, stderr=%s", name, code, exitOK, stderr)
		}
		if !strings.Contains(stderr, "opened audience: "+name) {
			t.Errorf("open(%s) stderr = %q, want it to name audience %q", name, stderr, name)
		}
		got := readTestFile(t, outPath)
		if !bytes.Equal(got, wantSegments[name]) {
			t.Errorf("open(%s) plaintext = %s, want %s", name, got, wantSegments[name])
		}
	}
}

// TestOpen_WrongRecipientKey_ExitsNegative_WrapsErrDecryptionFailed proves a
// key belonging to no audience fails to open, exits 3, and the error wraps
// chainbind.ErrDecryptionFailed by name — never a more specific reason,
// since naming one would be an oracle (pkg/chainbind/errors.go's own
// comment on why there is no ErrWrongRecipientKey).
func TestOpen_WrongRecipientKey_ExitsNegative_WrapsErrDecryptionFailed(t *testing.T) {
	fx := newTestFixture(t, "")
	packagePath := fx.seal(t)

	foreignPriv, _ := genX25519(t)
	foreignKeyPath := writeFile(t, fx.dir, "foreign.key", b64url(foreignPriv))

	code, stdout, stderr := runCLI(
		t, "open",
		"--package", packagePath,
		"--key", foreignKeyPath,
		"--issuer-key", fx.issuerPub,
	)
	if code != exitNegative {
		t.Fatalf("open exit = %d, want %d\nstdout=%s\nstderr=%s", code, exitNegative, stdout, stderr)
	}
	if !strings.Contains(stderr, "decryption failed") {
		t.Errorf("open stderr = %q, want it to name decryption failed", stderr)
	}
}
