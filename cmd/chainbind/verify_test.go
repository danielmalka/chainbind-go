package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/danielmalka/chainbind-go/pkg/chainbind"
)

// TestVerify_WithoutAuthority_ExitsNonZeroAndSaysIntentNotEvaluated is the
// D-011 test: `chainbind verify` with no --authority-* flag runs Verify with
// opt.Intent == nil. The intent level is unevaluated, Report.OK() is false,
// and the CLI must exit non-zero (exitNegative) and say plainly that the
// intent level was not evaluated — never print the word this file uses for
// a passing result. This is the single most important behavior in the
// subcommand (per the task brief): a future refactor that makes verify
// print success for a structural-only check must fail this test.
func TestVerify_WithoutAuthority_ExitsNonZeroAndSaysIntentNotEvaluated(t *testing.T) {
	fx := newTestFixture(t, "")
	packagePath := fx.seal(t)

	code, stdout, stderr := runCLI(
		t, "verify",
		"--package", packagePath,
		"--issuer-key", fx.issuerPub,
	)

	if code != exitNegative {
		t.Fatalf("verify (no authority) exit = %d, want %d\nstdout=%s\nstderr=%s", code, exitNegative, stdout, stderr)
	}
	if !containsAny(stdout, "NOT EVALUATED", "not evaluated") {
		t.Errorf("verify stdout = %q, want it to say the intent level was not evaluated", stdout)
	}
	// The success word this CLI prints for a passing report is "PASS" — see
	// printReportHuman. Assert it never appears, and separately assert the
	// word "verified" never appears either, so a future change that swaps
	// in different wording is still caught.
	if containsAny(stdout, "PASS", "verified", "Verified") {
		t.Errorf("verify stdout = %q, must not claim success when the intent level was never evaluated", stdout)
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// TestVerify_JSONOutput_StructuralIsText covers `verify --json`, which had no
// test at all, and pins that Structural is rendered as text rather than as
// the ordinal of its iota block. A machine consumer reading "Structural": 4
// has no legend anywhere telling it that 4 means a duplicate audience — and
// the number moves the day a fault is inserted above it.
func TestVerify_JSONOutput_StructuralIsText(t *testing.T) {
	fx := newTestFixture(t, "")
	packagePath := fx.seal(t)

	code, stdout, stderr := runCLI(
		t, "verify",
		"--package", packagePath,
		"--issuer-key", fx.issuerPub,
		"--authority-seed-dir", fx.seedDir,
		"--json",
	)
	if code != exitOK {
		t.Fatalf("verify --json exit = %d, want %d\nstderr=%s", code, exitOK, stderr)
	}

	var rec map[string]any
	if err := json.Unmarshal([]byte(stdout), &rec); err != nil {
		t.Fatalf("--json did not emit valid JSON: %v\n%s", err, stdout)
	}
	if _, isNumber := rec["Structural"].(float64); isNumber {
		t.Fatalf("Structural serialized as a bare ordinal: %s", stdout)
	}
	if rec["Structural"] != chainbind.FaultNone.String() {
		t.Fatalf("Structural = %v, want %q", rec["Structural"], chainbind.FaultNone.String())
	}
	if rec["Signature"] != true {
		t.Fatalf("Signature = %v, want true", rec["Signature"])
	}
}
