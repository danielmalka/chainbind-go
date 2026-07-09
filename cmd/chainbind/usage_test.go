package main

import "testing"

// TestOpen_SegmentFlag_IsUsageError pins the hard constraint that `open` has
// no --segment (or --audience) flag: Go's flag package errors on an
// unrecognised flag by default, and this test proves that behavior is not
// accidentally disabled (e.g. by switching to flag.ContinueOnError with a
// custom Usage that swallows the error, or to a lenient parser). A future
// change that adds --segment and makes it select a segment must fail this
// test.
func TestOpen_SegmentFlag_IsUsageError(t *testing.T) {
	fx := newTestFixture(t, "")
	packagePath := fx.seal(t)

	code, _, stderr := runCLI(
		t, "open",
		"--package", packagePath,
		"--key", fx.audiencePriv["user"],
		"--issuer-key", fx.issuerPub,
		"--segment", "user",
	)
	if code != exitUsage {
		t.Fatalf("open --segment exit = %d, want %d (usage error), stderr=%s", code, exitUsage, stderr)
	}
}

// TestOpen_AudienceFlag_IsUsageError is --audience's counterpart to the test
// above: the brief names both spellings explicitly.
func TestOpen_AudienceFlag_IsUsageError(t *testing.T) {
	fx := newTestFixture(t, "")
	packagePath := fx.seal(t)

	code, _, stderr := runCLI(
		t, "open",
		"--package", packagePath,
		"--key", fx.audiencePriv["user"],
		"--issuer-key", fx.issuerPub,
		"--audience", "user",
	)
	if code != exitUsage {
		t.Fatalf("open --audience exit = %d, want %d (usage error), stderr=%s", code, exitUsage, stderr)
	}
}

// TestSeal_BothAuthorityFlags_ExitsUsage covers "both --authority-seed-dir
// and --authority-url" on seal.
func TestSeal_BothAuthorityFlags_ExitsUsage(t *testing.T) {
	fx := newTestFixture(t, "")
	code, _, stderr := runCLI(
		t, "seal",
		"--payload", fx.payloadPath,
		"--audiences", fx.audiencesPath,
		"--intent-ref", fx.intentRef,
		"--signing-key", fx.signingKey,
		"--issuer", "did:example:issuer",
		"--kid", "issuer-signing-key-1",
		"--tenant", "cli-tenant",
		"--environment", "test",
		"--authority-seed-dir", fx.seedDir,
		"--authority-url", "https://example.invalid",
	)
	if code != exitUsage {
		t.Fatalf("seal (both authority flags) exit = %d, want %d, stderr=%s", code, exitUsage, stderr)
	}
}

// TestSeal_NoAuthorityFlag_ExitsUsage covers "neither --authority-seed-dir
// nor --authority-url" on seal: exactly one is required.
func TestSeal_NoAuthorityFlag_ExitsUsage(t *testing.T) {
	fx := newTestFixture(t, "")
	code, _, stderr := runCLI(
		t, "seal",
		"--payload", fx.payloadPath,
		"--audiences", fx.audiencesPath,
		"--intent-ref", fx.intentRef,
		"--signing-key", fx.signingKey,
		"--issuer", "did:example:issuer",
		"--kid", "issuer-signing-key-1",
		"--tenant", "cli-tenant",
		"--environment", "test",
	)
	if code != exitUsage {
		t.Fatalf("seal (no authority flag) exit = %d, want %d, stderr=%s", code, exitUsage, stderr)
	}
}

// TestVerify_BothAuthorityFlags_ExitsUsage is verify's counterpart: even
// though verify's --authority-* is optional, supplying both is still a
// conflict, not a "pick one" default.
func TestVerify_BothAuthorityFlags_ExitsUsage(t *testing.T) {
	fx := newTestFixture(t, "")
	packagePath := fx.seal(t)

	code, _, stderr := runCLI(
		t, "verify",
		"--package", packagePath,
		"--issuer-key", fx.issuerPub,
		"--authority-seed-dir", fx.seedDir,
		"--authority-url", "https://example.invalid",
	)
	if code != exitUsage {
		t.Fatalf("verify (both authority flags) exit = %d, want %d, stderr=%s", code, exitUsage, stderr)
	}
}

// TestLoadRecipientKey_WrongLength_ExitsOperational_NamesOnlyExpectedLength
// covers a key file of the wrong length: exit 1, and the error names the
// expected length (32 bytes) and nothing about the file's actual contents
// or its actual (wrong) length.
func TestLoadRecipientKey_WrongLength_ExitsOperational_NamesOnlyExpectedLength(t *testing.T) {
	fx := newTestFixture(t, "")
	packagePath := fx.seal(t)

	shortKeyPath := writeFile(t, fx.dir, "short.key", b64url([]byte("too-short")))

	code, _, stderr := runCLI(
		t, "open",
		"--package", packagePath,
		"--key", shortKeyPath,
		"--issuer-key", fx.issuerPub,
	)
	if code != exitOperational {
		t.Fatalf("open (wrong key length) exit = %d, want %d, stderr=%s", code, exitOperational, stderr)
	}
	if !containsAny(stderr, "32 bytes") {
		t.Errorf("stderr = %q, want it to name the expected length (32 bytes)", stderr)
	}
	if containsAny(stderr, "too-short") {
		t.Errorf("stderr = %q, must not echo the file's contents", stderr)
	}
}

// TestUnknownSubcommand_ExitsUsage covers dispatch of an unrecognised
// subcommand.
func TestUnknownSubcommand_ExitsUsage(t *testing.T) {
	code, _, _ := runCLI(t, "decrypt")
	if code != exitUsage {
		t.Fatalf("unknown subcommand exit = %d, want %d", code, exitUsage)
	}
}

// TestNoArgs_ExitsUsage covers invocation with no subcommand at all.
func TestNoArgs_ExitsUsage(t *testing.T) {
	code, _, _ := runCLI(t)
	if code != exitUsage {
		t.Fatalf("no args exit = %d, want %d", code, exitUsage)
	}
}

// TestTopLevelHelp_ExitsOK covers -h.
func TestTopLevelHelp_ExitsOK(t *testing.T) {
	code, stdout, _ := runCLI(t, "-h")
	if code != exitOK {
		t.Fatalf("-h exit = %d, want %d", code, exitOK)
	}
	if !containsAny(stdout, "Exit codes:") {
		t.Errorf("-h stdout = %q, want it to document exit codes", stdout)
	}
}
