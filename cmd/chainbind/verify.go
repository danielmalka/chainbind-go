package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/danielmalka/chainbind-go/pkg/chainbind"
	"github.com/danielmalka/chainbind-go/pkg/chainbind/profile/agenticcheckout"
)

// runVerify implements `chainbind verify`. --authority-* is optional: when
// neither is given, opt.Intent is nil, Verify reports the intent level as
// unevaluated, and Report.OK() is false — this is D-011's single most
// important behavior, and this subcommand never reports success for a
// structural-only check (AGENTS.local.md invariant 5).
func runVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)

	packagePath := fs.String("package", "", "path to the package JSON to verify")
	issuerKeyPath := fs.String("issuer-key", "", "path to the issuer's Ed25519 public key")
	seedDir := fs.String("authority-seed-dir", "", "seed directory for the mock intent authority")
	authorityURL := fs.String("authority-url", "", "base URL of a real intent authority")
	asJSON := fs.Bool("json", false, "print the raw Report as JSON instead of a human-readable summary")

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *packagePath == "" || *issuerKeyPath == "" {
		fmt.Fprintln(stderr, "chainbind verify: --package and --issuer-key are required")
		return exitUsage
	}

	iv, err := resolveAuthority(*seedDir, *authorityURL)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}

	pub, err := loadIssuerPublicKey(*issuerKeyPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitOperational
	}

	pkg, err := readPackage(*packagePath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitOperational
	}

	// --issuer-key IS the trust store for this invocation (documented in
	// the top-level -h): it answers for any iss/kid the package claims for
	// itself. A real verifier would consult a trust store keyed by iss/kid
	// instead of accepting one key unconditionally.
	opt := chainbind.VerifyOptions{
		IssuerKey:    func(string, string) (ed25519.PublicKey, bool) { return pub, true },
		Intent:       iv, // nil when no --authority-* flag was given.
		BindingSpecs: agenticcheckout.BindingSpecs(),
	}

	report, err := chainbind.Verify(context.Background(), pkg, opt)
	if err != nil {
		fmt.Fprintf(stderr, "chainbind verify: %v\n", err)
		return exitOperational
	}

	if *asJSON {
		if err := printReportJSON(stdout, report); err != nil {
			fmt.Fprintf(stderr, "chainbind verify: %v\n", err)
			return exitOperational
		}
	} else {
		printReportHuman(stdout, report)
	}

	if !report.OK() {
		return exitNegative
	}
	return exitOK
}

// readPackage reads and decodes path as a *chainbind.Package.
func readPackage(path string) (*chainbind.Package, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // path is an operator-supplied CLI flag, not untrusted input
	if err != nil {
		return nil, fmt.Errorf("chainbind: read package %q: %w", path, err)
	}
	var pkg chainbind.Package
	if err := json.Unmarshal(raw, &pkg); err != nil {
		return nil, fmt.Errorf("chainbind: parse package %q: %w", path, err)
	}
	return &pkg, nil
}

// printReportJSON writes r as indented JSON.
func printReportJSON(w io.Writer, r *chainbind.Report) error {
	out, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	_, err = fmt.Fprintln(w, string(out))
	return err
}

// printReportHuman writes a field-by-field summary of r. Structural is
// printed by name via its fmt.Stringer (StructuralFault.String), never as a
// bare number. The unevaluated-intent line says so in plain words and
// deliberately avoids the word this file uses for a passing result, so a
// package whose authorization binding was never checked cannot be mistaken
// for one that passed (D-011).
func printReportHuman(w io.Writer, r *chainbind.Report) {
	fmt.Fprintf(w, "structural: %s\n", r.Structural)
	fmt.Fprintf(w, "spec_version_supported: %t\n", r.SpecVersionSupported)
	fmt.Fprintf(w, "signature: %t\n", r.Signature)
	fmt.Fprintf(w, "aad_context_consistent: %t\n", r.AADContextConsistent)
	fmt.Fprintf(w, "segments_root: %t\n", r.SegmentsRoot)

	for _, name := range sortedStringKeys(r.CipherHashes) {
		fmt.Fprintf(w, "cipher_hash[%s]: %t\n", name, r.CipherHashes[name])
	}
	for _, name := range sortedStringKeys(r.ProfileBindings) {
		fmt.Fprintf(w, "binding[%s]: %t\n", name, r.ProfileBindings[name])
	}

	if r.Intent.Evaluated {
		fmt.Fprintf(w, "intent: evaluated, valid=%t\n", r.Intent.Valid)
	} else {
		fmt.Fprintln(w, "intent: NOT EVALUATED — no reachable intent authority was consulted, so this package's binding to its authorization has not been checked")
	}
	if r.Intent.Reason != "" {
		fmt.Fprintf(w, "intent_reason: %s\n", r.Intent.Reason)
	}

	if r.OK() {
		fmt.Fprintln(w, "result: PASS")
	} else {
		fmt.Fprintln(w, "result: FAIL")
	}
}

// sortedStringKeys returns m's keys sorted, for deterministic CLI output.
func sortedStringKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
