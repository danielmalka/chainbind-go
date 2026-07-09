// Command chainbind is the only place outside pkg/chainbind itself where
// Open ever runs (D-002, AGENTS.local.md invariant 1). The HTTP shell
// (cmd/chainbind-api) deliberately never exposes it: there is no
// /v1/packages/decrypt endpoint anywhere in this repository. A private key
// or a recovered plaintext is never sent over a network by this binary.
//
// Three subcommands wrap the library's three operations one-to-one, with no
// additional logic (TECHSPEC-001 §2/§3):
//
//	chainbind seal    reads a payload, audience public keys, an intent_ref
//	                  and a local signing key, and writes a signed *Package.
//	chainbind verify  reads a *Package and the issuer's public key, and
//	                  prints a *Report.
//	chainbind open    reads a *Package and a recipient's X25519 private key,
//	                  and writes the recovered plaintext. There is no
//	                  --segment or --audience flag: the audience is derived
//	                  by matching the supplied key's thumbprint against
//	                  cnf[a].jkt (TECHSPEC-001 §7, "Caller picks which
//	                  segment to open — not expressible").
package main

import (
	"fmt"
	"io"
	"os"
)

// Exit codes. Documented in the top-level -h text below; every subcommand
// returns exactly one of these.
const (
	// exitOK means the operation completed and the answer is positive.
	exitOK = 0
	// exitOperational means an operational failure: an unreadable file, a
	// key of the wrong length, an unreachable authority. The operation
	// could not be attempted or completed at all.
	exitOperational = 1
	// exitUsage means a usage error: a missing or conflicting flag, or an
	// unrecognised flag (e.g. --segment on open).
	exitUsage = 2
	// exitNegative means the operation completed and the answer is
	// negative: verify produced a Report that is not OK(), or open failed
	// an integrity check or could not decrypt.
	exitNegative = 3
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run dispatches to the named subcommand. It is separate from main so tests
// can drive it with injected writers and inspect the returned exit code
// without spawning a process.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printTopHelp(stderr)
		return exitUsage
	}

	switch args[0] {
	case "-h", "--help", "help":
		printTopHelp(stdout)
		return exitOK
	case "seal":
		return runSeal(args[1:], stdout, stderr)
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "open":
		return runOpen(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "chainbind: unknown subcommand %q\n\n", args[0])
		printTopHelp(stderr)
		return exitUsage
	}
}

// printTopHelp writes the top-level usage text, including the exit-code
// table the design brief requires to be documented in -h.
func printTopHelp(w io.Writer) {
	fmt.Fprint(w, `chainbind — seal, verify and open chainbind packages.

Usage:
  chainbind seal   --payload FILE --audiences FILE --intent-ref REF \
                   --signing-key FILE --issuer ISS --kid KID \
                   --tenant TENANT --environment ENV \
                   (--authority-seed-dir DIR | --authority-url URL) \
                   [--out FILE]

  chainbind verify --package FILE --issuer-key FILE \
                   [--authority-seed-dir DIR | --authority-url URL] \
                   [--json]

  chainbind open   --package FILE --key FILE --issuer-key FILE [--out FILE]

Exit codes:
  0  success
  1  operational failure — an unreadable file, a key of the wrong length,
     or an unreachable intent authority
  2  usage error — a missing or conflicting flag, or an unrecognised flag
  3  the operation completed and the answer is negative:
       verify: the Report is not OK() (includes: the intent level was not
               evaluated — never reported as success)
       open:   integrity check failed, or the recipient key opened no
               segment

Notes:
  - open takes no --segment or --audience flag. The audience is derived by
    matching the supplied private key's public thumbprint against the
    package's cnf entries; there is no way to ask to open a segment you do
    not hold the key for.
  - verify's --issuer-key IS the trust store for this invocation: the
    supplied key is accepted for whatever iss/kid the package under
    verification claims for itself. A production verifier would consult a
    real trust store keyed by iss/kid instead.
`)
}
