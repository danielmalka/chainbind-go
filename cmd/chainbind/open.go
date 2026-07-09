package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"io"

	"github.com/danielmalka/chainbind-go/internal/adapters/keywrap/x25519"
	"github.com/danielmalka/chainbind-go/pkg/chainbind"
	"github.com/danielmalka/chainbind-go/pkg/chainbind/profile/agenticcheckout"
)

// runOpen implements `chainbind open`. There is deliberately no
// --segment/--audience flag: Open derives the audience by matching the
// thumbprint of the supplied private key against cnf[a].jkt (TECHSPEC-001
// §7, "Caller picks which segment to open — not expressible"). Go's flag
// package errors on an unrecognised flag by default, so `open --segment X`
// is a usage error here, not a silently ignored one.
//
// opt carries only IssuerKey. Open ignores opt.Intent entirely (see
// pkg/chainbind/open.go's own doc comment: opening is offline, and the
// intent level is not an integrity property), so this subcommand does not
// even accept an --authority-* flag — a caller who passed one here could
// wrongly assume it was consulted. A caller who wants to know the package
// is bound to a live authorization runs `chainbind verify` and reads its
// result.
func runOpen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("open", flag.ContinueOnError)
	fs.SetOutput(stderr)

	packagePath := fs.String("package", "", "path to the package JSON to open")
	keyPath := fs.String("key", "", "path to the recipient's X25519 private key")
	issuerKeyPath := fs.String("issuer-key", "", "path to the issuer's Ed25519 public key")
	out := fs.String("out", "", "write the recovered plaintext here instead of stdout")

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *packagePath == "" || *keyPath == "" || *issuerKeyPath == "" {
		fmt.Fprintln(stderr, "chainbind open: --package, --key and --issuer-key are required")
		return exitUsage
	}

	priv, err := loadRecipientPrivateKey(*keyPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitOperational
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

	// BindingSpecs is not optional here, despite Open being offline. Open
	// runs Verify's Level 1 in full before it unwraps a data key, and L1.6 —
	// the recomputation of every profile binding — only runs for the specs it
	// is given. Pass none and level1Passed's loop over ProfileBindings is
	// vacuous: an issuer who writes garbage into bindings.transaction_id and
	// re-signs produces a package this command opens without complaint.
	//
	// opt.Intent is deliberately absent. Open ignores it: opening is offline,
	// and the intent level is not an integrity property. A caller who passes
	// a live authority here may assume it was consulted. It is not.
	opt := chainbind.VerifyOptions{
		IssuerKey:    func(string, string) (ed25519.PublicKey, bool) { return pub, true },
		BindingSpecs: agenticcheckout.BindingSpecs(),
	}

	audience, plaintext, err := chainbind.Open(context.Background(), pkg, priv, x25519.Wrapper{}, opt)
	if err != nil {
		// Every Open failure sentinel is a static string (ErrIntegrityCheckFailed,
		// ErrDecryptionFailed, ErrHashMismatch): never the plaintext, the DEK,
		// or priv (AGENTS.local.md invariant 10).
		fmt.Fprintf(stderr, "chainbind open: %v\n", err)
		return exitNegative
	}

	fmt.Fprintf(stderr, "opened audience: %s\n", audience)
	if err := writeOutput(*out, stdout, plaintext); err != nil {
		fmt.Fprintf(stderr, "chainbind open: %v\n", err)
		return exitOperational
	}
	return exitOK
}
