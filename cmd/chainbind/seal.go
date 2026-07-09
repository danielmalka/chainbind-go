package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/danielmalka/chainbind-go/internal/adapters/keywrap/x25519"
	"github.com/danielmalka/chainbind-go/internal/adapters/signer/local"
	"github.com/danielmalka/chainbind-go/pkg/chainbind"
	"github.com/danielmalka/chainbind-go/pkg/chainbind/profile/agenticcheckout"
)

// errSealRequiresOneAuthority is returned when seal is invoked with neither
// --authority-seed-dir nor --authority-url. Seal fails closed on an
// unreachable authority (architecture invariant 6); a CLI invocation with no
// authority configured at all gets the same refusal, just earlier.
var errSealRequiresOneAuthority = errors.New("chainbind seal: exactly one of --authority-seed-dir or --authority-url is required")

// runSeal implements `chainbind seal`. It decodes the payload into
// agenticcheckout.Payload, splits and projects it, signs locally
// (never Vault — a standalone user must be able to seal without a Vault
// deployment), wraps DEKs with x25519.Wrapper, and writes the resulting
// *chainbind.Package as indented JSON.
func runSeal(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("seal", flag.ContinueOnError)
	fs.SetOutput(stderr)

	payloadPath := fs.String("payload", "", "path to a JSON payload (agentic-checkout/v1 shape)")
	audiencesPath := fs.String("audiences", "", `path to a JSON array of audience public keys: [{"name","kid","public_key"}]`)
	intentRef := fs.String("intent-ref", "", "the immutable authorization reference this execution is checked against")
	signingKeyPath := fs.String("signing-key", "", "path to the issuer's Ed25519 signing key (32-byte seed, base64url)")
	issuer := fs.String("issuer", "", "issuer identifier (issuer.iss)")
	kid := fs.String("kid", "", "the signing key's identifier (signature.kid)")
	tenant := fs.String("tenant", "", "tenant id for the AAD context")
	environment := fs.String("environment", "", "environment name for the AAD context")
	seedDir := fs.String("authority-seed-dir", "", "seed directory for the mock intent authority")
	authorityURL := fs.String("authority-url", "", "base URL of a real intent authority")
	out := fs.String("out", "", "write the sealed package here instead of stdout")

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	if *payloadPath == "" || *audiencesPath == "" || *intentRef == "" ||
		*signingKeyPath == "" || *issuer == "" || *kid == "" {
		fmt.Fprintln(stderr, "chainbind seal: --payload, --audiences, --intent-ref, --signing-key, --issuer and --kid are all required")
		return exitUsage
	}

	iv, err := resolveAuthority(*seedDir, *authorityURL)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	if iv == nil {
		fmt.Fprintln(stderr, errSealRequiresOneAuthority)
		return exitUsage
	}

	priv, err := loadIssuerSigningKey(*signingKeyPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitOperational
	}

	audiences, err := loadAudiences(*audiencesPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitOperational
	}

	payload, err := readPayload(*payloadPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitOperational
	}

	var profile agenticcheckout.Profile
	segments, err := profile.Split(payload)
	if err != nil {
		fmt.Fprintf(stderr, "chainbind seal: split payload: %v\n", err)
		return exitOperational
	}
	projection, err := profile.Project(payload)
	if err != nil {
		fmt.Fprintf(stderr, "chainbind seal: project payload: %v\n", err)
		return exitOperational
	}

	signer, err := local.New(priv, *kid)
	if err != nil {
		fmt.Fprintf(stderr, "chainbind seal: %v\n", err)
		return exitOperational
	}

	req := chainbind.SealRequest{
		Segments:     segments,
		SegmentOrder: agenticcheckout.SegmentOrder(),
		Audiences:    toChainbindAudiences(audiences),
		IntentRef:    *intentRef,
		Authority:    authorityLabel(*seedDir, *authorityURL),
		Projection:   projection,
		Issuer:       *issuer,
		IssuedAt:     time.Now().UTC(),
		TenantID:     *tenant,
		Environment:  *environment,
		Profile:      agenticcheckout.Name,
		BindingSpecs: agenticcheckout.BindingSpecs(),
	}

	pkg, err := chainbind.Seal(context.Background(), req, signer, x25519.Wrapper{}, iv)
	if err != nil {
		fmt.Fprintf(stderr, "chainbind seal: %v\n", err)
		return exitOperational
	}

	raw, err := json.MarshalIndent(pkg, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "chainbind seal: encode package: %v\n", err)
		return exitOperational
	}
	if err := writeOutput(*out, stdout, raw); err != nil {
		fmt.Fprintf(stderr, "chainbind seal: %v\n", err)
		return exitOperational
	}
	return exitOK
}

// readPayload reads and decodes path as an agenticcheckout.Payload.
func readPayload(path string) (agenticcheckout.Payload, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // path is an operator-supplied CLI flag, not untrusted input
	if err != nil {
		return agenticcheckout.Payload{}, fmt.Errorf("chainbind seal: read payload %q: %w", path, err)
	}
	var payload agenticcheckout.Payload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return agenticcheckout.Payload{}, fmt.Errorf("chainbind seal: parse payload %q: %w", path, err)
	}
	return payload, nil
}

// toChainbindAudiences converts loadAudiences' result into the
// chainbind.Audience slice SealRequest expects.
func toChainbindAudiences(in []audienceAndPublicKey) []chainbind.Audience {
	out := make([]chainbind.Audience, 0, len(in))
	for _, a := range in {
		out = append(out, chainbind.Audience{Name: a.name, PublicKey: a.pub, Kid: a.kid})
	}
	return out
}
