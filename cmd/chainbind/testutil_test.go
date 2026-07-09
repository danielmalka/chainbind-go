package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/danielmalka/chainbind-go/pkg/chainbind/profile/agenticcheckout"
)

// runCLI invokes run(args, ...) with fresh buffers and returns the exit
// code plus everything written to stdout and stderr, so tests can assert on
// both without a subprocess. Exercising the subcommand functions directly
// (rather than building the binary and shelling out) keeps these tests fast
// and lets Go's race detector and coverage instrumentation see them; the
// black-box shape of run(args, io.Writer, io.Writer) is exactly what
// main() calls, so nothing about dispatch or flag parsing is skipped.
func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var outBuf, errBuf bytes.Buffer
	code = run(args, &outBuf, &errBuf)
	return code, outBuf.String(), errBuf.String()
}

// b64url encodes raw as base64url, unpadded — the CLI's key file format.
func b64url(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}

// readTestFile reads path, failing t on any error.
func readTestFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return raw
}

// writeFile writes contents to dir/name and returns the full path.
func writeFile(t *testing.T, dir, name, contents string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// genEd25519 generates a fresh Ed25519 keypair and returns the 32-byte seed
// (the CLI's --signing-key file format) alongside the derived key pair.
func genEd25519(t *testing.T) (seed []byte, pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	return priv.Seed(), pub, priv
}

// genX25519 generates a fresh X25519 keypair.
func genX25519(t *testing.T) (priv, pub []byte) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate x25519 key: %v", err)
	}
	return k.Bytes(), k.PublicKey().Bytes()
}

// testFixture bundles everything a seal->verify->open round trip needs:
// three audiences, their private keys, the issuer keypair, and the file
// paths seal/verify/open take as flags. email is embedded into the
// payload's Subject.Email so leak tests can look for a distinctive value.
type testFixture struct {
	dir string

	payloadPath   string
	audiencesPath string
	signingKey    string // issuer signing key file (seed)
	issuerPub     string // issuer public key file
	seedDir       string // mock intent authority seed dir

	intentRef string

	audiencePriv map[string]string // audience name -> private key file path
}

// newTestFixture writes a complete, self-consistent set of fixtures to a
// fresh temp dir: a payload whose projection (currency/amount/merchant_id)
// satisfies a freshly seeded mock authorization, three audiences with fresh
// X25519 keys, and the issuer's Ed25519 keypair. email, when non-empty,
// replaces the payload's Subject.Email — used by the leak test to plant a
// distinctive sentinel value.
func newTestFixture(t *testing.T, email string) testFixture {
	t.Helper()
	dir := t.TempDir()

	if email == "" {
		email = "cli-test@example.com"
	}
	payload := agenticcheckout.Payload{
		RequestContext: agenticcheckout.RequestContext{TenantID: "cli-tenant", Environment: "test"},
		Intent:         agenticcheckout.Intent{IntentRef: "intent:cli-test", Authority: "local-mock"},
		Subject: agenticcheckout.Subject{
			UserID: "usr_1", AccountID: "acc_1", Name: "Test User", Email: email,
			Roles: []string{"role_user"}, Permissions: []string{"checkout:create"}, AccountStatus: "active",
		},
		Checkout: agenticcheckout.Checkout{
			CheckoutID: "chk_1", MerchantID: "mer_test_1", MerchantName: "Test Store", Currency: "USD",
			Items:    []agenticcheckout.Item{{SKU: "SKU-1", Name: "Widget", Quantity: 1, UnitPrice: 500}},
			Subtotal: 500, Total: 500,
		},
		Payment: agenticcheckout.Payment{
			PaymentID: "pay_1", PaymentMethod: "card", BankAccountMasked: "***0000",
			BankCode: "000", PaymentReference: "ref-1", TransactionStatus: "pending", Amount: 500,
		},
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	payloadPath := writeFile(t, dir, "payload.json", string(payloadJSON))

	audienceNames := agenticcheckout.SegmentOrder()
	audiencePriv := make(map[string]string, len(audienceNames))
	type audJSON struct {
		Name      string `json:"name"`
		Kid       string `json:"kid"`
		PublicKey string `json:"public_key"`
	}
	var auds []audJSON
	for _, name := range audienceNames {
		priv, pub := genX25519(t)
		privPath := writeFile(t, dir, name+".key", b64url(priv))
		audiencePriv[name] = privPath
		auds = append(auds, audJSON{Name: name, Kid: name + "-key-1", PublicKey: b64url(pub)})
	}
	audsJSON, err := json.Marshal(auds)
	if err != nil {
		t.Fatalf("marshal audiences: %v", err)
	}
	audiencesPath := writeFile(t, dir, "audiences.json", string(audsJSON))

	seed, issuerPub, _ := genEd25519(t)
	signingKeyPath := writeFile(t, dir, "issuer.key", b64url(seed))
	issuerPubPath := writeFile(t, dir, "issuer.pub", b64url(issuerPub))

	seedDir := filepath.Join(dir, "authorizations")
	if err := os.Mkdir(seedDir, 0o700); err != nil {
		t.Fatalf("mkdir seed dir: %v", err)
	}
	writeFile(t, seedDir, "cli-test.json",
		`{"ref":"intent:cli-test","version":1,"rules":{"currency":{"equals":["USD"]},"amount":{"max":1000},"merchant_id":{"equals":["mer_test_1"]}}}`)

	return testFixture{
		dir:           dir,
		payloadPath:   payloadPath,
		audiencesPath: audiencesPath,
		signingKey:    signingKeyPath,
		issuerPub:     issuerPubPath,
		seedDir:       seedDir,
		intentRef:     "intent:cli-test",
		audiencePriv:  audiencePriv,
	}
}

// seal invokes `chainbind seal` against fx, writing the package to
// fx.dir/package.json, and fails t on a non-zero exit.
func (fx testFixture) seal(t *testing.T) (packagePath string) {
	t.Helper()
	packagePath = filepath.Join(fx.dir, "package.json")
	code, stdout, stderr := runCLI(
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
		"--out", packagePath,
	)
	if code != exitOK {
		t.Fatalf("seal exit = %d, want %d\nstdout=%s\nstderr=%s", code, exitOK, stdout, stderr)
	}
	return packagePath
}
