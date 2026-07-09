package x25519

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/danielmalka/chainbind-go/pkg/chainbind"
)

// Wrapper must satisfy the port pkg/chainbind declares for it.
var _ chainbind.KeyWrapper = Wrapper{}

func genKeypair(t *testing.T) (priv, pub []byte) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate x25519 key: %v", err)
	}
	return k.Bytes(), k.PublicKey().Bytes()
}

func TestWrapUnwrap_RoundTrip(t *testing.T) {
	priv, pub := genKeypair(t)
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("generate dek: %v", err)
	}

	w := Wrapper{}
	ctx := context.Background()

	wrapped, epk, err := w.Wrap(ctx, pub, dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	got, err := w.Unwrap(ctx, priv, epk, wrapped)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatalf("Unwrap recovered %x, want %x", got, dek)
	}
}

func TestUnwrap_WrongRecipientPrivateKeyFails(t *testing.T) {
	_, pub := genKeypair(t)
	otherPriv, _ := genKeypair(t)

	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("generate dek: %v", err)
	}

	w := Wrapper{}
	ctx := context.Background()

	wrapped, epk, err := w.Wrap(ctx, pub, dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	_, err = w.Unwrap(ctx, otherPriv, epk, wrapped)
	if !errors.Is(err, ErrUnwrapFailed) {
		t.Fatalf("Unwrap with the wrong private key = %v, want ErrUnwrapFailed", err)
	}
	if err.Error() != ErrUnwrapFailed.Error() {
		t.Fatalf("Unwrap error carries extra content: %q", err.Error())
	}
}

func TestUnwrap_TamperedWrappedKeyFails(t *testing.T) {
	priv, pub := genKeypair(t)
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("generate dek: %v", err)
	}

	w := Wrapper{}
	ctx := context.Background()

	wrapped, epk, err := w.Wrap(ctx, pub, dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	tampered := bytes.Clone(wrapped)
	tampered[0] ^= 0xFF

	if _, err := w.Unwrap(ctx, priv, epk, tampered); !errors.Is(err, ErrUnwrapFailed) {
		t.Fatalf("Unwrap of a tampered wrapped key = %v, want ErrUnwrapFailed", err)
	}
}

func TestUnwrap_TamperedEPKFails(t *testing.T) {
	priv, pub := genKeypair(t)
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("generate dek: %v", err)
	}

	w := Wrapper{}
	ctx := context.Background()

	wrapped, epk, err := w.Wrap(ctx, pub, dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	tamperedEPK := bytes.Clone(epk)
	tamperedEPK[0] ^= 0xFF

	if _, err := w.Unwrap(ctx, priv, tamperedEPK, wrapped); !errors.Is(err, ErrUnwrapFailed) {
		t.Fatalf("Unwrap with a tampered epk = %v, want ErrUnwrapFailed", err)
	}
}

func TestThumbprint_StableAndDistinct(t *testing.T) {
	_, pubA := genKeypair(t)
	_, pubB := genKeypair(t)

	tpA1, err := Thumbprint(pubA)
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	tpA2, err := Thumbprint(pubA)
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	if tpA1 != tpA2 {
		t.Fatalf("Thumbprint not stable for the same key: %q != %q", tpA1, tpA2)
	}

	tpB, err := Thumbprint(pubB)
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	if tpA1 == tpB {
		t.Fatal("Thumbprint produced the same value for two different keys")
	}
}

// TestThumbprint_RFC7638Construction pins the canonicalization this
// function relies on against the worked example in RFC 8037 Appendix A.3,
// the only published RFC 7638 thumbprint vector for an OKP JWK. That
// example uses an Ed25519 key (crv "Ed25519"); no published vector exists
// for crv "X25519" specifically, so this test reproduces the RFC's
// Ed25519 canonical-JSON-then-SHA-256 computation directly (the same
// construction Thumbprint uses with crv fixed to "X25519") and checks it
// against the RFC's published thumbprint, rather than asserting an
// invented X25519 vector.
func TestThumbprint_RFC7638Construction(t *testing.T) {
	const canonical = `{"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
	const wantThumbprint = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"

	got := thumbprintOf([]byte(canonical))
	if got != wantThumbprint {
		t.Fatalf("RFC 8037 Appendix A.3 thumbprint = %q, want %q", got, wantThumbprint)
	}
}

func TestWrap_FreshEphemeralKeyPerCall(t *testing.T) {
	_, pub := genKeypair(t)
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("generate dek: %v", err)
	}

	w := Wrapper{}
	ctx := context.Background()

	_, epk1, err := w.Wrap(ctx, pub, dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	_, epk2, err := w.Wrap(ctx, pub, dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	if bytes.Equal(epk1, epk2) {
		t.Fatal("two Wrap calls to the same recipient produced the same ephemeral public key")
	}
}

// TestAESKeyWrap_RFC3394KnownAnswer pins aesKeyWrap/aesKeyUnwrap against
// the authoritative known-answer vectors published in RFC 3394 §4.3 (128-
// bit key data under a 256-bit KEK) and §4.6 (256-bit key data under a
// 256-bit KEK).
func TestAESKeyWrap_RFC3394KnownAnswer(t *testing.T) {
	kek := mustHex(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")

	tests := []struct {
		name    string
		keyData string
		want    string
	}{
		{
			name:    "RFC 3394 §4.3 — 128-bit key data, 256-bit KEK",
			keyData: "00112233445566778899AABBCCDDEEFF", // gitleaks:allow RFC 3394 §4.3 published vector
			want:    "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7",
		},
		{
			name:    "RFC 3394 §4.6 — 256-bit key data, 256-bit KEK",
			keyData: "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F", // gitleaks:allow RFC 3394 §4.6 published vector
			want:    "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyData := mustHex(t, tt.keyData)
			want := mustHex(t, tt.want)

			got, err := aesKeyWrap(kek, keyData)
			if err != nil {
				t.Fatalf("aesKeyWrap: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("aesKeyWrap = %x, want %x", got, want)
			}

			back, err := aesKeyUnwrap(kek, got)
			if err != nil {
				t.Fatalf("aesKeyUnwrap: %v", err)
			}
			if !bytes.Equal(back, keyData) {
				t.Fatalf("aesKeyUnwrap = %x, want %x", back, keyData)
			}
		})
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex %q: %v", s, err)
	}
	return b
}

// TestConcatKDF_RFC7518AppendixC pins the Concat KDF against the worked
// example in RFC 7518 Appendix C — the only authoritative test vector for
// this profile. It is the check the round-trip tests cannot make: Wrap and
// Unwrap agree just as happily on a wrong KDF, and the divergence would
// surface only against somebody else's JOSE implementation, years later.
//
// The example uses apu="Alice" and apv="Bob", which is what makes it useful
// here: it exercises the 4-byte big-endian length prefix on non-empty
// PartyUInfo/PartyVInfo, a place implementations silently disagree.
func TestConcatKDF_RFC7518AppendixC(t *testing.T) {
	// Appendix C: "In this example, Z is following the octet sequence".
	z := []byte{
		158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132,
		38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121,
		140, 254, 144, 196,
	}

	// Appendix C: "Concatenating the parameters AlgorithmID through
	// SuppPubInfo results in an OtherInfo value of".
	wantOtherInfo := []byte{
		0, 0, 0, 7, 65, 49, 50, 56, 71, 67, 77,
		0, 0, 0, 5, 65, 108, 105, 99, 101,
		0, 0, 0, 3, 66, 111, 98,
		0, 0, 0, 128,
	}

	var otherInfo []byte
	otherInfo = append(otherInfo, lengthPrefixed([]byte("A128GCM"))...)
	otherInfo = append(otherInfo, lengthPrefixed([]byte("Alice"))...)
	otherInfo = append(otherInfo, lengthPrefixed([]byte("Bob"))...)
	var suppPubInfo [4]byte
	binary.BigEndian.PutUint32(suppPubInfo[:], 128)
	otherInfo = append(otherInfo, suppPubInfo[:]...)

	if !bytes.Equal(otherInfo, wantOtherInfo) {
		t.Fatalf("OtherInfo:\n got %v\nwant %v", otherInfo, wantOtherInfo)
	}

	// Appendix C: "The resulting derived key, which is the first 128 bits
	// of the round 1 hash output is".
	wantKey := []byte{86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26}

	got := concatKDF(z, otherInfo, 128)
	if !bytes.Equal(got, wantKey) {
		t.Fatalf("derived key:\n got %v\nwant %v", got, wantKey)
	}

	// Appendix C: "The base64url-encoded representation of this derived key".
	const wantB64 = "VqqN6vgjbSBcIijNcacQGg"
	if b64 := base64.RawURLEncoding.EncodeToString(got); b64 != wantB64 {
		t.Fatalf("derived key base64url = %q, want %q", b64, wantB64)
	}
}

// TestConcatKDFOtherInfo_EmptyPartyInfoIsAZeroLength guards the encoding an
// implementation most often gets wrong: an unset apu/apv is a four-byte zero
// *length*, not the absence of bytes. Getting this wrong shortens OtherInfo
// by eight bytes and derives a different KEK from the same shared secret.
func TestConcatKDFOtherInfo_EmptyPartyInfoIsAZeroLength(t *testing.T) {
	got := concatKDFOtherInfo("ECDH-ES+A256KW", 256)

	want := []byte{0, 0, 0, 14}
	want = append(want, []byte("ECDH-ES+A256KW")...)
	want = append(
		want,
		0, 0, 0, 0, // PartyUInfo: zero length, not zero bytes
		0, 0, 0, 0, // PartyVInfo: zero length, not zero bytes
		0, 0, 1, 0, // SuppPubInfo: 256, in bits, big-endian
	)

	if !bytes.Equal(got, want) {
		t.Fatalf("OtherInfo:\n got %v\nwant %v", got, want)
	}
}

// TestWrapUnwrapErrors_NameNoLength proves both directions collapse to a
// static sentinel. A length is a fact about secret material: it distinguishes
// algorithms, and an error that explains why a wrap failed is an oracle.
// Unwrap was already careful; Wrap was not, and the difference was invisible
// until someone read the two side by side.
func TestWrapUnwrapErrors_NameNoLength(t *testing.T) {
	priv, pub := genKeypair(t)
	w := Wrapper{}
	ctx := context.Background()

	// A DEK of a length RFC 3394 cannot wrap: not a positive multiple of 8.
	_, _, err := w.Wrap(ctx, pub, make([]byte, 31))
	if !errors.Is(err, ErrWrapFailed) {
		t.Fatalf("Wrap with a 31-byte dek = %v, want ErrWrapFailed", err)
	}
	if err.Error() != ErrWrapFailed.Error() {
		t.Fatalf("Wrap error carries extra content: %q", err.Error())
	}

	_, err = w.Unwrap(ctx, priv, pub, make([]byte, 7))
	if err.Error() != ErrUnwrapFailed.Error() {
		t.Fatalf("Unwrap error carries extra content: %q", err.Error())
	}
}
