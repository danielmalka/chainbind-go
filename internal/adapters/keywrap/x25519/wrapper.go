// Package x25519 implements chainbind.KeyWrapper: ECDH-ES key agreement
// over X25519 followed by A256KW (RFC 3394 AES Key Wrap with a 256-bit KEK)
// to wrap a segment's data-encryption key to a recipient's public key, and
// to unwrap it with the recipient's private key. It also computes the RFC
// 7638 JWK thumbprint of an X25519 public key, the value that goes into
// manifest.cnf[a].jkt.
package x25519

import (
	"context"
	"crypto/aes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// algorithmID is the JOSE "alg" value fed into the Concat KDF as AlgorithmID
// (RFC 7518 §4.6.2), fixing the key-derivation context to this exact
// combination of key agreement and key wrap. Changing it would silently
// change every derived KEK.
const algorithmID = "ECDH-ES+A256KW"

// kekLenBits is the length of the AES key-encryption key A256KW requires.
const kekLenBits = 256

// ErrUnwrapFailed is returned when Unwrap cannot recover a DEK: the wrong
// private key, a tampered epk, or a tampered wrapped key are all
// indistinguishable failures, and none of them may be described in more
// detail (architecture invariant 10 — no error carries secret-derived
// bytes).
var ErrUnwrapFailed = errors.New("keywrap/x25519: unwrap failed")

// ErrWrapFailed is the Wrap-side counterpart. It exists because the obvious
// error messages on this path name the length of the data-encryption key or
// of the ECDH-derived key-encryption key. A length is a fact about secret
// material, and invariant 10 admits no exceptions for facts that feel
// harmless: key lengths distinguish algorithms, and an oracle that reveals
// why a wrap failed is an oracle.
var ErrWrapFailed = errors.New("keywrap/x25519: wrap failed")

// Wrapper implements chainbind.KeyWrapper.
type Wrapper struct{}

// Wrap agrees on a shared secret with recipientPub via a fresh ephemeral
// X25519 keypair (ECDH-ES), derives a 256-bit KEK from it with the Concat
// KDF, and wraps dek under that KEK with RFC 3394 AES Key Wrap. epk is the
// ephemeral public key, recorded alongside the wrapped key so Unwrap can
// redo the agreement.
func (Wrapper) Wrap(_ context.Context, recipientPub, dek []byte) (wrapped, epk []byte, err error) {
	curve := ecdh.X25519()

	recipient, err := curve.NewPublicKey(recipientPub)
	if err != nil {
		return nil, nil, fmt.Errorf("keywrap/x25519: parse recipient public key: %w", err)
	}

	ephemeralPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("keywrap/x25519: generate ephemeral key: %w", err)
	}

	shared, err := ephemeralPriv.ECDH(recipient)
	if err != nil {
		return nil, nil, fmt.Errorf("keywrap/x25519: ecdh: %w", err)
	}

	kek := concatKDF(shared, concatKDFOtherInfo(algorithmID, kekLenBits), kekLenBits)

	wrapped, err = aesKeyWrap(kek, dek)
	if err != nil {
		return nil, nil, err
	}

	return wrapped, ephemeralPriv.PublicKey().Bytes(), nil
}

// Unwrap redoes the ECDH-ES agreement between priv and the ephemeral public
// key epk, rederives the KEK, and unwraps wrapped to recover the DEK. Any
// failure — wrong priv, tampered epk, tampered wrapped — collapses to the
// single static ErrUnwrapFailed sentinel.
func (Wrapper) Unwrap(_ context.Context, priv, epk, wrapped []byte) (dek []byte, err error) {
	curve := ecdh.X25519()

	recipientPriv, err := curve.NewPrivateKey(priv)
	if err != nil {
		return nil, ErrUnwrapFailed
	}

	ephemeralPub, err := curve.NewPublicKey(epk)
	if err != nil {
		return nil, ErrUnwrapFailed
	}

	shared, err := recipientPriv.ECDH(ephemeralPub)
	if err != nil {
		return nil, ErrUnwrapFailed
	}

	kek := concatKDF(shared, concatKDFOtherInfo(algorithmID, kekLenBits), kekLenBits)

	dek, err = aesKeyUnwrap(kek, wrapped)
	if err != nil {
		return nil, ErrUnwrapFailed
	}

	return dek, nil
}

// Thumbprint computes the RFC 7638 JWK thumbprint of an X25519 public key,
// represented per RFC 8037 as an OKP JWK with crv "X25519". The three
// required members are already in lexicographic order (crv, kty, x) and
// none of their values needs JSON escaping: kty and crv are fixed literals,
// and x is base64url, whose alphabet contains no character JSON escapes.
func Thumbprint(pub []byte) (string, error) {
	curve := ecdh.X25519()
	if _, err := curve.NewPublicKey(pub); err != nil {
		return "", fmt.Errorf("keywrap/x25519: parse public key: %w", err)
	}

	x := base64.RawURLEncoding.EncodeToString(pub)
	canonical := fmt.Sprintf(`{"crv":"X25519","kty":"OKP","x":%q}`, x)

	return thumbprintOf([]byte(canonical)), nil
}

// thumbprintOf is the RFC 7638 thumbprint computation itself: base64url(no
// padding) of SHA-256 over the caller-supplied canonical JWK JSON. Split
// out from Thumbprint so it can be pinned directly against the RFC 8037
// Appendix A.3 worked example, which supplies its own canonical JSON.
func thumbprintOf(canonicalJWK []byte) string {
	sum := sha256.Sum256(canonicalJWK)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// concatKDF implements the Concat KDF (NIST SP 800-56A, one-step key
// derivation) as profiled by RFC 7518 §4.6 for ECDH-ES. Each round hashes
// the 4-byte big-endian round counter, starting at 1, then Z, then
// OtherInfo. keyDataLenBits must be a multiple of 8.
//
// OtherInfo is supplied by the caller rather than built here, so that the
// worked example in RFC 7518 Appendix C — the only authoritative Concat KDF
// test vector for this profile, and it uses a non-empty apu and apv — can be
// pinned as a known-answer test. A key-derivation function exercised only
// through a round trip is not verified: encrypt and decrypt agree just as
// happily on a wrong KDF, and the divergence surfaces years later, against
// somebody else's JOSE implementation.
func concatKDF(z, otherInfo []byte, keyDataLenBits int) []byte {
	keyDataLen := keyDataLenBits / 8
	out := make([]byte, 0, keyDataLen)

	for counter := uint32(1); len(out) < keyDataLen; counter++ {
		h := sha256.New()
		var counterBytes [4]byte
		binary.BigEndian.PutUint32(counterBytes[:], counter)
		h.Write(counterBytes[:])
		h.Write(z)
		h.Write(otherInfo)
		out = append(out, h.Sum(nil)...)
	}

	return out[:keyDataLen]
}

// concatKDFOtherInfo builds OtherInfo for this adapter:
// AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo. The first three
// are each a 4-byte big-endian length prefix followed by the value; an
// empty PartyUInfo/PartyVInfo is therefore the four zero bytes of a zero
// length, not the absence of bytes. SuppPubInfo is the key length in
// **bits**, not bytes. This adapter never sets apu/apv (RFC 7518
// §4.6.1.2/4.6.1.3 default), and there is no SuppPrivInfo.
func concatKDFOtherInfo(algID string, keyDataLenBits int) []byte {
	var buf []byte
	buf = append(buf, lengthPrefixed([]byte(algID))...)
	buf = append(buf, lengthPrefixed(nil)...) // PartyUInfo: empty (apu unset)
	buf = append(buf, lengthPrefixed(nil)...) // PartyVInfo: empty (apv unset)

	var suppPubInfo [4]byte
	binary.BigEndian.PutUint32(suppPubInfo[:], safeUint32(keyDataLenBits))
	buf = append(buf, suppPubInfo[:]...)

	return buf
}

func lengthPrefixed(v []byte) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], safeUint32(len(v)))
	return append(length[:], v...)
}

// safeUint32 converts a non-negative int known to be small (a slice length
// or a Concat KDF loop counter, both bounded well under 2^32 in this
// package) to uint32. The explicit bounds check exists so the conversion
// is not a silent wraparound if that assumption is ever violated.
func safeUint32(n int) uint32 {
	if n < 0 || n > math.MaxUint32 {
		return 0
	}
	return uint32(n)
}

// safeUint64 converts a non-negative int (an RFC 3394 wrap/unwrap round
// counter, always small) to uint64, guarding the conversion the same way
// safeUint32 does.
func safeUint64(n int) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n)
}

// aesKeyWrapIV is the 64-bit default initial value from RFC 3394 §2.2.3.1.
var aesKeyWrapIV = [8]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// aesKeyWrap wraps keyData under kek per RFC 3394 §2.2.1. keyData must be a
// non-empty multiple of 8 bytes; kek must be a valid AES key (16, 24, or 32
// bytes — this adapter always supplies 32, matching A256KW).
//
// Its errors name no length. keyData is a data-encryption key and kek is
// derived from an ECDH shared secret; the length of either is a fact about
// secret material, and architecture invariant 10 admits no exceptions for
// facts that feel harmless.
func aesKeyWrap(kek, keyData []byte) ([]byte, error) {
	if len(keyData) == 0 || len(keyData)%8 != 0 {
		return nil, ErrWrapFailed
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, ErrWrapFailed
	}

	n := len(keyData) / 8
	r := make([][8]byte, n)
	for i := range n {
		copy(r[i][:], keyData[i*8:(i+1)*8])
	}

	a := aesKeyWrapIV

	var block16 [16]byte
	for j := 0; j <= 5; j++ {
		for i := 1; i <= n; i++ {
			copy(block16[:8], a[:])
			copy(block16[8:], r[i-1][:])
			block.Encrypt(block16[:], block16[:])

			copy(a[:], block16[:8])
			t := safeUint64(n*j + i)
			xorCounter(&a, t)
			copy(r[i-1][:], block16[8:])
		}
	}

	out := make([]byte, 8*(n+1))
	copy(out[:8], a[:])
	for i := range n {
		copy(out[8*(i+1):8*(i+2)], r[i][:])
	}
	return out, nil
}

// aesKeyUnwrap reverses aesKeyWrap and checks the recovered value against
// the standard integrity check (the well-known IV). A failure — wrong kek
// or a tampered wrapped value — returns a plain error; callers in this
// package convert it to the static ErrUnwrapFailed sentinel before it can
// reach an application error string.
func aesKeyUnwrap(kek, wrapped []byte) ([]byte, error) {
	if len(wrapped) < 16 || len(wrapped)%8 != 0 {
		return nil, ErrWrapFailed
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, ErrWrapFailed
	}

	n := len(wrapped)/8 - 1
	var a [8]byte
	copy(a[:], wrapped[:8])

	r := make([][8]byte, n)
	for i := range n {
		copy(r[i][:], wrapped[8*(i+1):8*(i+2)])
	}

	var block16 [16]byte
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			t := safeUint64(n*j + i)
			xorCounter(&a, t)

			copy(block16[:8], a[:])
			copy(block16[8:], r[i-1][:])
			block.Decrypt(block16[:], block16[:])

			copy(a[:], block16[:8])
			copy(r[i-1][:], block16[8:])
		}
	}

	if subtle.ConstantTimeCompare(a[:], aesKeyWrapIV[:]) != 1 {
		return nil, errors.New("keywrap/x25519: integrity check failed")
	}

	out := make([]byte, 8*n)
	for i := range n {
		copy(out[8*i:8*(i+1)], r[i][:])
	}
	return out, nil
}

// xorCounter XORs the 64-bit big-endian value t into a, as RFC 3394 §2.2.1
// requires ("A XOR t" where t is treated as a 64-bit big-endian integer,
// though it never exceeds 32 bits in practice since n*j+i is small).
func xorCounter(a *[8]byte, t uint64) {
	var tb [8]byte
	binary.BigEndian.PutUint64(tb[:], t)
	for i := range a {
		a[i] ^= tb[i]
	}
}
