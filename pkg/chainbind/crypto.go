package chainbind

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// dekSize is the length in bytes of a segment data-encryption key: 256 bits.
const dekSize = 32

// nonceSize is the length in bytes of a GCM nonce: 96 bits, the size GCM is
// designed for (TECHSPEC-001 §6.6 decision 7).
const nonceSize = 12

// ErrDecryptionFailed is returned when AES-256-GCM authentication fails —
// wrong key, tampered ciphertext, or AAD that no longer matches the segment
// it was sealed under. It carries no detail: which of those it was is not
// safe to distinguish from an error message (architecture invariant 10).
var ErrDecryptionFailed = errors.New("chainbind: decryption failed")

// NewDEK generates a fresh 256-bit data-encryption key from crypto/rand.
// Every segment, in every seal, gets its own DEK (architecture invariant 11
// depends on this: reusing a DEK across segments would let a spliced
// ciphertext decrypt under the wrong AAD's key).
func NewDEK() ([]byte, error) {
	dek := make([]byte, dekSize)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("chainbind: generate dek: %w", err)
	}
	return dek, nil
}

// Encrypt seals plaintext under dek with AES-256-GCM, authenticating aad as
// additional data (TECHSPEC-001 §6.3). A fresh 96-bit nonce is drawn from
// crypto/rand for every call and returned alongside the ciphertext; the
// nonce is not secret and is stored with the segment. dek must be 32 bytes.
func Encrypt(dek, plaintext, aad []byte) (ciphertext, nonce []byte, err error) {
	gcm, err := newGCM(dek)
	if err != nil {
		return nil, nil, err
	}

	nonce = make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("chainbind: generate nonce: %w", err)
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, aad)
	return ciphertext, nonce, nil
}

// Decrypt opens ciphertext with dek, nonce and aad. A non-nil error is
// always ErrDecryptionFailed: a wrong dek, a tampered ciphertext byte, and a
// mismatched aad are all indistinguishable failures by design, and none of
// them may be described in more detail (architecture invariant 10).
func Decrypt(dek, nonce, ciphertext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, ErrDecryptionFailed
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}

// newGCM builds an AES-256-GCM AEAD from dek. It returns ErrDecryptionFailed
// rather than the underlying error: a dek of the wrong length is itself
// secret-derived information an error message must not echo.
func newGCM(dek []byte) (cipher.AEAD, error) {
	if len(dek) != dekSize {
		return nil, ErrDecryptionFailed
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return gcm, nil
}
