package chainbind

import (
	"bytes"
	"errors"
	"testing"
)

func TestNewDEK_DistinctAcrossCalls(t *testing.T) {
	a, err := NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	b, err := NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	if len(a) != dekSize || len(b) != dekSize {
		t.Fatalf("NewDEK: got lengths %d, %d; want %d", len(a), len(b), dekSize)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two NewDEK() calls produced the same key")
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		plaintext []byte
	}{
		{name: "empty", plaintext: []byte{}},
		{name: "short", plaintext: []byte("hi")},
		{name: "one block", plaintext: bytes.Repeat([]byte{0x42}, 16)},
		{name: "multi block", plaintext: bytes.Repeat([]byte("chainbind segment payload "), 100)},
	}

	dek, err := NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	aad := []byte(`{"package_id":"pkg-1","segment":"a"}`)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, nonce, err := Encrypt(dek, tt.plaintext, aad)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			if len(nonce) != nonceSize {
				t.Fatalf("nonce length = %d, want %d", len(nonce), nonceSize)
			}

			got, err := Decrypt(dek, nonce, ciphertext, aad)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(got, tt.plaintext) {
				t.Fatalf("round-trip mismatch: got %q, want %q", got, tt.plaintext)
			}
		})
	}
}

func TestDecrypt_WrongAADFails(t *testing.T) {
	dek, err := NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	plaintext := []byte("segment a's plaintext")
	aadA := []byte(`{"package_id":"pkg-1","segment":"a"}`)
	aadB := []byte(`{"package_id":"pkg-1","segment":"b"}`)

	ciphertext, nonce, err := Encrypt(dek, plaintext, aadA)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if _, err := Decrypt(dek, nonce, ciphertext, aadB); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("Decrypt with segment b's AAD = %v, want ErrDecryptionFailed", err)
	}

	// Sanity: the same ciphertext still opens under the AAD it was sealed with.
	if _, err := Decrypt(dek, nonce, ciphertext, aadA); err != nil {
		t.Fatalf("Decrypt with the original AAD failed: %v", err)
	}
}

func TestDecrypt_TamperedCiphertextFails(t *testing.T) {
	dek, err := NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	aad := []byte(`{"package_id":"pkg-1","segment":"a"}`)

	ciphertext, nonce, err := Encrypt(dek, []byte("payload"), aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	tampered := bytes.Clone(ciphertext)
	tampered[0] ^= 0xFF

	if _, err := Decrypt(dek, nonce, tampered, aad); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("Decrypt of tampered ciphertext = %v, want ErrDecryptionFailed", err)
	}
}

func TestDecrypt_WrongDEKFails(t *testing.T) {
	dekA, err := NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	dekB, err := NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	aad := []byte(`{"package_id":"pkg-1","segment":"a"}`)

	ciphertext, nonce, err := Encrypt(dekA, []byte("payload"), aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if _, err := Decrypt(dekB, nonce, ciphertext, aad); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("Decrypt with the wrong dek = %v, want ErrDecryptionFailed", err)
	}
}

func TestEncrypt_FreshNoncePerCall(t *testing.T) {
	dek, err := NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	plaintext := []byte("identical plaintext")
	aad := []byte(`{"package_id":"pkg-1","segment":"a"}`)

	ciphertext1, nonce1, err := Encrypt(dek, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ciphertext2, nonce2, err := Encrypt(dek, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if bytes.Equal(nonce1, nonce2) {
		t.Fatal("two Encrypt calls under the same DEK produced the same nonce")
	}
	if bytes.Equal(ciphertext1, ciphertext2) {
		t.Fatal("two Encrypt calls of identical plaintext under the same DEK produced identical ciphertexts")
	}
}
