package local

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func TestSign_VerifyRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	s, err := New(priv, "issuer-key-1")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	message := []byte(`{"package_id":"pkg_test_0001"}`)
	sig, err := s.Sign(context.Background(), message)
	kid, kidErr := s.Kid(context.Background())
	if kidErr != nil {
		t.Fatalf("Kid: %v", kidErr)
	}
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if kid != "issuer-key-1" {
		t.Fatalf("Sign kid = %q, want %q", kid, "issuer-key-1")
	}
	if !Verify(pub, message, sig) {
		t.Fatalf("Verify(pub, message, sig) = false, want true")
	}
}

func TestVerify_FailsOnFlippedMessageByte(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	s, err := New(priv, "issuer-key-1")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	message := []byte(`{"package_id":"pkg_test_0001"}`)
	sig, err := s.Sign(context.Background(), message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	tampered := append([]byte(nil), message...)
	tampered[0] ^= 0xFF
	if Verify(pub, tampered, sig) {
		t.Fatalf("Verify accepted a signature over a message with a flipped byte")
	}
}

func TestVerify_FailsOnWrongPublicKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	wrongPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey (wrong key): %v", err)
	}
	s, err := New(priv, "issuer-key-1")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	message := []byte(`{"package_id":"pkg_test_0001"}`)
	sig, err := s.Sign(context.Background(), message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if Verify(wrongPub, message, sig) {
		t.Fatalf("Verify accepted a signature under the wrong public key")
	}
}

func TestNew_RejectsWrongKeySize(t *testing.T) {
	tests := []struct {
		name string
		priv ed25519.PrivateKey
	}{
		{"empty", nil},
		{"too short", make(ed25519.PrivateKey, ed25519.PrivateKeySize-1)},
		{"too long", make(ed25519.PrivateKey, ed25519.PrivateKeySize+1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.priv, "issuer-key-1")
			if err == nil {
				t.Fatalf("New with %s key: got nil error, want one", tt.name)
			}
			if !errors.Is(err, ErrKeySize) {
				t.Fatalf("New error = %v, want errors.Is ErrKeySize", err)
			}
		})
	}
}

func TestSign_RespectsCanceledContext(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	s, err := New(priv, "issuer-key-1")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = s.Sign(ctx, []byte("message"))
	if err == nil {
		t.Fatalf("Sign with a canceled context: got nil error, want one")
	}
}

// TestVerify_MalformedKeyOrSignature_ReturnsFalse_DoesNotPanic guards the
// verification path against a denial of service. crypto/ed25519.Verify
// panics on a wrong-size public key, and the issuer key is resolved from
// fields carried inside the package being verified — attacker-controlled
// by definition. A test with a wrong key of the *right size* does not
// reach this; that is why one existed and this bug survived it.
func TestVerify_MalformedKeyOrSignature_ReturnsFalse_DoesNotPanic(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	message := []byte("chainbind signing view")
	good := ed25519.Sign(priv, message)

	tests := []struct {
		name string
		pub  ed25519.PublicKey
		sig  []byte
	}{
		{"public key too short", make([]byte, 10), good},
		{"public key too long", make([]byte, ed25519.PublicKeySize+1), good},
		{"public key empty", ed25519.PublicKey{}, good},
		{"public key nil", nil, good},
		{"signature too short", pub, good[:10]},
		{"signature too long", pub, append(append([]byte{}, good...), 0x00)},
		{"signature nil", pub, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Verify panicked on malformed input: %v", r)
				}
			}()
			if Verify(tt.pub, message, tt.sig) {
				t.Fatal("Verify returned true for malformed input")
			}
		})
	}
}

// TestKid_DoesNotSign is the point of separating Kid from Sign: Seal needs
// the kid before it can build the view that commits to it, and a Signer must
// never be asked to sign anything but the thing being signed. A signer whose
// only way to reveal its kid is to sign a probe message is a signing oracle,
// and against Vault Transit it is also an extra network call and an extra
// audit entry on every seal.
func TestKid_DoesNotSign(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	s, err := New(priv, "issuer-signing-key-1:v1")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	kid, err := s.Kid(context.Background())
	if err != nil {
		t.Fatalf("Kid: %v", err)
	}
	if kid != "issuer-signing-key-1:v1" {
		t.Fatalf("Kid = %q, want the configured kid", kid)
	}

	// Kid is stable and side-effect free: calling it twice, and calling it
	// before Sign, changes nothing about what Sign produces.
	again, err := s.Kid(context.Background())
	if err != nil || again != kid {
		t.Fatalf("Kid not stable: %q, %v", again, err)
	}

	message := []byte("the only bytes this key ever signs")
	sig, err := s.Sign(context.Background(), message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !Verify(pub, message, sig) {
		t.Fatal("signature over the real message does not verify")
	}
}
