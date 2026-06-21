package auth

import (
	"encoding/base64"
	"errors"
	"testing"
)

var encKey = []byte("secret-key-base-at-least-32-bytes-long!!")

func TestSecretCrypto_RoundTrip(t *testing.T) {
	t.Parallel()
	plain := "JBSWY3DPEHPK3PXP" // a TOTP-shaped secret
	enc, err := EncryptSecret(encKey, plain)
	if err != nil {
		t.Fatalf("EncryptSecret: %v", err)
	}
	if enc == plain {
		t.Fatal("ciphertext equals plaintext")
	}
	got, err := DecryptSecret(encKey, enc)
	if err != nil {
		t.Fatalf("DecryptSecret: %v", err)
	}
	if got != plain {
		t.Errorf("round trip = %q, want %q", got, plain)
	}
}

func TestSecretCrypto_WrongKeyFails(t *testing.T) {
	t.Parallel()
	enc, _ := EncryptSecret(encKey, "topsecret")
	if _, err := DecryptSecret([]byte("a-different-key-also-32-bytes-long!!!"), enc); err == nil {
		t.Fatal("expected decryption with a wrong key to fail")
	}
}

func TestSecretCrypto_TamperFails(t *testing.T) {
	t.Parallel()
	enc, _ := EncryptSecret(encKey, "topsecret")
	raw, _ := base64.StdEncoding.DecodeString(enc)
	raw[len(raw)-1] ^= 0x01 // flip a bit in the tag
	tampered := base64.StdEncoding.EncodeToString(raw)
	if _, err := DecryptSecret(encKey, tampered); err == nil {
		t.Fatal("expected decryption of a tampered ciphertext to fail")
	}
}

func TestSecretCrypto_RandomNonce(t *testing.T) {
	t.Parallel()
	a, _ := EncryptSecret(encKey, "same")
	b, _ := EncryptSecret(encKey, "same")
	if a == b {
		t.Error("encrypting the same plaintext twice produced identical ciphertext (nonce reuse?)")
	}
}

func TestSecretCrypto_EmptyKeyRejected(t *testing.T) {
	t.Parallel()
	if _, err := EncryptSecret(nil, "x"); !errors.Is(err, ErrEmptyEncryptionKey) {
		t.Errorf("EncryptSecret(nil) err = %v, want ErrEmptyEncryptionKey", err)
	}
	if _, err := DecryptSecret([]byte{}, "x"); !errors.Is(err, ErrEmptyEncryptionKey) {
		t.Errorf("DecryptSecret(empty) err = %v, want ErrEmptyEncryptionKey", err)
	}
}

func TestSecretCrypto_BadBase64(t *testing.T) {
	t.Parallel()
	if _, err := DecryptSecret(encKey, "not valid base64 !!!"); err == nil {
		t.Fatal("expected error decoding invalid base64")
	}
}
