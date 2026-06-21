package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// ErrEmptyEncryptionKey is returned when secret encryption/decryption is asked
// to use empty key material.
var ErrEmptyEncryptionKey = errors.New("auth: empty encryption key material")

// EncryptSecret encrypts plaintext with AES-256-GCM and returns the
// base64-encoded result (nonce || ciphertext || tag). The AES key is derived
// from keyMaterial via SHA-256, so any length of key material (e.g.
// SECRET_KEY_BASE) is accepted. Use it to store short restricted secrets — TOTP
// seeds and the like — encrypted at rest, so a database compromise alone does
// not reveal them.
//
// GCM provides authenticated encryption: DecryptSecret fails if the key is
// wrong or the ciphertext was modified.
func EncryptSecret(keyMaterial []byte, plaintext string) (string, error) {
	gcm, err := newGCM(keyMaterial)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("auth: generate nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// DecryptSecret reverses EncryptSecret. It returns an error when keyMaterial is
// empty, the input is not valid base64, the ciphertext is too short, or
// authentication fails (wrong key or tampered ciphertext).
func DecryptSecret(keyMaterial []byte, encoded string) (string, error) {
	gcm, err := newGCM(keyMaterial)
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("auth: decode ciphertext: %w", err)
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return "", errors.New("auth: ciphertext too short")
	}
	nonce, ct := raw[:ns], raw[ns:]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("auth: decrypt: %w", err)
	}
	return string(pt), nil
}

// newGCM derives a 256-bit AES key from keyMaterial (SHA-256) and returns a GCM
// AEAD. Empty key material is rejected.
func newGCM(keyMaterial []byte) (cipher.AEAD, error) {
	if len(keyMaterial) == 0 {
		return nil, ErrEmptyEncryptionKey
	}
	key := sha256.Sum256(keyMaterial)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("auth: new cipher: %w", err)
	}
	return cipher.NewGCM(block)
}
