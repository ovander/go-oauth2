package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/dto"
)

type KeyManager struct {
	keysPath   string
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyID      string
	mu         sync.RWMutex
}

func NewKeyManager(keysPath string) (*KeyManager, error) {
	km := &KeyManager{
		keysPath: keysPath,
	}

	if err := km.loadOrGenerateKeys(); err != nil {
		return nil, err
	}

	return km, nil
}

func (km *KeyManager) loadOrGenerateKeys() error {
	km.mu.Lock()
	defer km.mu.Unlock()

	// Create keys directory if not exists
	if err := os.MkdirAll(km.keysPath, 0700); err != nil {
		return fmt.Errorf("failed to create keys directory: %w", err)
	}

	privateKeyPath := filepath.Join(km.keysPath, "private.pem")
	publicKeyPath := filepath.Join(km.keysPath, "public.pem")
	keyIDPath := filepath.Join(km.keysPath, "key_id")

	// Check if keys exist
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		// Generate new keys
		return km.generateKeys(privateKeyPath, publicKeyPath, keyIDPath)
	}

	// Load existing keys
	return km.loadKeys(privateKeyPath, publicKeyPath, keyIDPath)
}

func (km *KeyManager) generateKeys(privatePath, publicPath, keyIDPath string) error {
	// Generate 3072-bit RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Save private key
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	if err := os.WriteFile(privatePath, privateKeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	// Save public key
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	if err := os.WriteFile(publicPath, publicKeyPEM, 0644); err != nil {
		return fmt.Errorf("failed to save public key: %w", err)
	}

	// Generate and save key ID
	keyID := fmt.Sprintf("key-%d", time.Now().Unix())
	if err := os.WriteFile(keyIDPath, []byte(keyID), 0644); err != nil {
		return fmt.Errorf("failed to save key ID: %w", err)
	}

	km.privateKey = privateKey
	km.publicKey = &privateKey.PublicKey
	km.keyID = keyID

	return nil
}

func (km *KeyManager) loadKeys(privatePath, publicPath, keyIDPath string) error {
	// Load private key
	privateKeyPEM, err := os.ReadFile(privatePath)
	if err != nil {
		return fmt.Errorf("failed to read private key: %w", err)
	}

	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return fmt.Errorf("failed to decode private key PEM")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	// Load public key
	publicKeyPEM, err := os.ReadFile(publicPath)
	if err != nil {
		return fmt.Errorf("failed to read public key: %w", err)
	}

	block, _ = pem.Decode(publicKeyPEM)
	if block == nil {
		return fmt.Errorf("failed to decode public key PEM")
	}

	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	publicKey, ok := publicKeyInterface.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not RSA")
	}

	// Load key ID
	keyIDBytes, err := os.ReadFile(keyIDPath)
	if err != nil {
		// Generate new key ID if not exists
		km.keyID = fmt.Sprintf("key-%d", time.Now().Unix())
		os.WriteFile(keyIDPath, []byte(km.keyID), 0644)
	} else {
		km.keyID = string(keyIDBytes)
	}

	km.privateKey = privateKey
	km.publicKey = publicKey

	return nil
}

func (km *KeyManager) GetPrivateKey() *rsa.PrivateKey {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.privateKey
}

func (km *KeyManager) GetPublicKey() *rsa.PublicKey {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.publicKey
}

func (km *KeyManager) GetKeyID() string {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.keyID
}

func (km *KeyManager) GetJWKS() dto.JWKS {
	km.mu.RLock()
	defer km.mu.RUnlock()

	return dto.JWKS{
		Keys: []dto.JWK{
			{
				Kty: "RSA",
				Use: "sig",
				Kid: km.keyID,
				Alg: "RS256",
				N:   base64URLEncode(km.publicKey.N.Bytes()),
				E:   base64URLEncode(big.NewInt(int64(km.publicKey.E)).Bytes()),
			},
		},
	}
}

func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
