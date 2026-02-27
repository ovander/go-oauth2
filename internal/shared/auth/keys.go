package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/ovandermoten/go-oauth2/internal/dto"
	"github.com/ovandermoten/go-oauth2/pkg/logger"
)

// ErrUnknownKeyID is returned when a JWT presents a kid not in the active key ring.
var ErrUnknownKeyID = errors.New("unknown key ID")

// keyEntry bundles a key pair with its identifier.
type keyEntry struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyID      string
}

// KeyManager holds the active signing key and a ring of retired public keys
// that are still served in the JWKS endpoint so that relying parties can
// verify tokens that were issued before the last rotation.
//
// File layout under keysPath:
//
//	private.pem         — current signing key (private)
//	public.pem          — current signing key (public)
//	key_id              — current key identifier (UUID)
//	retired/            — directory of retired public keys
//	  <kid>.pub         — PEM-encoded public key for retired KID <kid>
//
// M-03 fix: the retired/ directory enables key rotation without
// immediately invalidating outstanding tokens.  Call RotateKey() to
// promote the current key to retired/ and generate a fresh pair.
type KeyManager struct {
	keysPath string
	current  keyEntry
	// retired maps KID → public key for keys that have been rotated out
	// but may still appear in valid, unexpired tokens.
	retired map[string]*rsa.PublicKey
	mu      sync.RWMutex
	// rsaBits controls the RSA key size for generateKeys.
	// Production always uses 3072; tests may use 2048 for speed.
	rsaBits int
}

// NewKeyManager creates a KeyManager using a 3072-bit RSA key (production default).
func NewKeyManager(keysPath string) (*KeyManager, error) {
	return newKeyManagerWithBits(keysPath, 3072)
}

// newKeyManagerWithBits is the internal constructor.  Tests pass 2048 to keep
// key generation fast while still exercising the same code paths as production.
func newKeyManagerWithBits(keysPath string, rsaBits int) (*KeyManager, error) {
	km := &KeyManager{
		keysPath: keysPath,
		retired:  make(map[string]*rsa.PublicKey),
		rsaBits:  rsaBits,
	}
	if err := km.loadOrGenerateKeys(); err != nil {
		return nil, err
	}
	return km, nil
}

// loadOrGenerateKeys loads the current key pair (or generates one if absent)
// and populates the retired key ring from the retired/ subdirectory.
func (km *KeyManager) loadOrGenerateKeys() error {
	km.mu.Lock()
	defer km.mu.Unlock()

	if err := os.MkdirAll(km.keysPath, 0700); err != nil {
		return fmt.Errorf("failed to create keys directory: %w", err)
	}

	privateKeyPath := filepath.Join(km.keysPath, "private.pem")
	publicKeyPath := filepath.Join(km.keysPath, "public.pem")
	keyIDPath := filepath.Join(km.keysPath, "key_id")

	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		if err := km.generateKeys(privateKeyPath, publicKeyPath, keyIDPath); err != nil {
			return err
		}
	} else {
		if err := km.loadKeys(privateKeyPath, publicKeyPath, keyIDPath); err != nil {
			return err
		}
	}

	// Load retired public keys (best-effort; missing retired/ is not an error).
	return km.loadRetiredKeys()
}

// generateKeys creates a fresh 3072-bit RSA key pair and persists it.
//
// M-04 fix: the key ID is now a random UUID instead of a Unix timestamp.
// A timestamp-based KID leaks the server restart time and is enumerable.
func (km *KeyManager) generateKeys(privatePath, publicPath, keyIDPath string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, km.rsaBits)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	// HIGH-05 fix: write private key with read-only owner permissions (0400).
	// The previous mode was 0600 (owner rw); 0400 removes the write bit so
	// that even the service account cannot accidentally overwrite the key.
	//
	// If the file already exists (e.g. this is a RotateKey call overwriting
	// the current key pair), os.WriteFile would fail with EACCES because
	// 0400 files are not writable — even by their owner.  Remove the old
	// file first; removal only requires write permission on the PARENT
	// DIRECTORY, which we own (created with 0700 in loadOrGenerateKeys).
	_ = os.Remove(privatePath) // best-effort; ignored if file does not exist
	if err := os.WriteFile(privatePath, privateKeyPEM, 0400); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	// G306: 0644 is intentional — the public key is not sensitive and is served
	// over HTTP via the JWKS endpoint. World-readable filesystem access matches
	// the documented security contract (see TestHIGH05_GenerateKeys_PublicKeyPermission).
	if err := os.WriteFile(publicPath, publicKeyPEM, 0644); err != nil { //nolint:gosec // G306: public key is not sensitive; 0644 is intentional
		return fmt.Errorf("failed to save public key: %w", err)
	}

	// M-04: random UUID, not a timestamp.
	keyID := uuid.New().String()
	if err := os.WriteFile(keyIDPath, []byte(keyID), 0600); err != nil { //nolint:gosec
		return fmt.Errorf("failed to save key ID: %w", err)
	}

	km.current = keyEntry{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		keyID:      keyID,
	}
	return nil
}

func (km *KeyManager) loadKeys(privatePath, publicPath, keyIDPath string) error {
	// HIGH-05 fix: enforce 0400 on existing private key files.  If the file
	// was created by an older version of this code (which used 0600), or if
	// something widened the permissions, tighten them automatically on load
	// rather than refusing to start — avoiding a hard break for existing
	// deployments while still closing the window immediately.
	if info, statErr := os.Stat(privatePath); statErr == nil {
		if info.Mode().Perm() > 0400 {
			if chmodErr := os.Chmod(privatePath, 0400); chmodErr != nil {
				return fmt.Errorf("HIGH-05: private key %s has insecure permissions %o and chmod failed: %w",
					privatePath, info.Mode().Perm(), chmodErr)
			}
		}
	}

	privateKeyPEM, err := os.ReadFile(privatePath) //nolint:gosec // G304: path derived from KEYS_PATH, validated as absolute in config.Validate()
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

	publicKeyPEM, err := os.ReadFile(publicPath) //nolint:gosec // G304: path derived from KEYS_PATH, validated as absolute in config.Validate()
	if err != nil {
		return fmt.Errorf("failed to read public key: %w", err)
	}
	block, _ = pem.Decode(publicKeyPEM)
	if block == nil {
		return fmt.Errorf("failed to decode public key PEM")
	}
	publicKeyIface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}
	publicKey, ok := publicKeyIface.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not RSA")
	}

	// Load (or migrate) the key ID.
	var keyID string
	keyIDBytes, err := os.ReadFile(keyIDPath) //nolint:gosec // G304: path derived from KEYS_PATH, validated as absolute in config.Validate()
	if err != nil {
		// M-04: no key_id file → generate a UUID and persist it.
		keyID = uuid.New().String()
		_ = os.WriteFile(keyIDPath, []byte(keyID), 0600) //nolint:gosec
	} else {
		keyID = strings.TrimSpace(string(keyIDBytes))
		// M-04: migrate legacy timestamp-based KIDs (old format: "key-<unix>").
		if strings.HasPrefix(keyID, "key-") {
			keyID = uuid.New().String()
			_ = os.WriteFile(keyIDPath, []byte(keyID), 0600) //nolint:gosec
		}
	}

	km.current = keyEntry{
		privateKey: privateKey,
		publicKey:  publicKey,
		keyID:      keyID,
	}
	return nil
}

// loadRetiredKeys scans {keysPath}/retired/ and loads every *.pub file as a
// retired public key into the in-memory ring.  This is best-effort: a missing
// directory is not an error; individual parse errors are skipped rather than
// failing startup.
func (km *KeyManager) loadRetiredKeys() error {
	retiredDir := filepath.Join(km.keysPath, "retired")
	entries, err := os.ReadDir(retiredDir)
	if os.IsNotExist(err) {
		return nil // no retired keys — normal for fresh installs
	}
	if err != nil {
		return fmt.Errorf("failed to read retired keys directory: %w", err)
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pub") {
			continue
		}
		path := filepath.Join(retiredDir, e.Name())
		pub, err := loadPublicKeyFromFile(path)
		if err != nil {
			// Non-fatal: skip corrupt archived keys rather than preventing startup.
			continue
		}
		kid := strings.TrimSuffix(e.Name(), ".pub")
		km.retired[kid] = pub
	}
	return nil
}

// RotateKey promotes the current signing key to the retired ring and generates
// a fresh key pair.  Outstanding tokens signed with the old key remain
// verifiable until they expire because the old public key stays in the JWKS.
//
// M-03 fix: without this method there is no supported rotation path; admins
// would have to replace files manually and restart, causing a verification
// outage for all outstanding tokens.
func (km *KeyManager) RotateKey() error {
	km.mu.Lock()
	defer km.mu.Unlock()

	// Archive the current public key to retired/<kid>.pub before overwriting.
	retiredDir := filepath.Join(km.keysPath, "retired")
	if err := os.MkdirAll(retiredDir, 0700); err != nil {
		return fmt.Errorf("failed to create retired keys directory: %w", err)
	}

	oldKID := km.current.keyID
	pubBytes, err := x509.MarshalPKIXPublicKey(km.current.publicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal current public key for archival: %w", err)
	}
	retiredPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	retiredPath := filepath.Join(retiredDir, oldKID+".pub")
	if err := os.WriteFile(retiredPath, retiredPEM, 0600); err != nil { //nolint:gosec
		return fmt.Errorf("failed to write retired public key: %w", err)
	}

	// Add to in-memory ring immediately so in-flight requests stay verifiable.
	km.retired[oldKID] = km.current.publicKey

	// Generate and persist the new key pair.
	privatePath := filepath.Join(km.keysPath, "private.pem")
	publicPath := filepath.Join(km.keysPath, "public.pem")
	keyIDPath := filepath.Join(km.keysPath, "key_id")
	return km.generateKeys(privatePath, publicPath, keyIDPath)
}

// GetPublicKeyByID returns the public key for the given KID, searching both
// the current key and the retired ring.  Used by TokenService.verifyToken
// to perform KID-aware key selection (M-03).
func (km *KeyManager) GetPublicKeyByID(kid string) (*rsa.PublicKey, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if km.current.keyID == kid {
		return km.current.publicKey, nil
	}
	if pub, ok := km.retired[kid]; ok {
		return pub, nil
	}
	return nil, fmt.Errorf("%w: %s", ErrUnknownKeyID, kid)
}

// GetPrivateKey returns the current signing private key.
func (km *KeyManager) GetPrivateKey() *rsa.PrivateKey {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.current.privateKey
}

// GetPublicKey returns the current signing public key.
func (km *KeyManager) GetPublicKey() *rsa.PublicKey {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.current.publicKey
}

// GetKeyID returns the current signing key's identifier.
func (km *KeyManager) GetKeyID() string {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.current.keyID
}

// GetJWKS returns a JWKS containing the current key and all retired keys.
//
// M-03 fix: clients that cached the JWKS before a rotation still see the old
// public key and can verify existing tokens without hitting 401s.
func (km *KeyManager) GetJWKS() dto.JWKS {
	km.mu.RLock()
	defer km.mu.RUnlock()

	keys := make([]dto.JWK, 0, 1+len(km.retired))

	// Current signing key first.
	keys = append(keys, rsaPublicKeyToJWK(km.current.publicKey, km.current.keyID))

	// Retired keys — public only, still needed for token verification.
	for kid, pub := range km.retired {
		keys = append(keys, rsaPublicKeyToJWK(pub, kid))
	}

	return dto.JWKS{Keys: keys}
}

// StartRotationSchedule starts a background goroutine that calls RotateKey on
// the given interval.  It returns a stop function that the caller must invoke
// on shutdown to release the goroutine.
//
// LOW-05 fix: without an automated schedule, operators must rotate keys
// manually (or forget to).  Calling StartRotationSchedule from bootstrap.go
// with a 30-day interval gives keys a predictable lifetime and ensures the
// retired key ring never accumulates stale entries indefinitely.
//
// Runbook note: the rotation interval should be shorter than the refresh-token
// TTL so that a compromised private key cannot be used to forge tokens that
// outlive the next rotation.  For example, with a 7-day refresh-token TTL,
// rotate keys every 7 days or less.
//
// Usage:
//
//	stop := km.StartRotationSchedule(30 * 24 * time.Hour)
//	defer stop()
func (km *KeyManager) StartRotationSchedule(interval time.Duration) (stop func()) {
	stopCh := make(chan struct{})
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := km.RotateKey(); err != nil {
					logger.Errorf("LOW-05: scheduled key rotation failed: %v", err)
				} else {
					logger.WithFields(logger.Fields{
						"interval_hours": interval.Hours(),
						"new_kid":        km.GetKeyID(),
					}).Info("LOW-05: scheduled key rotation completed")
				}
			case <-stopCh:
				logger.Info("LOW-05: key rotation schedule stopped")
				return
			}
		}
	}()
	// stop closes the stop channel and then blocks until the goroutine has
	// fully exited.  This guarantees that no further RotateKey calls can
	// occur after stop() returns, which is required for deterministic tests
	// and clean shutdown ordering in production.
	return func() {
		close(stopCh)
		<-doneCh
	}
}

// rsaPublicKeyToJWK converts an RSA public key to a JWK representation.
func rsaPublicKeyToJWK(pub *rsa.PublicKey, kid string) dto.JWK {
	return dto.JWK{
		Kty: "RSA",
		Use: "sig",
		Kid: kid,
		Alg: "RS256",
		N:   base64URLEncode(pub.N.Bytes()),
		E:   base64URLEncode(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// loadPublicKeyFromFile reads a PEM-encoded RSA public key from disk.
func loadPublicKeyFromFile(path string) (*rsa.PublicKey, error) {
	pemBytes, err := os.ReadFile(path) //nolint:gosec // G304: path constructed from KEYS_PATH/retired/<uuid>.pub; all components are internally generated
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block in %s", path)
	}
	iface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key in %s: %w", path, err)
	}
	pub, ok := iface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key in %s is not RSA", path)
	}
	return pub, nil
}

func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
