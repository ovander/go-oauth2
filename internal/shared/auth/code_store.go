package auth

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// AuthorizationCode represents a stored authorization code
type AuthorizationCode struct {
	Code                string
	UserID              uint
	AppID               uint
	ClientID            string
	RedirectURI         string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Role                string
	AppRoles            map[string]string
	CreatedAt           time.Time
	ExpiresAt           time.Time
	Used                bool
}

// CodeStore manages authorization codes in memory
type CodeStore struct {
	codes map[string]*AuthorizationCode
	mu    sync.RWMutex
	ttl   time.Duration
}

// NewCodeStore creates a new code store with the specified TTL
func NewCodeStore(ttl time.Duration) *CodeStore {
	cs := &CodeStore{
		codes: make(map[string]*AuthorizationCode),
		ttl:   ttl,
	}

	// Start cleanup goroutine
	go cs.cleanup()

	return cs
}

// GenerateCode generates a new authorization code
func (cs *CodeStore) GenerateCode(userID, appID uint, clientID, redirectURI, scope, nonce, codeChallenge, codeChallengeMethod, role string, appRoles map[string]string) (string, error) {
	// Generate random code
	codeBytes := make([]byte, 32)
	if _, err := rand.Read(codeBytes); err != nil {
		return "", err
	}
	code := base64.RawURLEncoding.EncodeToString(codeBytes)

	now := time.Now()
	authCode := &AuthorizationCode{
		Code:                code,
		UserID:              userID,
		AppID:               appID,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		Nonce:               nonce,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Role:                role,
		AppRoles:            appRoles,
		CreatedAt:           now,
		ExpiresAt:           now.Add(cs.ttl),
		Used:                false,
	}

	cs.mu.Lock()
	cs.codes[code] = authCode
	cs.mu.Unlock()

	return code, nil
}

// RedeemCode retrieves and marks an authorization code as used
// Returns nil if code doesn't exist, is expired, or already used
func (cs *CodeStore) RedeemCode(code string) *AuthorizationCode {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	authCode, exists := cs.codes[code]
	if !exists {
		return nil
	}

	// Check if expired
	if time.Now().After(authCode.ExpiresAt) {
		delete(cs.codes, code)
		return nil
	}

	// Check if already used
	if authCode.Used {
		// Delete the code to prevent replay attacks
		delete(cs.codes, code)
		return nil
	}

	// Mark as used
	authCode.Used = true

	return authCode
}

// GetCode retrieves a code without marking it as used (for validation)
func (cs *CodeStore) GetCode(code string) *AuthorizationCode {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	authCode, exists := cs.codes[code]
	if !exists {
		return nil
	}

	// Check if expired
	if time.Now().After(authCode.ExpiresAt) {
		return nil
	}

	return authCode
}

// DeleteCode removes a code from the store
func (cs *CodeStore) DeleteCode(code string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	delete(cs.codes, code)
}

// cleanup periodically removes expired codes
func (cs *CodeStore) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		cs.mu.Lock()
		now := time.Now()
		for code, authCode := range cs.codes {
			if now.After(authCode.ExpiresAt) {
				delete(cs.codes, code)
			}
		}
		cs.mu.Unlock()
	}
}
