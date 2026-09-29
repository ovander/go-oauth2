package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
	"github.com/ovander/go-oauth2/pkg/logger"
)

// CodeStoreConfig holds configuration for the code store
type CodeStoreConfig struct {
	TTL             time.Duration
	CleanupInterval time.Duration
}

// DefaultCodeStoreConfig returns default configuration
func DefaultCodeStoreConfig() CodeStoreConfig {
	return CodeStoreConfig{
		TTL:             10 * time.Minute,
		CleanupInterval: time.Minute,
	}
}

// CodeStore manages authorization codes with database backing
type CodeStore struct {
	repo            repository.AuthorizationCodeRepository
	ttl             time.Duration
	cleanupInterval time.Duration
	stopCh          chan struct{}
	wg              sync.WaitGroup
}

// NewCodeStore creates a new database-backed code store
func NewCodeStore(repo repository.AuthorizationCodeRepository, config CodeStoreConfig) *CodeStore {
	if config.TTL == 0 {
		config.TTL = 10 * time.Minute
	}
	if config.CleanupInterval == 0 {
		config.CleanupInterval = time.Minute
	}

	cs := &CodeStore{
		repo:            repo,
		ttl:             config.TTL,
		cleanupInterval: config.CleanupInterval,
		stopCh:          make(chan struct{}),
	}

	// Start cleanup goroutine
	cs.wg.Add(1)
	go cs.cleanup()

	return cs
}

// NewCodeStoreWithTTL creates a new code store with specified TTL (backwards compatible)
func NewCodeStoreWithTTL(repo repository.AuthorizationCodeRepository, ttl time.Duration) *CodeStore {
	return NewCodeStore(repo, CodeStoreConfig{
		TTL:             ttl,
		CleanupInterval: time.Minute,
	})
}

// GenerateCode generates and stores a new authorization code
func (cs *CodeStore) GenerateCode(ctx context.Context, userID, appID uint, clientID, redirectURI, scope, nonce, codeChallenge, codeChallengeMethod, role string, appRoles map[string]string) (string, error) {
	// Generate cryptographically secure random code
	codeBytes := make([]byte, 32)
	if _, err := rand.Read(codeBytes); err != nil {
		return "", fmt.Errorf("failed to generate random code: %w", err)
	}
	code := base64.RawURLEncoding.EncodeToString(codeBytes)

	now := time.Now()
	authCode := &model.AuthorizationCode{
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
		Used:                false,
		ExpiresAt:           now.Add(cs.ttl),
		CreatedAt:           now,
	}

	if err := cs.repo.Create(ctx, authCode); err != nil {
		return "", fmt.Errorf("failed to store authorization code: %w", err)
	}

	return code, nil
}

// RedeemCode retrieves and marks an authorization code as used atomically
// Returns nil if code doesn't exist, is expired, or already used
func (cs *CodeStore) RedeemCode(ctx context.Context, code string) (*model.AuthorizationCode, error) {
	authCode, err := cs.repo.FindByCode(ctx, code)
	if err != nil {
		return nil, nil // Code not found
	}

	// Check if expired
	if authCode.IsExpired() {
		// Clean up expired code
		_ = cs.repo.Delete(ctx, code)
		return nil, nil
	}

	// Check if already used (replay attack prevention)
	if authCode.Used {
		// Delete to prevent further attempts
		_ = cs.repo.Delete(ctx, code)
		return nil, nil
	}

	// Mark as used atomically
	if err := cs.repo.MarkAsUsed(ctx, code); err != nil {
		// Another request might have used it first
		return nil, nil
	}

	return authCode, nil
}

// GetCode retrieves a code without marking it as used (for validation only)
func (cs *CodeStore) GetCode(ctx context.Context, code string) (*model.AuthorizationCode, error) {
	authCode, err := cs.repo.FindByCode(ctx, code)
	if err != nil {
		return nil, err
	}

	// Check if expired
	if authCode.IsExpired() {
		return nil, nil
	}

	return authCode, nil
}

// DeleteCode removes a code from the store
func (cs *CodeStore) DeleteCode(ctx context.Context, code string) error {
	return cs.repo.Delete(ctx, code)
}

// RevokeUserCodes revokes all codes for a user (used during logout/token revocation)
func (cs *CodeStore) RevokeUserCodes(ctx context.Context, userID uint) error {
	return cs.repo.DeleteByUserID(ctx, userID)
}

// Stop gracefully stops the cleanup goroutine
func (cs *CodeStore) Stop() {
	close(cs.stopCh)
	cs.wg.Wait()
}

// cleanup periodically removes expired codes
func (cs *CodeStore) cleanup() {
	defer cs.wg.Done()

	ticker := time.NewTicker(cs.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-cs.stopCh:
			// NEW-01 fix: use structured logger so cleanup events appear in
			// production log aggregation systems alongside other service logs.
			logger.Info("code store: cleanup goroutine stopped")
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			deleted, err := cs.repo.DeleteExpired(ctx)
			cancel()

			if err != nil {
				logger.Errorf("code store: cleanup failed to delete expired authorization codes: %v", err)
			} else if deleted > 0 {
				logger.Infof("code store: cleanup deleted %d expired authorization codes", deleted)
			}
		}
	}
}
