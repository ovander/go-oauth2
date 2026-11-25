package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
	"github.com/ovander/go-oauth2/pkg/logger"
)

// CodeStoreConfig holds configuration for the code store
type CodeStoreConfig struct {
	TTL             time.Duration
	CleanupInterval time.Duration
	// ReplayRetention keeps a redeemed code this long after its redemption
	// (when longer than its TTL), so that a replay is still recognised while
	// the tokens it was redeemed for may be valid (CODE_REPLAY_MODE). Zero
	// removes a used code at its expiry, as before.
	ReplayRetention time.Duration
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
	replayRetention time.Duration
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
		replayRetention: config.ReplayRetention,
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
	return cs.GenerateCodeWithAuthn(ctx, userID, appID, clientID, redirectURI, scope, nonce, codeChallenge, codeChallengeMethod, role, appRoles, AuthnEvidence{})
}

// GenerateCodeWithAuthn is GenerateCode that also stores the end-user
// authentication evidence behind the code, so the tokens it is redeemed for
// carry the real auth_time, amr and acr.
func (cs *CodeStore) GenerateCodeWithAuthn(ctx context.Context, userID, appID uint, clientID, redirectURI, scope, nonce, codeChallenge, codeChallengeMethod, role string, appRoles map[string]string, authn AuthnEvidence) (string, error) {
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
		AuthTime:            authn.AuthTime,
		AMR:                 model.StringArray(authn.AMR),
		ACR:                 authn.ACR,
		Used:                false,
		ExpiresAt:           now.Add(cs.ttl),
		CreatedAt:           now,
	}

	if err := cs.repo.Create(ctx, authCode); err != nil {
		return "", fmt.Errorf("failed to store authorization code: %w", err)
	}

	return code, nil
}

// ErrCodeReplayed is returned by RedeemCode, with the code as it was
// redeemed, when the code was already used: a replay (RFC 6749 §4.1.2).
var ErrCodeReplayed = errors.New("authorization code already redeemed")

// RedeemCode retrieves and marks an authorization code as used atomically.
// It returns nil, nil when the code does not exist or is expired. A code
// already used is a replay: RedeemCode returns it with ErrCodeReplayed, its
// TokenFamily and AccessJTI saying what it was redeemed for, and leaves it
// stored: the caller deletes it (DeleteCode) once the replay is handled, so
// that a replay it does not trust cannot erase the evidence. A code redeemed
// now gets a new TokenFamily and AccessJTI, recorded with the redemption
// itself when the repository supports it, for the caller to mint the tokens
// with.
func (cs *CodeStore) RedeemCode(ctx context.Context, code string) (*model.AuthorizationCode, error) {
	authCode, err := cs.repo.FindByCode(ctx, code)
	if err != nil {
		return nil, nil // Code not found
	}

	// A used code is a replay whether or not it has expired since: the
	// tokens it was redeemed for may still be valid.
	if authCode.Used {
		return authCode, ErrCodeReplayed
	}

	// Check if expired
	if authCode.IsExpired() {
		// Clean up expired code
		_ = cs.repo.Delete(ctx, code)
		return nil, nil
	}

	// Mark as used atomically, with the tokens it is redeemed for.
	family, accessJTI := uuid.New().String(), uuid.New().String()
	if r, ok := cs.repo.(repository.AuthorizationCodeRedeemer); ok {
		var keepUntil time.Time
		if cs.replayRetention > 0 {
			keepUntil = time.Now().Add(cs.replayRetention)
		}
		err = r.MarkAsUsedWithTokens(ctx, code, family, accessJTI, keepUntil)
	} else {
		err = cs.repo.MarkAsUsed(ctx, code)
	}
	if err != nil {
		// Another request redeemed it between the read and the update: this
		// one is a replay of a code redeemed a moment ago.
		if again, ferr := cs.repo.FindByCode(ctx, code); ferr == nil && again != nil && again.Used {
			return again, ErrCodeReplayed
		}
		return nil, nil
	}
	authCode.Used, authCode.TokenFamily, authCode.AccessJTI = true, family, accessJTI

	return authCode, nil
}

// KeepFamilyCode extends, by the replay retention, how long the redeemed code
// of a refresh-token family is kept: a refresh rotation calls it, so that the
// code stays recognisable as long as its family can be refreshed. It does
// nothing without a replay retention or a repository that supports it.
func (cs *CodeStore) KeepFamilyCode(ctx context.Context, tokenFamily string) error {
	r, ok := cs.repo.(repository.AuthorizationCodeFamilyRetainer)
	if cs.replayRetention <= 0 || tokenFamily == "" || !ok {
		return nil
	}
	return r.KeepFamilyUntil(ctx, tokenFamily, time.Now().Add(cs.replayRetention))
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
