package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/ovandermoten/go-oauth2/internal/contextkeys"
	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/repository"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth"
)

// AuthRejectReason classifies why AuthMiddleware rejected a *present* bearer
// token, so the audit sink can map it to the right token-abuse security event.
type AuthRejectReason string

const (
	// AuthRejectInvalid: the token is malformed, has a bad signature, names an
	// unknown user, or is otherwise unverifiable — a forgery / probing signal.
	AuthRejectInvalid AuthRejectReason = "invalid"
	// AuthRejectExpired: the token verified but is past its exp. Usually normal
	// client behaviour (refresh-then-retry), so the wired sink does not record it.
	AuthRejectExpired AuthRejectReason = "expired"
	// AuthRejectRevoked: the token was invalidated by nuclear (token-version) or
	// per-JTI revocation but is still being presented — a stolen/stale-credential
	// replay signal.
	AuthRejectRevoked AuthRejectReason = "revoked"
)

// AuthRejectFunc is invoked when AuthMiddleware rejects a *present* bearer token,
// letting the caller record a token-abuse security event. It is never called
// when the Authorization header is simply absent — an unauthenticated probe is
// not a token-abuse signal and would only add noise.
type AuthRejectFunc func(r *http.Request, reason AuthRejectReason, detail string)

// isRevoked reports whether the token's JTI has been individually revoked via
// /oauth/revoke (the JTI is blacklisted in used_tokens). Nil repo or an empty
// JTI means "not revoked"; a repo error fails open (returns false) so a
// transient store outage never locks out otherwise-valid tokens — consistent
// with Introspect's best-effort blacklist check. EPIC-14 / RFC-012: this is
// what propagates a per-token revocation to the direct-auth hot path, not just
// to introspection.
func isRevoked(ctx context.Context, usedTokenRepo repository.UsedTokenRepository, jti string) bool {
	if usedTokenRepo == nil || jti == "" {
		return false
	}
	revoked, err := usedTokenRepo.IsUsed(ctx, jti)
	return err == nil && revoked
}

// UserTokenError says why a user access token was refused. Reason is empty
// when the refusal is not a token-abuse signal (a locked account).
type UserTokenError struct {
	Reason  AuthRejectReason
	Detail  string
	Message string
	Status  int
}

func (e *UserTokenError) Error() string { return e.Message }

// UserTokenLocked is the Detail of the error for a valid token whose account
// is locked.
const UserTokenLocked = "account_locked"

// VerifyUserToken runs every check AuthMiddleware applies to a user access
// token — signature and expiry, a numeric user subject, the user's existence,
// nuclear revocation (token_version), per-token revocation (jti) and account
// lock — and returns the user and claims. It is the single implementation of
// those checks, shared by AuthMiddleware and by anything else that accepts a
// user's token on their behalf (the A4 decide endpoint).
//
// On error the user and claims are nil — except for a locked account (Detail
// UserTokenLocked), where the token is valid and both are returned with the
// error. A caller must never treat a non-nil user as success.
func VerifyUserToken(ctx context.Context, tokenService *auth.TokenService, userRepo repository.UserRepository, usedTokenRepo repository.UsedTokenRepository, tokenString string) (*model.User, *auth.AccessTokenClaims, *UserTokenError) {
	claims, err := tokenService.VerifyAccessToken(tokenString)
	if err != nil {
		if errors.Is(err, auth.ErrTokenExpired) {
			return nil, nil, &UserTokenError{Reason: AuthRejectExpired, Detail: "token_expired", Message: "invalid or expired token", Status: http.StatusUnauthorized}
		}
		return nil, nil, &UserTokenError{Reason: AuthRejectInvalid, Detail: "verify_failed", Message: "invalid or expired token", Status: http.StatusUnauthorized}
	}

	userID, err := strconv.ParseUint(claims.Subject, 10, 64)
	if err != nil {
		return nil, nil, &UserTokenError{Reason: AuthRejectInvalid, Detail: "bad_subject_claim", Message: "invalid token claims", Status: http.StatusUnauthorized}
	}

	user, err := userRepo.FindByID(ctx, uint(userID))
	if err != nil {
		return nil, nil, &UserTokenError{Reason: AuthRejectInvalid, Detail: "user_not_found", Message: "user not found", Status: http.StatusUnauthorized}
	}

	// CRITICAL: Verify token version to support token revocation
	// If the user's token version has been incremented (via logout, password reset, etc.),
	// all previously issued tokens become invalid.
	//
	// FIND-01 fix: the previous guard `claims.TokenVersion > 0 &&` created a
	// bypass for tokens minted when TokenVersion was 0 (every new user before
	// their first nuclear revocation event).  After IncrementTokenVersion bumps
	// the DB row to 1, old tokens with TokenVersion=0 passed the "> 0" guard
	// as false and the check was silently skipped — the attacker remained
	// authenticated despite the revocation.
	//
	// The correct comparison is user.TokenVersion > claims.TokenVersion, which
	// matches the Introspect implementation (NEW-03 fix) and correctly catches
	// the 0→1, 1→2, and any N→N+k transitions.
	if user.TokenVersion > claims.TokenVersion {
		return nil, nil, &UserTokenError{Reason: AuthRejectRevoked, Detail: "token_version_superseded", Message: "token has been revoked", Status: http.StatusUnauthorized}
	}

	// EPIC-14: reject a token whose JTI was individually revoked via
	// /oauth/revoke, so per-token revocation propagates to this hot path
	// (previously only Introspect honored the blacklist).
	if isRevoked(ctx, usedTokenRepo, claims.ID) {
		return nil, nil, &UserTokenError{Reason: AuthRejectRevoked, Detail: "jti_revoked", Message: "token has been revoked", Status: http.StatusUnauthorized}
	}

	// Check if user account is locked
	if user.IsLocked() {
		// The token itself is good, so the user and claims come back with
		// the error: a caller deciding on the user's behalf still needs to
		// know who is locked.
		return user, claims, &UserTokenError{Detail: UserTokenLocked, Message: "account is locked", Status: http.StatusForbidden}
	}
	return user, claims, nil
}

// AuthMiddleware validates JWT tokens, verifies token version + revocation, and
// adds user info to context.
//
// An optional onReject hook is invoked whenever a *present* bearer token is
// rejected, classified as invalid / expired / revoked, so the caller can emit a
// token-abuse security event. A request with no Authorization header never fires
// the hook (an unauthenticated probe is not a token-abuse signal).
func AuthMiddleware(tokenService *auth.TokenService, userRepo repository.UserRepository, usedTokenRepo repository.UsedTokenRepository, onReject ...AuthRejectFunc) func(http.Handler) http.Handler {
	var reject AuthRejectFunc
	if len(onReject) > 0 {
		reject = onReject[0]
	}
	fire := func(r *http.Request, reason AuthRejectReason, detail string) {
		if reject != nil {
			reject(r, reason, detail)
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				// Absent credential — not a token-abuse signal; do not audit.
				writeAuthError(w, "authorization header required", http.StatusUnauthorized)
				return
			}

			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			if tokenString == authHeader {
				fire(r, AuthRejectInvalid, "malformed_authorization_header")
				writeAuthError(w, "invalid authorization header format", http.StatusUnauthorized)
				return
			}

			user, claims, terr := VerifyUserToken(r.Context(), tokenService, userRepo, usedTokenRepo, tokenString)
			if terr != nil {
				if terr.Reason != "" {
					fire(r, terr.Reason, terr.Detail)
				}
				writeAuthError(w, terr.Message, terr.Status)
				return
			}

			// Add user info to context
			ctx := context.WithValue(r.Context(), contextkeys.UserIDKey, user.ID)
			ctx = context.WithValue(ctx, contextkeys.UserRoleKey, string(user.Role))
			ctx = context.WithValue(ctx, contextkeys.CurrentUserKey, user)
			ctx = context.WithValue(ctx, contextkeys.JWTClaimsKey, claims)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// OptionalAuthMiddleware extracts user info if token present, but doesn't require it
func OptionalAuthMiddleware(tokenService *auth.TokenService, userRepo repository.UserRepository, usedTokenRepo repository.UsedTokenRepository) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				next.ServeHTTP(w, r)
				return
			}

			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			if tokenString == authHeader {
				next.ServeHTTP(w, r)
				return
			}

			claims, err := tokenService.VerifyAccessToken(tokenString)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			userID, err := strconv.ParseUint(claims.Subject, 10, 64)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			user, err := userRepo.FindByID(r.Context(), uint(userID))
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			// Verify token version — silently treat the request as unauthenticated
			// when the token has been revoked via nuclear revocation.
			//
			// FIND-01 fix: same correction as AuthMiddleware above.  The "> 0"
			// guard on claims.TokenVersion meant tokens minted when TokenVersion
			// was 0 were never rejected here, defeating nuclear revocation on the
			// OptionalAuth paths (e.g. POST /oauth/revoke Path 1 classification).
			if user.TokenVersion > claims.TokenVersion {
				next.ServeHTTP(w, r)
				return
			}

			// EPIC-14: a per-token-revoked token is treated as unauthenticated.
			if isRevoked(r.Context(), usedTokenRepo, claims.ID) {
				next.ServeHTTP(w, r)
				return
			}

			// Skip if user is locked
			if user.IsLocked() {
				next.ServeHTTP(w, r)
				return
			}

			ctx := context.WithValue(r.Context(), contextkeys.UserIDKey, user.ID)
			ctx = context.WithValue(ctx, contextkeys.UserRoleKey, string(user.Role))
			ctx = context.WithValue(ctx, contextkeys.CurrentUserKey, user)
			ctx = context.WithValue(ctx, contextkeys.JWTClaimsKey, claims)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetUserIDFromContext extracts the user ID from the request context
func GetUserIDFromContext(ctx context.Context) (uint, bool) {
	userID, ok := ctx.Value(contextkeys.UserIDKey).(uint)
	return userID, ok
}

// GetUserRoleFromContext extracts the user role from the request context
func GetUserRoleFromContext(ctx context.Context) (string, bool) {
	role, ok := ctx.Value(contextkeys.UserRoleKey).(string)
	return role, ok
}

// writeAuthError writes a JSON error response for authentication failures.
//
// M-05 fix: the previous implementation used raw string concatenation
// (`{"error": "` + message + `"}`), which produces malformed JSON when
// message contains a double-quote or backslash.  json.NewEncoder escapes
// all special characters automatically.
func writeAuthError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", `Bearer realm="oauth2", error="invalid_token"`)
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{Error: message})
}
