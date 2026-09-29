// Package hooks is Socrate's in-process extension point (plan A6). Operators
// who build their own binary register Go functions that observe or veto
// identity events without touching the service code:
//
//	hooks.OnBeforeTokenIssue(func(ctx context.Context, e *hooks.TokenIssue) error {
//	    if e.App.ClientID == "legacy" && e.User.Role != model.UserRoleAdmin {
//	        return errors.New("legacy client is admin-only")
//	    }
//	    return nil
//	})
//
// Registration is meant to happen before the server starts (from a fork's
// main or an init()). The core itself uses the same mechanism for the
// declarative claim mapping (A2) and the webhook outbox (A3), so it is
// exercised on every request path, not just by forks.
//
// Semantics:
//   - BeforeTokenIssue runs before every token grant (authorization code,
//     refresh, client_credentials, the JSON login and magic-link logins). The
//     first error aborts issuance; the token endpoint answers access_denied.
//   - AfterLogin and UserProvisioned are observers: they run synchronously,
//     panics are recovered and logged, and they cannot fail the request. Do
//     slow work (HTTP calls) asynchronously from the hook.
package hooks

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/pkg/logger"
)

// ErrVetoed wraps a BeforeTokenIssue error so services and handlers can map
// it to a stable OAuth error (access_denied) without inspecting the message.
var ErrVetoed = errors.New("token issuance vetoed by hook")

// TokenIssue describes a token about to be minted. User is nil for
// client_credentials (service accounts).
type TokenIssue struct {
	User  *model.User
	App   *model.App
	Grant string // authorization_code | refresh_token | client_credentials | password | magic_link | admin_password
	Scope string
}

// Login describes a completed interactive authentication.
type Login struct {
	User   *model.User
	App    *model.App // nil for the admin portal
	Method string     // password | magic_link | admin_password | admin_elevate
	MFA    bool
}

// UserProvisioned describes a newly created account.
type UserProvisioned struct {
	User   *model.User
	App    *model.App // the app the user was created for, when known
	Source string     // signup | invite | admin | service_account | superadmin
}

type (
	BeforeTokenIssueFunc func(ctx context.Context, e *TokenIssue) error
	AfterLoginFunc       func(ctx context.Context, e Login)
	UserProvisionedFunc  func(ctx context.Context, e UserProvisioned)
)

var reg struct {
	mu          sync.RWMutex
	beforeToken []BeforeTokenIssueFunc
	afterLogin  []AfterLoginFunc
	provisioned []UserProvisionedFunc
}

// OnBeforeTokenIssue registers a veto/observe hook for token issuance.
func OnBeforeTokenIssue(fn BeforeTokenIssueFunc) {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	reg.beforeToken = append(reg.beforeToken, fn)
}

// OnAfterLogin registers an observer for completed logins.
func OnAfterLogin(fn AfterLoginFunc) {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	reg.afterLogin = append(reg.afterLogin, fn)
}

// OnUserProvisioned registers an observer for account creation.
func OnUserProvisioned(fn UserProvisionedFunc) {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	reg.provisioned = append(reg.provisioned, fn)
}

// Reset removes every registered hook (tests).
func Reset() {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	reg.beforeToken, reg.afterLogin, reg.provisioned = nil, nil, nil
}

// RunBeforeTokenIssue invokes the registered hooks in order; the first error
// aborts issuance and is returned wrapped in ErrVetoed. A hook panic is
// treated as a veto (fail closed), never as an allow.
func RunBeforeTokenIssue(ctx context.Context, e *TokenIssue) (err error) {
	reg.mu.RLock()
	fns := append([]BeforeTokenIssueFunc(nil), reg.beforeToken...)
	reg.mu.RUnlock()
	for i, fn := range fns {
		if herr := call(ctx, i, fn, e); herr != nil {
			return fmt.Errorf("%w: %v", ErrVetoed, herr)
		}
	}
	return nil
}

func call(ctx context.Context, i int, fn BeforeTokenIssueFunc, e *TokenIssue) (err error) {
	defer func() {
		if r := recover(); r != nil {
			logger.FromContext(ctx).Errorf("hooks: BeforeTokenIssue[%d] panicked: %v", i, r)
			err = fmt.Errorf("hook %d panicked", i)
		}
	}()
	return fn(ctx, e)
}

// RunAfterLogin notifies observers; failures never affect the login.
func RunAfterLogin(ctx context.Context, e Login) {
	reg.mu.RLock()
	fns := append([]AfterLoginFunc(nil), reg.afterLogin...)
	reg.mu.RUnlock()
	for i, fn := range fns {
		func() {
			defer func() {
				if r := recover(); r != nil {
					logger.FromContext(ctx).Errorf("hooks: AfterLogin[%d] panicked: %v", i, r)
				}
			}()
			fn(ctx, e)
		}()
	}
}

// RunUserProvisioned notifies observers; failures never affect provisioning.
func RunUserProvisioned(ctx context.Context, e UserProvisioned) {
	reg.mu.RLock()
	fns := append([]UserProvisionedFunc(nil), reg.provisioned...)
	reg.mu.RUnlock()
	for i, fn := range fns {
		func() {
			defer func() {
				if r := recover(); r != nil {
					logger.FromContext(ctx).Errorf("hooks: UserProvisioned[%d] panicked: %v", i, r)
				}
			}()
			fn(ctx, e)
		}()
	}
}
