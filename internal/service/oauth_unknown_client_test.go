// Package service — an unknown client_id at the token endpoint is a client
// authentication failure (ErrAppNotFound, audited as unknown_client), while any
// other app-lookup error stays an internal error so the endpoint fails closed.
package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
	"gorm.io/gorm"
)

// lookupErrAppRepo answers every FindByClientID with err.
type lookupErrAppRepo struct {
	crit02AppRepo
	err error
}

func (r *lookupErrAppRepo) FindByClientID(_ context.Context, _ string) (*model.App, error) {
	return nil, r.err
}

// unknownClientGrants runs each token grant for client "ghost" against a
// service whose app lookup fails with lookupErr. The code and refresh token are
// valid for "ghost", so the app lookup is what decides the outcome.
func unknownClientGrants(t *testing.T, lookupErr error) map[string]func() (*captureAuditRepo, error) {
	t.Helper()
	ghost := &model.App{ID: 9, ClientID: "ghost", Active: true, RedirectURIs: model.StringArray{"https://app.example.com/cb"}}
	newSvc := func() (*oauthService, *captureAuditRepo) {
		svc := newCrit02Service(t, ghost)
		svc.appRepo = &lookupErrAppRepo{err: lookupErr}
		audit := &captureAuditRepo{}
		svc.auditRepo = audit
		return svc, audit
	}
	return map[string]func() (*captureAuditRepo, error){
		"client_credentials": func() (*captureAuditRepo, error) {
			svc, audit := newSvc()
			_, err := svc.handleClientCredentialsGrant(context.Background(), dto.TokenRequest{Scope: "api"}, "ghost", "any-secret")
			return audit, err
		},
		"authorization_code": func() (*captureAuditRepo, error) {
			svc, audit := newSvc()
			code := seedCode(t, svc, "ghost", "https://app.example.com/cb", 5)
			req := dto.TokenRequest{GrantType: "authorization_code", Code: code, RedirectURI: "https://app.example.com/cb"}
			_, err := svc.handleAuthorizationCodeGrant(context.Background(), req, "ghost", "any-secret")
			return audit, err
		},
		"refresh_token": func() (*captureAuditRepo, error) {
			svc, audit := newSvc()
			ts, err := svc.tokenService.GenerateTokenSet(&model.User{ID: 5, Email: "u@test.com"}, ghost, "user", "openid", nil, "", time.Now().Unix())
			if err != nil {
				t.Fatalf("GenerateTokenSet: %v", err)
			}
			req := dto.TokenRequest{GrantType: "refresh_token", RefreshToken: ts.RefreshToken}
			_, err = svc.handleRefreshTokenGrant(context.Background(), req, "ghost", "any-secret")
			return audit, err
		},
	}
}

func TestTokenGrants_UnknownClient_IsClientAuthFailure(t *testing.T) {
	for grant, run := range unknownClientGrants(t, gorm.ErrRecordNotFound) {
		t.Run(grant, func(t *testing.T) {
			audit, err := run()
			if !errors.Is(err, ErrAppNotFound) {
				t.Fatalf("err = %v, want ErrAppNotFound", err)
			}
			if tokenOutcome(err) != "invalid_client" {
				t.Errorf("metrics outcome = %q, want invalid_client", tokenOutcome(err))
			}
			if audit.last == nil || audit.last.EventType != model.SecurityEventClientAuthFailed {
				t.Fatalf("want client_auth_failed audited, got %+v", audit.last)
			}
			if audit.last.Details["reason"] != "unknown_client" || audit.last.Details["client_id"] != "ghost" {
				t.Errorf("details = %v, want reason unknown_client for client ghost", audit.last.Details)
			}
			if audit.last.AppID != nil {
				t.Errorf("AppID = %v, want nil (no such app)", *audit.last.AppID)
			}
		})
	}
}

func TestTokenGrants_AppLookupFailure_StaysInternal(t *testing.T) {
	dbDown := errors.New("dial tcp 127.0.0.1:5432: connect: connection refused")
	for grant, run := range unknownClientGrants(t, dbDown) {
		t.Run(grant, func(t *testing.T) {
			audit, err := run()
			if err == nil {
				t.Fatal("expected an error when the app lookup fails")
			}
			if errors.Is(err, ErrAppNotFound) || errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("err = %v: a database failure must not look like a client-authentication failure", err)
			}
			if !errors.Is(err, dbDown) {
				t.Errorf("err = %v, want it to wrap the repository error", err)
			}
			if audit.last != nil && audit.last.EventType == model.SecurityEventClientAuthFailed {
				t.Errorf("a database failure was audited as client_auth_failed: %+v", audit.last)
			}
		})
	}
}
