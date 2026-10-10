package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/database/migrate"
	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
	"github.com/ovander/go-oauth2/internal/service"
	"github.com/ovander/go-oauth2/internal/shared/auth"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// #336, end to end against PostgreSQL: an operator registers an
// application-defined scope through the admin API, it round-trips through the
// allowed_scopes text[] column, the client obtains it with client_credentials,
// introspection reports it, and no other client can obtain it.

func appScopeTx(t *testing.T) (*gorm.DB, model.User) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping the Postgres integration test")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := migrate.Run(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.App{}, &model.UserAppRole{}, &model.SecurityAuditLog{}, &model.UsedToken{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	tx := db.Begin()
	t.Cleanup(func() { tx.Rollback() })
	admin := model.User{Email: fmt.Sprintf("sa-336-%d@example.test", time.Now().UnixNano()), Role: model.UserRoleSuperadmin}
	if err := tx.Create(&admin).Error; err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	return tx, admin
}

func appScopeCreate(t *testing.T, h *AdminHandler, adminID uint, body string) (*httptest.ResponseRecorder, dto.AppWithSecretResponse) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/apps", bytes.NewBufferString(body))
	req = req.WithContext(adminCtx(adminID, model.UserRoleSuperadmin))
	rr := httptest.NewRecorder()
	h.CreateApp(rr, req)
	var resp dto.AppWithSecretResponse
	if rr.Code == http.StatusCreated {
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("create body: %v", err)
		}
	}
	return rr, resp
}

func TestIntegration_AppDefinedScopes(t *testing.T) {
	tx, admin := appScopeTx(t)
	appRepo := repository.NewAppRepository(tx)
	h := newLifecycleHandler(service.NewAppService(appRepo), &captureAuditService{})

	// Registration: malformed or reserved names keep the existing 400 shape.
	for _, bad := range []string{"monitoring:evil", "admin:x", "socrate:x", "openid:x", "Swingdrift:worker", "swingdrift", "swingdrift:worker admin", ""} {
		body := fmt.Sprintf(`{"name":"bad","redirect_uris":["https://app.example/cb"],"allowed_scopes":["api",%q]}`, bad)
		rr, _ := appScopeCreate(t, h, admin.ID, body)
		var e dto.ErrorResponse
		_ = json.Unmarshal(rr.Body.Bytes(), &e)
		if rr.Code != http.StatusBadRequest || !strings.Contains(e.Error, "invalid scope") {
			t.Errorf("allowed_scopes %q: status %d body %s, want 400 invalid scope", bad, rr.Code, rr.Body.String())
		}
	}

	// Accepted: a global scope plus a well-formed app scope.
	rr, worker := appScopeCreate(t, h, admin.ID,
		`{"name":"swingdrift-worker","redirect_uris":["https://app.example/cb"],"allowed_scopes":["api","swingdrift:worker"]}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create with an app scope: %d %s", rr.Code, rr.Body.String())
	}
	if strings.Join(worker.AllowedScopes, " ") != "api swingdrift:worker" {
		t.Fatalf("allowed_scopes = %v", worker.AllowedScopes)
	}
	rr, other := appScopeCreate(t, h, admin.ID,
		`{"name":"other","redirect_uris":["https://app.example/cb"],"allowed_scopes":["api"]}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create other: %d %s", rr.Code, rr.Body.String())
	}

	// Update through the admin API: add a second app scope, reject a reserved one.
	put := func(id uint, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/api/admin/apps/x", bytes.NewBufferString(body))
		req = chiCtxWithID(req.WithContext(adminCtx(admin.ID, model.UserRoleSuperadmin)), fmt.Sprint(id))
		rr := httptest.NewRecorder()
		h.UpdateApp(rr, req)
		return rr
	}
	if rr := put(worker.ID, `{"allowed_scopes":["api","swingdrift:worker","swingdrift:reports.read"]}`); rr.Code != http.StatusOK {
		t.Fatalf("update with app scopes: %d %s", rr.Code, rr.Body.String())
	}
	if rr := put(other.ID, `{"allowed_scopes":["api","monitoring:evil"]}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("update with a reserved namespace: %d, want 400", rr.Code)
	}
	stored, err := appRepo.FindByClientID(context.Background(), worker.ClientID)
	if err != nil || strings.Join(stored.AllowedScopes, " ") != "api swingdrift:worker swingdrift:reports.read" {
		t.Fatalf("stored allowed_scopes = %v (%v)", stored, err)
	}

	km, err := auth.NewKeyManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	ts := auth.NewTokenService(km, auth.TokenConfig{Issuer: "https://auth.example.com", AccessTokenTTL: time.Hour, RefreshTokenTTL: time.Hour})

	for _, mode := range []string{"off", "observe", "enforce"} {
		t.Run(mode, func(t *testing.T) {
			svc := service.NewOAuthService(repository.NewUserRepository(tx), appRepo, repository.NewUserAppRoleRepository(tx),
				nil, ts, km, "https://auth.example.com", repository.NewSecurityAuditLogRepository(tx),
				repository.NewUsedTokenRepository(tx), "off", 0, "off", 0, "off", "off", mode)
			cc := func(clientID, secret, scope string) (*dto.TokenResponse, error) {
				return svc.Token(context.Background(), dto.TokenRequest{GrantType: "client_credentials", Scope: scope}, clientID, secret)
			}

			resp, err := cc(worker.ClientID, worker.ClientSecret, "api swingdrift:worker")
			if err != nil {
				t.Fatalf("client_credentials with a registered app scope: %v", err)
			}
			claims, err := ts.VerifyAccessToken(resp.AccessToken)
			if err != nil || claims.Scope != "api swingdrift:worker" || claims.Subject != fmt.Sprintf("app:%d", worker.ID) {
				t.Fatalf("claims = %+v (%v)", claims, err)
			}
			ir, err := svc.Introspect(context.Background(), resp.AccessToken, worker.ClientID)
			if err != nil || !ir.Active || ir.Scope != "api swingdrift:worker" {
				t.Fatalf("introspect = %+v (%v)", ir, err)
			}

			for _, tc := range []struct{ clientID, secret, scope string }{
				{worker.ClientID, worker.ClientSecret, "swingdrift:unregistered"},
				{worker.ClientID, worker.ClientSecret, "swingdrift:worker admin:x"},
				{other.ClientID, other.ClientSecret, "swingdrift:worker"},
				{other.ClientID, other.ClientSecret, "api swingdrift:reports.read"},
			} {
				if _, err := cc(tc.clientID, tc.secret, tc.scope); !errors.Is(err, service.ErrInvalidScope) {
					t.Errorf("client %s scope %q: got %v, want ErrInvalidScope", tc.clientID, tc.scope, err)
				}
			}
		})
	}
}

// The token-exchange error mapping answers invalid_scope (not server_error)
// for a scope the requesting client does not register.
func TestIntegration_TokenExchange_InvalidScopeMapping(t *testing.T) {
	svc := &fakeOAuthSvc{tokenErr: fmt.Errorf("%w: unknown scope 'swingdrift:worker'", service.ErrInvalidScope)}
	r := buildOAuthTestRouter(svc)
	body := strings.NewReader("grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=x&subject_token_type=urn:ietf:params:oauth:token-type:access_token&scope=swingdrift:worker&audience=https://api")
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), `"invalid_scope"`) {
		t.Fatalf("status %d body %s, want 400 invalid_scope", rr.Code, rr.Body.String())
	}
}
