// Command demoapp is an e2e test application built only from backendkit: a
// BFF (Authorization Code + PKCE as a confidential client, server-side
// sessions, bearer-injecting proxy) in front of a resource API that verifies
// Socrate tokens (jwtauth) and asks Socrate's policy decision point (pep).
//
// Env: APP_BFF_ADDR, APP_API_ADDR, APP_PUBLIC_ORIGIN, SOCRATE_ISSUER,
// SOCRATE_PUBLIC_URL, SOCRATE_URL, SOCRATE_ADMIN_URL, SOCRATE_CLIENT_ID,
// SOCRATE_CLIENT_SECRET, SOCRATE_APP_ID.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ovander/backendkit/bff"
	"github.com/ovander/backendkit/ctxutil"
	"github.com/ovander/backendkit/jwtauth"
	"github.com/ovander/backendkit/pep"
	"github.com/ovander/backendkit/socrate"
	"github.com/sirupsen/logrus"
)

func env(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("%s is required", k)
	}
	return v
}

type pending struct {
	verifier, nonce, returnTo string
	at                        time.Time
}

type app struct {
	client   *socrate.Client
	gw       *bff.Gateway
	login    bff.LoginBinding
	cookie   bff.CookieConfig
	store    *bff.MemoryStore
	origin   string
	authzURL string
	clientID string

	mu      sync.Mutex
	pending map[string]pending // state → PKCE verifier + binding nonce
}

func main() {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	lg := logrus.NewEntry(logger)

	client, err := socrate.NewClient(socrate.ClientConfig{
		BaseURL:      env("SOCRATE_URL"),
		AdminBaseURL: env("SOCRATE_ADMIN_URL"),
		ClientID:     env("SOCRATE_CLIENT_ID"),
		ClientSecret: env("SOCRATE_CLIENT_SECRET"),
		AppID:        env("SOCRATE_APP_ID"),
	})
	if err != nil {
		log.Fatal(err)
	}

	store := bff.NewMemoryStore(30*time.Minute, 8*time.Hour)
	cookie := bff.CookieConfig{Name: "demo_session", Secure: false}
	a := &app{
		client:   client,
		store:    store,
		cookie:   cookie,
		gw:       &bff.Gateway{Store: store, Cookie: cookie, Refresher: client},
		login:    bff.LoginBinding{Cookie: bff.CookieConfig{Name: "demo_login", Secure: false}, TTL: 10 * time.Minute},
		origin:   env("APP_PUBLIC_ORIGIN"),
		authzURL: strings.TrimRight(env("SOCRATE_PUBLIC_URL"), "/") + "/oauth/authorize",
		clientID: env("SOCRATE_CLIENT_ID"),
		pending:  map[string]pending{},
	}

	// ── Resource API (loopback only; reached through the BFF proxy) ────────────
	enforcer, err := pep.New(pep.Config{Decider: client, Logger: lg, FreshAuthMaxAge: 5 * time.Minute})
	if err != nil {
		log.Fatal(err)
	}
	auth := jwtauth.New(strings.TrimRight(env("SOCRATE_URL"), "/")+"/.well-known/jwks.json", env("SOCRATE_ISSUER"), lg)
	api := http.NewServeMux()
	api.HandleFunc("GET /api/me", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		writeJSON(w, 200, map[string]any{
			"sub": ctxutil.GetUserSub(ctx), "email": ctxutil.GetUserEmail(ctx),
			"role": ctxutil.GetUserRole(ctx), "auth_time": ctxutil.GetAuthTime(ctx), "amr": ctxutil.GetAMR(ctx),
		})
	})
	api.HandleFunc("POST /api/invoices/{id}/approve", func(w http.ResponseWriter, r *http.Request) {
		err := enforcer.Check(r.Context(), "invoice.approve",
			socrate.PolicyResource{Type: "invoice", ID: r.PathValue("id"), Attributes: map[string]any{"amount": 1200}},
			socrate.PolicyContext{IP: clientIP(r)})
		if pep.WriteDenial(w, err) {
			return
		}
		writeJSON(w, 200, map[string]any{"approved": r.PathValue("id")})
	})
	api.HandleFunc("POST /api/jobs/nightly", func(w http.ResponseWriter, r *http.Request) {
		// The application deciding for itself (no user), e.g. a background job.
		if pep.WriteDenial(w, enforcer.CheckAsApp(r.Context(), "report.export", socrate.PolicyResource{Type: "report"})) {
			return
		}
		writeJSON(w, 200, map[string]any{"job": "ran"})
	})
	api.HandleFunc("GET /api/service/whoami", func(w http.ResponseWriter, r *http.Request) {
		// A service-account call with the app's own client_credentials token.
		u, err := client.GetUserAsService(r.Context(), ctxutil.GetUserSub(r.Context()))
		if err != nil {
			writeJSON(w, 502, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, 200, u)
	})
	go func() {
		log.Printf("demo API on %s", env("APP_API_ADDR"))
		log.Fatal(http.ListenAndServe(env("APP_API_ADDR"), auth.Handler(api)))
	}()

	// ── BFF (public, behind Caddy) ─────────────────────────────────────────────
	apiURL, _ := url.Parse("http://" + env("APP_API_ADDR"))
	mux := http.NewServeMux()
	mux.HandleFunc("GET /bff/login", a.handleLogin)
	mux.HandleFunc("GET /bff/callback", a.handleCallback)
	mux.HandleFunc("GET /bff/session", a.handleSession)
	mux.HandleFunc("POST /bff/logout", a.handleLogout)
	mux.HandleFunc("/api/", a.gw.ProxyWithSession(bff.NewSingleHostProxy(apiURL)))
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html><title>Demo app</title><h1>Demo app</h1><a href="/bff/login">Sign in</a>`))
	})
	log.Printf("demo BFF on %s (origin %s)", env("APP_BFF_ADDR"), a.origin)
	log.Fatal(http.ListenAndServe(env("APP_BFF_ADDR"), mux))
}

func (a *app) handleLogin(w http.ResponseWriter, r *http.Request) {
	p := bff.NewPKCE()
	state := bff.RandomToken(32)
	nonce := a.login.Begin(w)
	a.mu.Lock()
	a.pending[state] = pending{verifier: p.Verifier, nonce: nonce, returnTo: bff.SanitizeReturnTo(r.URL.Query().Get("return_to")), at: time.Now()}
	a.mu.Unlock()
	q := url.Values{
		"response_type": {"code"}, "client_id": {a.clientID}, "redirect_uri": {a.origin + "/bff/callback"},
		"scope": {"openid profile email"}, "state": {state},
		"code_challenge": {p.Challenge}, "code_challenge_method": {"S256"},
	}
	http.Redirect(w, r, a.authzURL+"?"+q.Encode(), http.StatusFound)
}

func (a *app) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		writeJSON(w, 400, map[string]any{"error": e, "error_description": q.Get("error_description")})
		return
	}
	a.mu.Lock()
	pd, ok := a.pending[q.Get("state")]
	delete(a.pending, q.Get("state"))
	a.mu.Unlock()
	if !ok || time.Since(pd.at) > 10*time.Minute || !a.login.Verify(w, r, pd.nonce) {
		writeJSON(w, 400, map[string]any{"error": "invalid_state"})
		return
	}
	ts, err := a.client.ExchangeCode(r.Context(), q.Get("code"), a.origin+"/bff/callback", pd.verifier)
	if err != nil {
		writeJSON(w, 502, map[string]any{"error": "code_exchange_failed", "detail": err.Error()})
		return
	}
	claims := jwtPayload(ts.IDToken)
	user := bff.UserInfo{Sub: str(claims["sub"]), Email: str(claims["email"]), Name: str(claims["name"])}
	sess := bff.NewSession(bff.RandomToken(32), bff.RandomToken(32), ts, user, time.Now())
	a.store.Put(sess)
	a.cookie.SetSession(w, sess.ID())
	http.Redirect(w, r, pd.returnTo, http.StatusFound)
}

func (a *app) handleSession(w http.ResponseWriter, r *http.Request) {
	s, ok := a.gw.SessionFromRequest(r)
	if !ok {
		writeJSON(w, 200, map[string]any{"authenticated": false})
		return
	}
	writeJSON(w, 200, map[string]any{"authenticated": true, "user": s.User(), "csrf": s.CSRF()})
}

func (a *app) handleLogout(w http.ResponseWriter, r *http.Request) {
	s, ok := a.gw.SessionFromRequest(r)
	if ok {
		if !a.gw.CheckCSRF(r, s) {
			writeJSON(w, 403, map[string]any{"error": "csrf"})
			return
		}
		// RFC 7009 revocation of the refresh token, as the confidential client.
		form := url.Values{"token": {s.RefreshToken()}, "token_type_hint": {"refresh_token"}}
		req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, strings.TrimRight(os.Getenv("SOCRATE_URL"), "/")+"/oauth/revoke", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(a.clientID, os.Getenv("SOCRATE_CLIENT_SECRET"))
		if resp, err := http.DefaultClient.Do(req); err == nil {
			log.Printf("revoke refresh token → %d", resp.StatusCode)
			resp.Body.Close()
		}
		a.store.Delete(s.ID())
	}
	a.cookie.ClearSession(w)
	w.WriteHeader(http.StatusNoContent)
}

func jwtPayload(tok string) map[string]any {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return map[string]any{}
	}
	b, _ := base64.RawURLEncoding.DecodeString(parts[1])
	m := map[string]any{}
	_ = json.Unmarshal(b, &m)
	return m
}

func str(v any) string { s, _ := v.(string); return s }

func clientIP(r *http.Request) string {
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		return strings.TrimSpace(strings.Split(xf, ",")[0])
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

var _ = context.Background
