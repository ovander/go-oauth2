package service

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
)

// testMagicLanding is the landing page the magic-link test apps register.
var testMagicLanding = "https://app.example.com/auth/magic?lang=fr"

func TestRequestMagicLink_EmailOpensTheAppLandingPage(t *testing.T) {
	svc, _, userRepo, _, roleRepo, emailSvc := buildMagicLinkService(t)
	app := &model.App{ID: 1, ClientID: "app-1", Name: "Test App", MagicLinkURL: &testMagicLanding}
	seedTestUser(userRepo, roleRepo, &model.User{ID: 10, Email: "alice@example.com", IsVerified: true}, app)

	rawToken, err := svc.RequestMagicLink(context.Background(), "alice@example.com", app)
	if err != nil || rawToken == "" {
		t.Fatalf("RequestMagicLink = %q, %v", rawToken, err)
	}
	u, err := url.Parse(emailSvc.LastEmail.URL)
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Scheme + "://" + u.Host + u.Path; got != "https://app.example.com/auth/magic" {
		t.Errorf("email link opens %s, want the app's landing page", got)
	}
	q := u.Query()
	if q.Get("token") != rawToken || q.Get("client_id") != "app-1" || q.Get("lang") != "fr" {
		t.Errorf("email link query = %v; want token, client_id and the page's own lang", q)
	}
	if strings.Contains(emailSvc.LastEmail.URL, "/api/auth/magic-link/verify") {
		t.Error("email link still points at the POST-only verify endpoint")
	}
}

func TestRequestMagicLink_RefusedWhenNotConfigured(t *testing.T) {
	blank := "  "
	for name, landing := range map[string]*string{"nil": nil, "blank": &blank} {
		t.Run(name, func(t *testing.T) {
			svc, mlRepo, userRepo, _, roleRepo, emailSvc := buildMagicLinkService(t)
			app := &model.App{ID: 1, ClientID: "app-1", Name: "Test App", MagicLinkURL: landing}
			seedTestUser(userRepo, roleRepo, &model.User{ID: 10, Email: "alice@example.com", IsVerified: true}, app)

			// Same answer for a member and an unknown address: it depends on the app only.
			for _, email := range []string{"alice@example.com", "ghost@example.com"} {
				if _, err := svc.RequestMagicLink(context.Background(), email, app); !errors.Is(err, ErrMagicLinkNotConfigured) {
					t.Errorf("RequestMagicLink(%s) err = %v, want ErrMagicLinkNotConfigured", email, err)
				}
			}
			if len(mlRepo.tokens) != 0 || emailSvc.LastEmail != nil {
				t.Errorf("tokens=%d email=%v; want no token and no email", len(mlRepo.tokens), emailSvc.LastEmail)
			}
		})
	}
}

func TestValidateMagicLinkURL(t *testing.T) {
	redirects := []string{"https://app.example.com/callback", "http://localhost:5173/callback"}
	ok := []string{
		"https://app.example.com/auth/magic",
		"https://APP.example.com:443/auth/magic",
		"https://app.example.com/auth/magic?lang=fr",
		"http://localhost:5173/magic",
	}
	for _, u := range ok {
		if err := validateMagicLinkURL(u, redirects); err != nil {
			t.Errorf("validateMagicLinkURL(%q) = %v, want nil", u, err)
		}
	}
	bad := []string{
		"",
		"/auth/magic",
		"app.example.com/auth/magic",
		"http://app.example.com/auth/magic",
		"https://evil.example.com/auth/magic",
		"https://app.example.com.evil.test/auth/magic",
		"https://app.example.com:8443/auth/magic",
		"http://localhost:4000/magic",
		"https://app.example.com/auth/magic#frag",
		"https://user:pw@app.example.com/auth/magic",
		"https://app.example.com/../auth/magic",
		"https://app.example.com/auth/magic?token=x",
		"https://app.example.com/auth/magic?client_id=x",
		"javascript:alert(1)",
	}
	for _, u := range bad {
		if err := validateMagicLinkURL(u, redirects); !errors.Is(err, ErrInvalidMagicLinkURL) {
			t.Errorf("validateMagicLinkURL(%q) = %v, want ErrInvalidMagicLinkURL", u, err)
		}
	}
	if err := validateMagicLinkURL("https://app.example.com/auth/magic", nil); !errors.Is(err, ErrInvalidMagicLinkURL) {
		t.Errorf("no redirect_uris: err = %v, want ErrInvalidMagicLinkURL", err)
	}
}

func TestAppService_MagicLinkURL(t *testing.T) {
	ctx := context.Background()
	svc := newAppSvc()
	landing := "https://app.example.com/auth/magic"

	app, _, err := svc.Create(ctx, dto.CreateAppRequest{
		Name: "ml", RedirectURIs: []string{"https://app.example.com/callback"}, MagicLinkURL: &landing,
	}, 1)
	if err != nil || app.MagicLinkURL == nil || *app.MagicLinkURL != landing {
		t.Fatalf("Create = %+v, %v; want magic_link_url stored", app, err)
	}

	evil := "https://evil.example.com/auth/magic"
	if _, _, err := svc.Create(ctx, dto.CreateAppRequest{
		Name: "ml2", RedirectURIs: []string{"https://app.example.com/callback"}, MagicLinkURL: &evil,
	}, 1); !errors.Is(err, ErrInvalidMagicLinkURL) {
		t.Errorf("Create(foreign origin) err = %v, want ErrInvalidMagicLinkURL", err)
	}

	// Moving the redirect URIs away from the landing page's origin is refused...
	moved := []string{"https://new.example.com/callback"}
	if _, err := svc.Update(ctx, app.ID, dto.UpdateAppRequest{RedirectURIs: moved}); !errors.Is(err, ErrInvalidMagicLinkURL) {
		t.Errorf("Update(redirects only) err = %v, want ErrInvalidMagicLinkURL", err)
	}
	// ...unless the landing page moves with them.
	newLanding := "https://new.example.com/auth/magic"
	got, err := svc.Update(ctx, app.ID, dto.UpdateAppRequest{RedirectURIs: moved, MagicLinkURL: &newLanding})
	if err != nil || *got.MagicLinkURL != newLanding {
		t.Fatalf("Update(both) = %v, %v", got.MagicLinkURL, err)
	}
	// Omitted leaves it unchanged; an empty string clears it.
	name := "renamed"
	if got, err = svc.Update(ctx, app.ID, dto.UpdateAppRequest{Name: &name}); err != nil || got.MagicLinkURL == nil {
		t.Fatalf("Update(name) = %v, %v; want magic_link_url unchanged", got.MagicLinkURL, err)
	}
	empty := ""
	if got, err = svc.Update(ctx, app.ID, dto.UpdateAppRequest{MagicLinkURL: &empty}); err != nil || got.MagicLinkURL != nil {
		t.Fatalf("Update(clear) = %v, %v; want nil", got.MagicLinkURL, err)
	}
}
