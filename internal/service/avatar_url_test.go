package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
)

func TestNormalizeAvatarURL(t *testing.T) {
	for _, ok := range []string{
		"https://cdn.example.com/u/42.png",
		"  https://cdn.example.com/u/42.png?v=3  ",
		"HTTPS://cdn.example.com/a.jpg",
	} {
		got, err := normalizeAvatarURL(ok)
		if err != nil || got == nil || *got != strings.TrimSpace(ok) {
			t.Errorf("normalizeAvatarURL(%q) = %v, %v", ok, got, err)
		}
	}
	for _, empty := range []string{"", "   "} {
		if got, err := normalizeAvatarURL(empty); got != nil || err != nil {
			t.Errorf("normalizeAvatarURL(%q) = %v, %v; want nil, nil", empty, got, err)
		}
	}
	for _, bad := range []string{
		"http://cdn.example.com/a.png",
		"javascript:alert(1)",
		"data:image/png;base64,AAAA",
		"/relative/a.png",
		"cdn.example.com/a.png",
		"https://user:pw@cdn.example.com/a.png",
		"https://cdn.example.com/a b.png",
		"https://cdn.example.com/" + strings.Repeat("a", MaxAvatarURLLength),
	} {
		if _, err := normalizeAvatarURL(bad); !errors.Is(err, ErrInvalidAvatarURL) {
			t.Errorf("normalizeAvatarURL(%q) err = %v, want ErrInvalidAvatarURL", bad, err)
		}
	}
}

func TestUpdateProfile_AvatarURL(t *testing.T) {
	repo := newFakeMagicLinkUserRepo()
	repo.add(&model.User{ID: 7, Email: "a@example.test", Name: "A"})
	svc := NewUserService(repo)
	ctx := context.Background()
	str := func(s string) *string { return &s }

	u, err := svc.UpdateProfile(ctx, 7, dto.UpdateProfileRequest{AvatarURL: str("https://cdn.example.com/7.png")})
	if err != nil || u.AvatarURL == nil || *u.AvatarURL != "https://cdn.example.com/7.png" {
		t.Fatalf("set: %v, %v", u, err)
	}
	// Omitted leaves it unchanged.
	if u, err = svc.UpdateProfile(ctx, 7, dto.UpdateProfileRequest{Name: str("B")}); err != nil || u.AvatarURL == nil {
		t.Fatalf("unchanged: %v, %v", u, err)
	}
	// A bad value is refused and leaves the stored one.
	if _, err = svc.UpdateProfile(ctx, 7, dto.UpdateProfileRequest{AvatarURL: str("javascript:alert(1)")}); !errors.Is(err, ErrInvalidAvatarURL) {
		t.Fatalf("bad: err = %v", err)
	}
	if got, _ := repo.FindByID(ctx, 7); got.AvatarURL == nil || *got.AvatarURL != "https://cdn.example.com/7.png" {
		t.Fatalf("bad value changed the stored avatar: %v", got.AvatarURL)
	}
	// "" clears it.
	if u, err = svc.UpdateProfile(ctx, 7, dto.UpdateProfileRequest{AvatarURL: str("")}); err != nil || u.AvatarURL != nil {
		t.Fatalf("clear: %v, %v", u.AvatarURL, err)
	}
}

func TestUserInfo_Picture(t *testing.T) {
	repo := newFakeMagicLinkUserRepo()
	pic := "https://cdn.example.com/9.png"
	repo.add(&model.User{ID: 9, Email: "p@example.test", Name: "P", IsVerified: true, AvatarURL: &pic})
	repo.add(&model.User{ID: 10, Email: "q@example.test", Name: "Q"})
	svc := &oauthService{userRepo: repo, userAppRoleRepo: newFakeMagicLinkRoleRepo()}

	info, err := svc.GetUserInfo(context.Background(), 9, "")
	if err != nil || info.Picture != pic || !info.EmailVerified {
		t.Fatalf("GetUserInfo(9) = %+v, %v", info, err)
	}
	if info, _ := svc.GetUserInfo(context.Background(), 10, ""); info.Picture != "" {
		t.Fatalf("no avatar: picture = %q, want empty (omitted)", info.Picture)
	}
}

func TestDiscovery_AdvertisesPicture(t *testing.T) {
	svc := &oauthService{issuer: testIssuer}
	if cfg := svc.GetOpenIDConfiguration(testIssuer); !sliceHas(cfg.ClaimsSupported, "picture") {
		t.Errorf("claims_supported is missing picture: %v", cfg.ClaimsSupported)
	}
}
