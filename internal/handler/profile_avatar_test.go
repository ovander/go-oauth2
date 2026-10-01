package handler

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ovander/go-oauth2/internal/contextkeys"
	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/service"
)

// avatarUserService stubs only UpdateProfile; the embedded interface is nil.
type avatarUserService struct {
	service.UserService
	err error
}

func (s *avatarUserService) UpdateProfile(_ context.Context, id uint, req dto.UpdateProfileRequest) (*model.User, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &model.User{ID: id, Email: "a@example.test", AvatarURL: req.AvatarURL}, nil
}

func putProfile(h *ProfileHandler, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPut, "/api/profile", bytes.NewBufferString(body))
	req = req.WithContext(context.WithValue(req.Context(), contextkeys.UserIDKey, uint(7)))
	rr := httptest.NewRecorder()
	h.UpdateProfile(rr, req)
	return rr
}

func TestUpdateProfile_ReturnsAvatarURL(t *testing.T) {
	rr := putProfile(NewProfileHandler(&avatarUserService{}), `{"avatar_url":"https://cdn.example.com/7.png"}`)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"avatar_url":"https://cdn.example.com/7.png"`) {
		t.Fatalf("PUT /api/profile → %d %s", rr.Code, rr.Body.String())
	}
}

// An invalid avatar URL is a 400 that says why, unlike other (internal)
// failures, which stay generic.
func TestUpdateProfile_InvalidAvatarURL_Is400WithReason(t *testing.T) {
	err := fmt.Errorf("%w: must use https", service.ErrInvalidAvatarURL)
	rr := putProfile(NewProfileHandler(&avatarUserService{err: err}), `{"avatar_url":"http://x/a.png"}`)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid avatar_url: must use https") {
		t.Fatalf("PUT /api/profile → %d %s", rr.Code, rr.Body.String())
	}
}
