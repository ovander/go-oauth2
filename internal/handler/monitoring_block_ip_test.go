package handler

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ovander/go-oauth2/internal/contextkeys"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
	"github.com/ovander/go-oauth2/internal/service"
)

// blockRepo records the blocks created; nothing is blocked beforehand.
type blockRepo struct {
	repository.BlockedIPRepository
	created []*model.BlockedIP
}

func (r *blockRepo) IsBlocked(context.Context, string) (bool, error) { return false, nil }
func (r *blockRepo) Create(_ context.Context, b *model.BlockedIP) error {
	r.created = append(r.created, b)
	return nil
}

func blockIP(h *MonitoringHandler, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/api/admin/security/blocked-ips", bytes.NewBufferString(body))
	r = r.WithContext(context.WithValue(r.Context(), contextkeys.UserIDKey, uint(1)))
	rr := httptest.NewRecorder()
	h.BlockIP(rr, r)
	return rr
}

// BlockIP refuses loopback, a trusted proxy, the server's own addresses and
// anything that is not an IP, and stores an accepted address in canonical form.
func TestBlockIP_RefusesProtectedAddresses(t *testing.T) {
	_, proxies, _ := net.ParseCIDR("10.0.0.0/8")
	repo := &blockRepo{}
	h := &MonitoringHandler{blockedIPRepo: repo}
	h.SetIPBlockGuard(service.NewIPBlockGuard([]*net.IPNet{proxies}, nil))

	for _, ip := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1", "10.0.0.5", "0.0.0.0", "not-an-ip", "198.51.100.0/24"} {
		if rr := blockIP(h, `{"ip_address":"`+ip+`","reason":"test"}`); rr.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", ip, rr.Code)
		}
	}
	if len(repo.created) != 0 {
		t.Fatalf("%d block(s) created for refused addresses", len(repo.created))
	}

	if rr := blockIP(h, `{"ip_address":"::ffff:198.51.100.9","reason":"test"}`); rr.Code != http.StatusCreated {
		t.Fatalf("ordinary address: %d %s", rr.Code, rr.Body.String())
	}
	if len(repo.created) != 1 || repo.created[0].IPAddress != "198.51.100.9" {
		t.Fatalf("stored %+v, want one block of 198.51.100.9 (canonical form)", repo.created)
	}
}
