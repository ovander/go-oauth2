package metrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
)

// The RED middleware must label by the chi route PATTERN, never the raw path
// (which would carry ids, emails and tokens into a time series).
func TestHTTP_LabelsByRoutePatternNotPath(t *testing.T) {
	r := chi.NewRouter()
	r.Use(HTTP("test"))
	r.Get("/api/admin/users/{id}", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	for _, id := range []string{"1", "2", "secret-token-value"} {
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/admin/users/"+id, nil))
	}
	got := testutil.ToFloat64(httpRequests.WithLabelValues("test", "/api/admin/users/{id}", "GET", "4xx"))
	if got != 3 {
		t.Fatalf("requests for the pattern = %v, want 3", got)
	}
	// A raw-path label must not exist anywhere in the exposition.
	body := scrape(t)
	if strings.Contains(body, "secret-token-value") {
		t.Fatal("raw path leaked into the exposition")
	}
}

func TestHTTP_UnmatchedRoutes(t *testing.T) {
	r := chi.NewRouter()
	r.Use(HTTP("test"))
	r.Get("/exists", func(w http.ResponseWriter, _ *http.Request) {}) // chi skips middleware on a route-less mux
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if got := testutil.ToFloat64(httpRequests.WithLabelValues("test", "unmatched", "GET", "4xx")); got < 1 {
		t.Fatalf("unmatched counter = %v, want >= 1", got)
	}
}

type fakeAudit struct {
	repository.SecurityAuditLogRepository
	fail bool
}

func (f fakeAudit) Create(_ context.Context, _ *model.SecurityAuditLog) error {
	if f.fail {
		return context.DeadlineExceeded
	}
	return nil
}

func TestInstrumentAuditRepo_CountsPersistedEventsOnly(t *testing.T) {
	ok := InstrumentAuditRepo(fakeAudit{})
	before := testutil.ToFloat64(securityEvents.WithLabelValues("login_failed", "false"))
	_ = ok.Create(context.Background(), &model.SecurityAuditLog{EventType: model.SecurityEventLoginFailed, Success: false})
	if got := testutil.ToFloat64(securityEvents.WithLabelValues("login_failed", "false")); got != before+1 {
		t.Fatalf("counter = %v, want %v", got, before+1)
	}
	failing := InstrumentAuditRepo(fakeAudit{fail: true})
	_ = failing.Create(context.Background(), &model.SecurityAuditLog{EventType: model.SecurityEventLoginFailed, Success: false})
	if got := testutil.ToFloat64(securityEvents.WithLabelValues("login_failed", "false")); got != before+1 {
		t.Fatalf("a failed persist must not be counted: %v", got)
	}
}

func TestSigningKeyAgeGauge(t *testing.T) {
	SetSigningKeyCreatedAt(func() time.Time { return time.Now().Add(-90 * time.Second) })
	body := scrape(t)
	if !strings.Contains(body, "socrate_signing_key_age_seconds 9") && !strings.Contains(body, "socrate_signing_key_age_seconds 8") {
		t.Fatalf("key age gauge missing or wrong:\n%s", grepLine(body, "signing_key_age"))
	}
	SetBuildInfo("1.2.3", "abc")
	if !strings.Contains(scrape(t), `socrate_build_info{commit="abc",version="1.2.3"} 1`) {
		t.Fatal("build_info gauge missing")
	}
}

func scrape(t *testing.T) string {
	t.Helper()
	rr := httptest.NewRecorder()
	Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return rr.Body.String()
}

func grepLine(body, needle string) string {
	for _, l := range strings.Split(body, "\n") {
		if strings.Contains(l, needle) && !strings.HasPrefix(l, "#") {
			return l
		}
	}
	return "<none>"
}
