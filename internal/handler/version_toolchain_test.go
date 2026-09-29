package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"testing"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/version"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// GET /version (and /api/version) reports the Go toolchain that built the
// binary, next to the ldflags-stamped build info. The existing keys stay: the
// body is read by the consoles and other clients.
func TestVersion_ReportsBuildInfoAndGoToolchain(t *testing.T) {
	rr := httptest.NewRecorder()
	NewHealthHandler(nil).Version(rr, httptest.NewRequest(http.MethodGet, "/api/version", nil))

	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v (body %q)", err, rr.Body.String())
	}
	want := map[string]string{
		"version":    version.Version,
		"commit":     version.Commit,
		"branch":     version.Branch,
		"build_time": version.BuildTime,
		"go_version": runtime.Version(),
	}
	for k, v := range want {
		if body[k] != v {
			t.Errorf("%s = %q, want %q", k, body[k], v)
		}
	}
	if len(body) != len(want) {
		t.Errorf("body has %d keys, want %d: %v", len(body), len(want), body)
	}
}

// The monitoring console's System Health card reads this response. It used to
// report a hard-coded version "1.0.0" and go_version "1.21+".
func TestDashboardHealth_ReportsRealVersionAndGoToolchain(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; GetHealth pings the database")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if sqlDB, err := db.DB(); err == nil {
		t.Cleanup(func() { _ = sqlDB.Close() })
	}

	rr := httptest.NewRecorder()
	NewDashboardHandler(db, nil, nil, nil).GetHealth(rr, httptest.NewRequest(http.MethodGet, "/api/admin/dashboard/health", nil))

	var body dto.DashboardHealthResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v (body %q)", err, rr.Body.String())
	}
	if body.Version != version.Version {
		t.Errorf("version = %q, want %q (the build's version, not a constant)", body.Version, version.Version)
	}
	if got := body.Details["go_version"]; got != runtime.Version() {
		t.Errorf("details.go_version = %v, want %q", got, runtime.Version())
	}
}
