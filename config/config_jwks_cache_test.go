package config

import (
	"os"
	"testing"
	"time"
)

func TestConfig_JWKSCacheMaxAge_Default(t *testing.T) {
	if err := os.Unsetenv("JWKS_CACHE_MAX_AGE_SECONDS"); err != nil {
		t.Fatalf("unset: %v", err)
	}
	if got := Load().JWKSCacheMaxAge; got != 300*time.Second {
		t.Errorf("JWKSCacheMaxAge default = %v, want 5m", got)
	}
}

func TestConfig_JWKSCacheMaxAge_ParsesSeconds(t *testing.T) {
	t.Setenv("JWKS_CACHE_MAX_AGE_SECONDS", "60")
	if got := Load().JWKSCacheMaxAge; got != time.Minute {
		t.Errorf("JWKSCacheMaxAge = %v, want 1m", got)
	}
}

func TestConfig_JWKSCacheMaxAge_Zero(t *testing.T) {
	t.Setenv("JWKS_CACHE_MAX_AGE_SECONDS", "0")
	if got := Load().JWKSCacheMaxAge; got != 0 {
		t.Errorf("JWKSCacheMaxAge = %v, want 0 (caching disabled)", got)
	}
}
