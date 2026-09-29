package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ovander/go-oauth2/config"
	"github.com/ovander/go-oauth2/internal/version"
	"github.com/ovander/go-oauth2/pkg/logger"
)

func main() {
	// Log version info — immediately visible in journalctl on every deploy
	logger.WithFields(logger.Fields{
		"version":    version.Version,
		"commit":     version.Commit,
		"branch":     version.Branch,
		"build_time": version.BuildTime,
	}).Info("🔖 Socrate starting")

	// Load configuration
	cfg := config.Load()

	// Validate configuration (fails on critical missing settings in production)
	if err := cfg.Validate(); err != nil {
		logger.Fatalf("Configuration validation failed: %v", err)
	}

	// Initialize application
	app := Bootstrap(cfg)

	// Effective-configuration summary (security posture, admin hardening,
	// scheduled jobs) — one structured line per startup.
	LogStartupSummary(cfg)

	// Determine server mode based on ADMIN_PORT configuration
	if cfg.AdminPort != "" {
		// DUAL-PORT MODE (Recommended for production)
		// OAuth server on public port, Admin API on internal port
		startDualPortMode(cfg, app)
	} else {
		// SINGLE-PORT MODE (Backwards compatible)
		// All routes on single port with /manage prefix for admin
		startSinglePortMode(cfg, app)
	}
}

// startSinglePortMode runs all routes on a single port
// Admin routes are available under /manage/api/admin/*
func startSinglePortMode(cfg *config.Config, app *App) {
	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      app.Router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
		// L-04 fix: the default (1 MB) is excessive for a token endpoint whose
		// largest expected header is a Bearer JWT (~2 KB).  16 KB is generous
		// for all legitimate OAuth/OIDC clients while capping memory spent on
		// oversized (or malicious) requests before the body is even read.
		MaxHeaderBytes: 16 * 1024,
	}

	go func() {
		logger.Infof("🚀 OAuth 2.0 Server listening on port %s (single-port mode)", cfg.Port)
		logger.Warnf("⚠️  Admin API available at /manage/api/admin/* (consider using dual-port mode for production)")

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Failed to start server: %v", err)
		}
	}()

	waitForShutdown(srv, nil, app)
}

// startDualPortMode runs OAuth and Admin servers on separate ports
// This allows different firewall rules for each
func startDualPortMode(cfg *config.Config, app *App) {
	// OAuth server (public-facing)
	oauthSrv := &http.Server{
		Addr:           ":" + cfg.Port,
		Handler:        app.OAuthRouter,
		ReadTimeout:    15 * time.Second,
		WriteTimeout:   15 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 16 * 1024, // L-04: 16 KB — generous for OAuth/OIDC, far below the 1 MB default
	}

	// Admin server (internal — slightly larger limit for dashboard/API payloads).
	// Binds AdminBindHost (loopback by default) so the Tier-0 control plane is not
	// publicly reachable; a same-host reverse proxy / BFF fronts it.
	adminSrv := &http.Server{
		Addr:           net.JoinHostPort(cfg.AdminBindHost, cfg.AdminPort),
		Handler:        app.AdminRouter,
		ReadTimeout:    15 * time.Second,
		WriteTimeout:   15 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 16 * 1024, // L-04: same conservative limit as the public server
	}

	// Start OAuth server
	go func() {
		logger.Infof("🚀 OAuth 2.0 Server listening on port %s (public)", cfg.Port)

		if err := oauthSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Failed to start OAuth server: %v", err)
		}
	}()

	// Start Admin server
	go func() {
		logger.Infof("🔒 Admin API listening on %s (internal control plane)", adminSrv.Addr)
		if cfg.AdminBindHost != "127.0.0.1" && cfg.AdminBindHost != "::1" && cfg.AdminBindHost != "localhost" {
			logger.Warnf("⚠️  Admin API bound to %q (not loopback) — ensure it is firewalled / network-isolated from public access", cfg.AdminBindHost)
		}

		if err := adminSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Failed to start Admin server: %v", err)
		}
	}()

	waitForShutdown(oauthSrv, adminSrv, app)
}

// waitForShutdown handles graceful shutdown for one or two servers
func waitForShutdown(srv1, srv2 *http.Server, app *App) {
	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("🛑 Shutting down servers...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown first server
	if err := srv1.Shutdown(ctx); err != nil {
		logger.Warnf("Server 1 forced to shutdown: %v", err)
	}

	// Shutdown second server if present
	if srv2 != nil {
		if err := srv2.Shutdown(ctx); err != nil {
			logger.Warnf("Server 2 forced to shutdown: %v", err)
		}
	}

	// Stop background workers (code store cleanup, rate limiter cleanup, etc.)
	logger.Info("Stopping background workers...")
	app.Stop()

	// Close database connection
	sqlDB, err := app.DB.DB()
	if err == nil {
		_ = sqlDB.Close()
	}

	logger.Info("👋 Servers stopped")
}
