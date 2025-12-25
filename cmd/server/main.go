package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/socrate-auth/go-oauth/config"
)

func main() {
	// Load configuration
	cfg := config.Load()

	// Initialize application
	app := Bootstrap(cfg)

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
	}

	go func() {
		log.Printf("🚀 OAuth 2.0 Server starting on port %s (single-port mode)", cfg.Port)
		log.Printf("📍 Issuer: %s", cfg.OAuthIssuer)
		log.Printf("🌍 Environment: %s", cfg.Environment)
		log.Printf("⚠️  Admin API available at /manage/api/admin/* (consider using dual-port mode for production)")

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	waitForShutdown(srv, nil, app)
}

// startDualPortMode runs OAuth and Admin servers on separate ports
// This allows different firewall rules for each
func startDualPortMode(cfg *config.Config, app *App) {
	// OAuth server (public-facing)
	oauthSrv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      app.OAuthRouter,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Admin server (internal)
	adminSrv := &http.Server{
		Addr:         ":" + cfg.AdminPort,
		Handler:      app.AdminRouter,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start OAuth server
	go func() {
		log.Printf("🚀 OAuth 2.0 Server starting on port %s (public)", cfg.Port)
		log.Printf("📍 Issuer: %s", cfg.OAuthIssuer)
		log.Printf("🌍 Environment: %s", cfg.Environment)

		if err := oauthSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start OAuth server: %v", err)
		}
	}()

	// Start Admin server
	go func() {
		log.Printf("🔒 Admin API starting on port %s (internal)", cfg.AdminPort)
		log.Printf("   Ensure this port is firewalled from public access!")

		if err := adminSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start Admin server: %v", err)
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

	log.Println("🛑 Shutting down servers...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown first server
	if err := srv1.Shutdown(ctx); err != nil {
		log.Printf("Server 1 forced to shutdown: %v", err)
	}

	// Shutdown second server if present
	if srv2 != nil {
		if err := srv2.Shutdown(ctx); err != nil {
			log.Printf("Server 2 forced to shutdown: %v", err)
		}
	}

	// Close database connection
	sqlDB, err := app.DB.DB()
	if err == nil {
		sqlDB.Close()
	}

	log.Println("👋 Servers stopped")
}
