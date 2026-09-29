.PHONY: build run dev test test-coverage coverage-report coverage-gate clean deps fmt lint deploy deploy-check

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=gofmt

# Binary name
BINARY_NAME=oauth-server
BINARY_PATH=bin/$(BINARY_NAME)

# Version info (baked into binary at build time via -ldflags)
VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT     := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
BRANCH     := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
MODULE     := github.com/ovander/go-oauth2

LDFLAGS := -ldflags "\
  -X '$(MODULE)/internal/version.Version=$(VERSION)' \
  -X '$(MODULE)/internal/version.Commit=$(COMMIT)' \
  -X '$(MODULE)/internal/version.BuildTime=$(BUILD_TIME)' \
  -X '$(MODULE)/internal/version.Branch=$(BRANCH)'"

# Build the application
build:
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_PATH) ./cmd/server

# Run the application
run: build
	./$(BINARY_PATH)

# Development mode with hot reload (requires air)
dev:
	air

# Run tests
test:
	$(GOTEST) -v ./...

# Run tests with coverage
test-coverage:
	$(GOTEST) -v -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

# Coverage report: overall total + Tier A (security-critical) coverage.
# Mirrors the CI coverage job (docs/TEST-STRATEGY.md). Report-only.
coverage-report:
	@$(GOTEST) ./... -coverprofile=coverage.out -covermode=atomic > /dev/null
	@echo "Overall:"; $(GOCMD) tool cover -func=coverage.out | tail -1
	@$(GOTEST) ./internal/service/... ./internal/shared/auth/... ./internal/middleware/... ./config/... \
		-coverpkg=./internal/service/...,./internal/shared/auth/...,./internal/middleware/...,./config/... \
		-coverprofile=tierA.out > /dev/null
	@echo "Tier A (security-critical, target >=90%):"; $(GOCMD) tool cover -func=tierA.out | tail -1

# Coverage gate: the blocking Tier A ratchet used by CI (Phase 8). Fails if Tier
# A coverage drops below TIER_A_MIN. Override the floor: make coverage-gate TIER_A_MIN=60
coverage-gate:
	@TIER_A_MIN=$(or $(TIER_A_MIN),55.0) bash scripts/coverage-gate.sh

# Clean build artifacts
clean:
	$(GOCLEAN)
	rm -rf bin/
	rm -f coverage.out coverage.html

# Download dependencies
deps:
	$(GOMOD) download
	$(GOMOD) tidy

# Format code
fmt:
	$(GOFMT) -s -w .

# Lint code (requires golangci-lint)
lint:
	golangci-lint run

# Generate RSA keys
gen-keys:
	mkdir -p keys
	openssl genrsa -out keys/private.pem 3072
	openssl rsa -in keys/private.pem -pubout -out keys/public.pem
	echo "key-$$(date +%s)" > keys/key_id

# Database migrations (using goose)
# Schema migrations are Go code (internal/database/migrate) applied by the
# server when AUTO_MIGRATE=true; there is no goose/SQL directory.
migrate-up:
	@echo "Run the server once with AUTO_MIGRATE=true (e.g. 'AUTO_MIGRATE=true make run'), then drop the flag."

migrate-down:
	@echo "Down-migrations are not supported; restore a database dump (see docs/DEPLOYMENT-VPS-MULTI-APP.md §8.3)."

migrate-status:
	@echo "Migration state lives in the schema itself; see internal/database/migrate."

# Deploy the server to a host with the legacy /opt/socrate layout (standalone/dev use; the
# production deploy kit is described in deploy/README.md).
# Usage: make deploy VPS=user@host [REMOTE_DIR=/opt/socrate]
# Files are staged in the remote user's home directory, then moved into place with sudo.
VPS        ?=
REMOTE_DIR ?= /opt/socrate

deploy-check:
	@test -n "$(VPS)" || { echo "usage: make deploy VPS=user@host [REMOTE_DIR=/opt/socrate]"; exit 2; }

deploy: deploy-check build-linux
	@echo "→ Uploading binary…"
	scp bin/socrate             $(VPS):socrate-new
	ssh $(VPS) "sudo mv socrate-new $(REMOTE_DIR)/bin/oauth-server && sudo chown socrate:socrate $(REMOTE_DIR)/bin/oauth-server"
	@echo "→ Uploading GeoIP databases (skipped if unchanged)…"
	rsync -az --progress data/  $(VPS):socrate-data/
	ssh $(VPS) "sudo rsync -az socrate-data/ $(REMOTE_DIR)/data/ && sudo chown -R socrate:socrate $(REMOTE_DIR)/data/"
	@echo "→ Restarting service…"
	ssh $(VPS) "sudo systemctl restart socrate"
	@echo "→ Tailing logs (Ctrl-C to stop)…"
	ssh -t $(VPS) "journalctl -u socrate -n 40 -f"

build-linux:
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o bin/socrate ./cmd/server

# Docker
docker-build:
	docker build -t oauth-server .

docker-run:
	docker run -p 8080:8080 --env-file .env oauth-server

# Help
help:
	@echo "Available targets:"
	@echo "  build          - Build the application"
	@echo "  run            - Build and run the application"
	@echo "  dev            - Run with hot reload (requires air)"
	@echo "  test           - Run tests"
	@echo "  test-coverage  - Run tests with HTML coverage report"
	@echo "  coverage-report - Overall + Tier A (security-critical) coverage"
	@echo "  coverage-gate  - Blocking Tier A coverage ratchet (CI Phase 8)"
	@echo "  clean          - Clean build artifacts"
	@echo "  deps           - Download and tidy dependencies"
	@echo "  fmt            - Format code"
	@echo "  lint           - Lint code (requires golangci-lint)"
	@echo "  gen-keys       - Generate RSA keys for JWT signing"
	@echo "  migrate-up     - Run database migrations"
	@echo "  migrate-down   - Rollback database migrations"
	@echo "  docker-build   - Build Docker image"
	@echo "  docker-run     - Run Docker container"
