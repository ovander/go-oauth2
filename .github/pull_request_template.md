## What and why

<!-- What this changes and why. Link the issue if there is one ("Closes #…"). -->

## How it was tested

<!-- New or changed tests (including adversarial ones for security changes), and anything checked by hand. -->

- [ ] `gofmt`, `go vet`, `go test -race ./...` with `TEST_DATABASE_URL` pass
- [ ] `golangci-lint run ./...` and `govulncheck ./...` report nothing new
- [ ] `make coverage-gate` passes
- [ ] A line is added under `## [Unreleased]` in `CHANGELOG.md`

## Deploy notes

<!-- Delete what does not apply. -->
- Migration: <!-- number; works on upgrade and fresh install; back up first if it rewrites data -->
- New or changed environment variable / mode default: <!-- name, default, also in .env.example -->
- Client-facing contract change: <!-- discovery, claims, endpoints, error codes — or none -->
- Order with the consoles or backendkit: <!-- e.g. deploy the server first -->
