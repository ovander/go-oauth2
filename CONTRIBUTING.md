# Contributing to Socrate

Thank you for your interest. Socrate is the OAuth 2.1 / OpenID Connect server of a four-repository
suite: this server, the [`backendkit`](https://github.com/ovander/backendkit) Go library, and the
[admin](https://github.com/ovander/oauth2-admin) and
[monitoring](https://github.com/ovander/oauth2-monitoring) consoles. Contributions are accepted
under the project's licence, [Apache-2.0](LICENSE).

## Development setup

Requirements: Go (the `toolchain` line in `go.mod` downloads the exact version, 1.27.2) and
PostgreSQL 16.

```bash
git clone https://github.com/ovander/go-oauth2 && cd go-oauth2
go mod download
cp .env.example .env        # at least DATABASE_URL; see the README → Quick start
make gen-keys               # RSA signing keys for local use
make run
```

## Design rules

- **Standards first.** Behaviour follows the RFCs (OAuth 2.1 draft, RFC 9700, OIDC Core, RFC
  7009/7662/8693/9449/9207); a deviation is documented where it is made.
- **Backward-compatible, never a flag day.** A new security control ships behind an
  `off / observe / enforce` mode, off by default until telemetry shows it is safe to turn on.
- **Fail closed** on authentication and authorisation paths.
- **Schema changes are new migrations** in `internal/database/migrate`; a released migration is
  never edited.
- Every security-relevant change comes with an adversarial test, not only a happy-path one.

## Tests and checks

Run these before opening a pull request; CI runs the same and all of them are required:

```bash
test -z "$(gofmt -l .)"
go build ./... && go vet ./...
TEST_DATABASE_URL=postgres://…/socrate_test?sslmode=disable go test -race ./...
golangci-lint run ./...        # v2.14.0, built with Go 1.27.2
govulncheck ./...
make coverage-gate             # Tier-A coverage ratchet (see docs/TEST-STRATEGY.md)
```

Without `TEST_DATABASE_URL` the database tests skip; CI runs them against PostgreSQL 16. A perf
smoke (`deploy/perf/run.sh`) also runs in CI.

## Pull requests

1. Branch from `main` (`feat/…`, `fix/…`, `chore/…`, `docs/…`, `ci/…`).
2. Commit with [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`,
   `chore:`, `docs:`, `ci:`, `test:`, `build:`).
3. Add a line under `## [Unreleased]` in [`CHANGELOG.md`](CHANGELOG.md).
4. Open the PR with the template filled in, including deploy notes (migration, new environment
   variable, a mode that changes default, order with the consoles).
5. CI must be green. The maintainer reviews and merges.

## Releases

The maintainer tags releases `vX.Y.Z` on `main` after moving the `[Unreleased]` changelog section
under the new version. The `Release` workflow then publishes the GitHub release with that
section as its notes.

## Security

Please do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).
