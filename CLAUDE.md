# CLAUDE.md — go-oauth2 (Socrate)

Standing instructions for Claude Code in this repository. Read this file and `CONTRIBUTING.md`
before any change. The shared client library is `ovander/backendkit`; the operator consoles are
`ovander/oauth2-admin` and `ovander/oauth2-monitoring`, and applications such as
`ovander/ascenda-backend` rely on this server's token contract.

## Project in one paragraph

Socrate is an OAuth 2.1 / OpenID Connect identity provider in Go (module
`github.com/ovander/go-oauth2`): chi router, GORM on PostgreSQL 16, numbered schema migrations in
`internal/database/migrate`, RS256 signing with a rotating key ring. It serves the public OAuth
endpoints (authorize, token, userinfo, introspect, revoke, discovery, JWKS), hosted login and
consent, and a separate admin API meant for loopback only, including the policy decision point
(A4) and the monitoring endpoints. Many controls ship behind `off / observe / enforce` modes.

## Sources of truth, in order

1. The code. Read it before proposing changes; do not describe code you have not opened.
2. `deploy/migration/SOCRATE-V1.3.0-OP-CONTRACT.md` for the client-facing contract (discovery
   values, `sub`, `aud`, refresh and JWKS behaviour).
3. `README.md`, `docs/` and `CHANGELOG.md`.

## Hard rules

- **The token contract is public.** Do not change discovery values, claim semantics (`sub` is the
  numeric user id, `aud[0]` the client id), endpoint paths or error codes without a changelog
  entry and a deprecation path; relying parties depend on them.
- **Additive by default.** A new control ships behind an `off / observe / enforce` mode, default
  off; changing a default is its own, announced change.
- **Migrations.** A schema change is a new numbered migration; never edit a released one. It must
  work both on an upgrade and on a fresh install.
- **Fail closed** on authentication and authorisation paths.
- **Never weaken a gate** to get green: no skipped or deleted tests, no `//nolint` or `t.Skip`
  without a one-line reason, no lowered coverage ratchet, no required check removed.
- **Secrets** never enter the repository: no `.env`, keys, tokens or real client secrets.
- **Scope.** One change per PR; do not widen a PR with unrelated fixes (open a separate one).

## Local gate (the same checks as CI)

```bash
test -z "$(gofmt -l .)"
go build ./... && go vet ./...
TEST_DATABASE_URL=postgres://…/socrate_test?sslmode=disable go test -race ./...
golangci-lint run ./...        # v2.14.0, built with Go 1.27.1
govulncheck ./...
make coverage-gate
```

## Git workflow

- Branch from `main`: `feat/…`, `fix/…`, `chore/…`, `ci/…`, `docs/…`. Conventional Commits.
- Open a PR; never push to `main`, never force-push a shared branch, never merge with red CI.
  The owner merges.
- Each PR adds a line under `## [Unreleased]` in `CHANGELOG.md`, and says in its body what it
  changes, how it was tested, and any deploy note (migration, env variable, mode default, order
  with the consoles).

## Releases and deploys (the owner runs them)

A release is an annotated tag `vX.Y.Z` on `main`, with the `[Unreleased]` changelog section moved
under the new version; the `Release` workflow publishes it. Production deploys use the kit
described in `deploy/README.md`. Do not tag or deploy unless asked.
