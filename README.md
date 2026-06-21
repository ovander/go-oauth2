# OAuth 2.0 Server (Go)

[![CI](https://github.com/ovander/go-oauth2/actions/workflows/ci.yml/badge.svg)](https://github.com/ovander/go-oauth2/actions/workflows/ci.yml)

A complete OAuth 2.0 and OpenID Connect server implementation in Go, following the DTMA architecture pattern.

## CI

Every push to `main` and every pull request runs `go build`, `go vet`,
`go test -race`, and `govulncheck` via GitHub Actions
(`.github/workflows/ci.yml`). `gofmt`/`golangci-lint` enforcement is planned as
a follow-up.

## Features

- **OAuth 2.0 Grant Types**
  - Authorization Code (with PKCE support)
  - Refresh Token
  - Client Credentials

- **OpenID Connect**
  - ID Tokens
  - UserInfo endpoint
  - Discovery endpoint
  - JWKS endpoint

- **Security**
  - RS256 JWT signing
  - Automatic key rotation
  - PKCE support
  - Rate limiting
  - Account lockout
  - Password strength validation

- **Multi-tenant**
  - Multiple OAuth client applications
  - Per-application user role management
  - App-scoped permissions

## Quick Start

### Prerequisites

- Go 1.22+
- PostgreSQL 14+
- Make (optional)

### Setup

1. Clone and install dependencies:
```bash
cd go-oauth
go mod download
```

2. Copy the environment file:
```bash
cp .env.example .env
```

3. Configure your database connection in `.env`

4. Generate RSA keys:
```bash
make gen-keys
```

5. Run the server:
```bash
make run
```

## API Endpoints

### Health
- `GET /health` - Health check
- `GET /health/liveness` - Liveness probe
- `GET /health/readiness` - Readiness probe

### OAuth 2.0
- `GET /oauth/authorize` - Authorization endpoint
- `POST /oauth/token` - Token endpoint
- `GET/POST /oauth/userinfo` - UserInfo endpoint
- `POST /oauth/introspect` - Token introspection
- `POST /oauth/revoke` - Token revocation

### OpenID Connect Discovery
- `GET /.well-known/openid-configuration` - OpenID Configuration
- `GET /.well-known/jwks.json` - JSON Web Key Set

### Authentication
- `POST /api/auth/signup` - Register new user
- `GET /api/auth/verify-email` - Verify email
- `POST /api/auth/login` - Login
- `POST /api/auth/refresh` - Refresh tokens
- `POST /api/auth/logout` - Logout
- `POST /api/auth/request-password-reset` - Request password reset
- `POST /api/auth/reset-password` - Reset password
- `GET /api/auth/invite` - Validate invite token
- `POST /api/auth/invite` - Accept invite

### User Profile
- `GET /api/profile` - Get profile
- `PUT/PATCH /api/profile` - Update profile

### Admin
- `GET /api/admin/apps` - List owned apps
- `POST /api/admin/apps` - Create app
- `GET /api/admin/stats` - Admin statistics
- `GET /api/admin/activity` - Activity logs

### App User Management
- `GET /api/apps/:app_id/users` - List app users
- `POST /api/apps/:app_id/users` - Add user to app
- `GET /api/apps/:app_id/users/:user_id` - Get user details
- `PUT /api/apps/:app_id/users/:user_id` - Update user role
- `DELETE /api/apps/:app_id/users/:user_id` - Remove user from app

## Architecture

```
go-oauth/
├── cmd/server/          # Application entry point
├── config/              # Configuration management
├── internal/
│   ├── contextkeys/     # Context key constants
│   ├── dto/             # Data Transfer Objects
│   ├── handler/         # HTTP handlers
│   ├── http/            # Router setup
│   ├── middleware/      # HTTP middleware
│   ├── model/           # Domain models (GORM)
│   ├── repository/      # Data access layer
│   ├── service/         # Business logic
│   └── shared/auth/     # Auth utilities
├── pkg/
│   └── database/        # Database connection
└── keys/                # RSA keys for JWT signing
```

## License

MIT
