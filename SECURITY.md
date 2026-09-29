# Security policy

Socrate is an OAuth 2.1 / OpenID Connect identity provider: it issues the tokens every
application in the suite trusts. Security reports are welcome and handled first.

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting**: the repository's **Security** tab →
**Report a vulnerability**. Do not open a public issue or pull request for a vulnerability.

Include what you found, how to reproduce it, and the version you tested (`GET /api/version`, the
`🔖 Socrate starting` log line, or the commit you built).

You will get an acknowledgement within a week. Fixes are released as a patch version as soon as
they are ready, and the report is credited in the release notes unless you prefer otherwise.

## Scope

- In scope: the Socrate server in this repository — the OAuth/OIDC endpoints, hosted login and
  consent, token issuance and verification (including DPoP and token exchange), the admin API,
  the policy decision point, audit logging and integrity, and the deployment files in `deploy/`.
- Out of scope: the admin and monitoring consoles and their BFFs (report those in
  [`ovander/oauth2-admin`](https://github.com/ovander/oauth2-admin) and
  [`ovander/oauth2-monitoring`](https://github.com/ovander/oauth2-monitoring)), the
  [`backendkit`](https://github.com/ovander/backendkit) client library, denial-of-service by
  volume, and findings that need a misconfiguration the documentation warns against (for
  example an admin API exposed publicly instead of on loopback).

## Supported versions

Only the latest `v1.x` minor release receives security fixes. Upgrading within `v1` is
backward-compatible; new security controls ship behind `off / observe / enforce` modes so they
can be adopted gradually.

## Security model in brief

Authorization Code with PKCE (S256) only; RS256 tokens with a published JWKS and rotating keys;
refresh-token rotation with reuse detection; audience-bound tokens; DPoP (`cnf.jkt`); MFA and
step-up for administrators; rate limiting, lockout and IP auto-blocking; a hash-chained audit
log with an optional background integrity scanner (`AUDIT_INTEGRITY_SCAN_INTERVAL_SECONDS`); client-IP attribution that trusts only `TRUSTED_PROXIES`; and an
admin API meant to be reachable on loopback only. The [README](README.md#security) and
[`docs/`](docs/) describe each control and which ones are on by default.

## Past reviews

Socrate has been through four internal security-audit passes and an end-to-end security and
penetration test of the whole suite before v1.3.0. The fixes are listed in
[`CHANGELOG.md`](CHANGELOG.md) with the finding IDs they close.
