# Socrate Suite — Security & Code Audit, Pass 2

**Date:** 2026-07-03
**Companion to:** `docs/CR-socrate-suite-security-pass1.md` (the original audit) and
`docs/CR-socrate-suite-remediation-plan.md` (the remediation plan this pass updates).
**Scope:** all four repositories (`go-oauth2`, `backendkit`, `oauth2-admin`,
`oauth2-monitoring`) at their current `main`, after the full remediation round —
14 merged PRs including the H1 privilege-escalation fix, both BFFs' fail-closed
rewrite, the M1/M2/L1–L4 identity-server hardening, and the full migration of
both consoles onto a new shared `backendkit/bff` package.

**Method:** four independent re-audits (one per repo), each instructed to (a)
verify every pass-1 finding actually landed in the current code — not trust the
merged PR's own claims — and (b) do a fresh, adversarial scan for anything new,
with particular attention on the parts of the codebase that changed the most
(the new shared `bff` package, and both consoles' migration onto it). Two
claims from the raw sub-agent reports were independently re-verified by hand
against the actual code, the GitHub API, and the real `proxy.golang.org` module
proxy before being included below, and one was refuted — see the note in
§3.5. This report does not repeat pass-1's findings in full; it verifies their
disposition and adds what's new.

---

## 1. Headline

**Every pass-1 finding is confirmed fixed, and none were regressed by the BFF
consolidation migration.** That migration was the single riskiest change in this
round — deleting hand-rolled Session/proxy/cookie/CSRF/PKCE code in two
production consoles and replacing it with a brand-new shared package — and it
held up under independent re-verification, including empirical concurrency
tests re-run against the actual merged code.

**The fresh scan found real, new issues, concentrated in exactly the place a
fresh scan should look hardest: the new shared `bff` package itself.** It had
no independent review before this pass (I designed and wrote it under time
pressure earlier in this engagement). Two of the three findings there were
empirically reproduced with adversarial test code, not just reasoned about:

- **High** — a session with an empty CSRF token silently disables CSRF
  protection for that session (reproduced).
- **Medium** — `Gateway`'s zero-value (`AuthEnabled` unset) is a fully-open
  pass-through, contradicting the package's own "fail-closed by default"
  documentation.
- **Medium** — concurrent requests near an access token's expiry can race a
  single-use, rotating refresh token and get a valid session deleted
  (reproduced: 7 of 8 concurrent requests failed and the session was deleted,
  in one of 50 trials against a rotating-refresh-token fake).

None of these are currently triggered by how the two consoles actually use the
package today (both explicitly set `AuthEnabled: true`; neither generates an
empty CSRF token) — but they are real defects in shared security
infrastructure now depended on by two production services, and the kind of
thing that bites in week two of production traffic (a login storm at an
expiry boundary; a future store migration that drops a field; a copy-pasted
`&bff.Gateway{...}` literal that omits one field). **Recommend fixing before
the next backendkit release** — see §2 for the full findings and §4 for the
suggested fix shape.

A handful of smaller, real findings were also found in each of the four
repos (below); none are release-blocking.

---

## 2. `backendkit/bff` — fresh findings (new package, first independent review)

### 2.1 HIGH — Empty CSRF token silently disables CSRF protection

`bff/session.go`'s `MatchCSRF` and `bff/gateway.go`'s `CheckCSRF` compare the
request's CSRF header against the session's stored value via
`ConstantTimeEqual` (`subtle.ConstantTimeCompare`). If a session's `csrf`
field is empty — via `NewSession(id, "", …)`, a `NewSessionFromSnapshot`
rehydration where the persisted record lost the field (schema drift, a store
bug, a partial write), or any other path that leaves it empty — a request
carrying **no CSRF header at all** (`r.Header.Get(...) == ""`) passes:
`subtle.ConstantTimeCompare` on two zero-length byte slices returns 1.
Reproduced directly: `NewSessionFromSnapshot(SessionSnapshot{ID:"sid",
CSRF:""}).MatchCSRF("")` → `true`. Neither current consumer constructs a
session with an empty CSRF today, so this is not actively triggered — but it
is a silent, no-error failure mode in a function the package's own docs
describe as providing CSRF protection, and it's a one-line fix: reject an
empty `want` up front in `MatchCSRF`.

### 2.2 MEDIUM/HIGH — `Gateway`'s safe-by-default claim doesn't hold for its zero value

`doc.go` states the defaults are "deliberately safe: … fail-closed (no valid
session ⇒ 401, never a pass-through)". But `Gateway.AuthEnabled` is a plain
`bool` with no constructor (`grep` confirms no `NewGateway` exists) — so its
Go zero value is `false`. When `AuthEnabled == false`, `ProxyWithSession`
proxies immediately with no session check, no CSRF check, and does **not**
strip the client's `Authorization`/`Cookie` headers (stripping only happens in
the authenticated branch). A `&bff.Gateway{Store: store, Cookie: cookie,
Refresher: ref}` built the obvious way — omitting `AuthEnabled: true`, which
every current call site sets manually — is a fully open pass-through that
forwards whatever `Authorization` header the client supplies. This is the
opposite of "fail-closed by default." Both current consumers happen to set
the field explicitly, so this is not exploitable in the deployed
configuration today, but it's a footgun for the next consumer (or the next
refactor) and directly contradicts the package's own documentation.
Recommend a `NewGateway(...)` constructor that defaults `AuthEnabled: true`,
or inverting the flag to `DisableAuth bool` so the zero value is safe.

### 2.3 MEDIUM — Concurrent token refresh races a rotating refresh token, killing valid sessions

`Gateway.EnsureFresh` has no per-session serialization around the refresh
call. Two concurrent requests that both observe `AccessValid == false` near
expiry both call `Refresher.RefreshToken(ctx, s.RefreshToken())` with the
*same* refresh-token value. Against an upstream that rotates (single-use)
refresh tokens — standard OAuth practice, and what Socrate itself does per
pass-1's audit — the loser's call fails with an already-used-token error, and
`ProxyWithSession`'s error path unconditionally deletes the session and clears
the cookie on any refresh error, logging the user out even though a sibling
request refreshed successfully in the same instant. Reproduced empirically
with an adversarial test (a rotating-refresh-token fake, 8 concurrent
requests × 50 trials): one trial produced 7 of 8 concurrent requests 401'd
and the session deleted. Notably, `jwtauth`'s H-1 fix in this same module
(pass-1, §H-1) solved the analogous problem — concurrent JWKS refetches —
with `golang.org/x/sync/singleflight`, already a direct dependency of this
module. The same pattern applied to `EnsureFresh` would close this.

### 2.4 LOW — `AllowPassthrough` + unset `AuthEnabled` compounds §2.2

When `AllowPassthrough=true` and no valid session resolves, `ProxyWithSession`
proxies with CSRF entirely skipped and the client's raw
`Authorization`/`Cookie` forwarded unmodified — by design, for migration
windows. This only matters once `AuthEnabled=true` (else §2.2 already
applies), and no live session data leaks through this path since nothing has
been resolved yet when it fires. Not raising this above Low on its own, but
combined with §2.2 it means two independent booleans, both unsafe at their Go
zero value, gate whether the proxy is safe at all — worth tightening the API
so misuse is harder, not just documented against.

### 2.5 Verified clean

`SanitizeReturnTo` held up against a real adversarial pass: control characters,
all backslash variants, `//`/`https://` prefixes, and a percent-encoded
double-slash (`%2F%2F`, which by the time the function sees it has already
been query-decoded to `//` by `url.Query().Get()`, so the existing `"//"`
check catches it). A leading-slash `javascript:` payload
(`/javascript:alert(1)`) technically passes the sanitizer, but was confirmed
non-exploitable: Go's `url.Parse` (and every mainstream browser) only treats a
leading token as a scheme when the string does *not* start with `/` — a
string starting with `/` is unconditionally a relative path, so
`u.Scheme=="" && u.Host==""` holds and no browser will interpret it as an
executable URI on redirect. `RandomToken`/`PKCE`/`ConstantTimeEqual` all use
correct primitives (`crypto/rand`, RFC 7636-verified S256, `subtle` compare
with no early-return timing leak beyond the length leak inherent to
`ConstantTimeCompare` itself, which is acceptable for fixed-length tokens).
`Session.Snapshot()`/`NewSessionFromSnapshot()` round-trips every field
losslessly (verified both by the package's own test and by field-by-field
comparison).

### 2.6 Also verified: pass-1 findings in `backendkit` are genuinely fixed

- **H-1 (JWKS-refetch DoS)**: single-flight, cooldown, and negative-cache are
  all present and correctly wired in `jwtauth/middleware.go`'s `getKey()`; a
  legitimately-rotated kid still resolves after the cooldown. Re-ran the
  concurrency tests under `-race`: clean.
- **M-2 (`exp` not required)**: `jwt.WithExpirationRequired()` +
  `jwt.WithLeeway()` confirmed present.
- **M-1 (path-escaping)**: every caller-supplied path *segment* across
  `admin.go`/`monitoring.go`/`alerts.go`/`reports.go` is now escaped —
  confirmed exhaustively. **New, adjacent, out-of-original-scope finding
  (Low)**: query-string *values* were not brought into the same fix.
  `monitoring.go`'s `StreamSecurityEvents` (`Severity`, `EventType`,
  `LastEventID`) and `GetGeoAnalytics`/`GetTokenStats` (`period`) still
  concatenate caller-supplied values into the query string with plain `+`,
  not `url.QueryEscape`. A value containing `&`/`#` could inject or override
  an adjacent query parameter. These are admin-authenticated endpoints, so
  ranked Low, but it's the same bug class M-1 closed and was evidently missed
  because it's a query string, not a path segment.

---

## 3. Per-repo verification detail

### 3.1 go-oauth2

**All six pass-1 findings (H1, M1, M2, L1, L2, L3, L4) plus the pgx CVE fix
verified genuinely fixed**, matching their documented scope precisely, with no
partial fixes or silent regressions. The intentionally-deferred gap (L3's
user-Bearer self-revoke path) is real, documented accurately in the merged
PR, and not worse than stated. Fix commits (`aa6e205`, `d86906a`, `9d28a49`)
touch exactly the files their messages claim.

**New findings:**

- **Medium — the M1 error-sanitization sweep covered the JSON API but missed
  the parallel server-rendered form handlers.** `internal/web/handler.go`'s
  `AcceptInviteSubmit` (`POST /auth/invite`) and `SignupSubmit` (`POST
  /auth/signup`) both render `err.Error()` directly into HTML served to an
  **unauthenticated** browser, and call the *exact same* service methods
  (`authService.Signup`, `authService.AcceptInvite`) that were hardened on
  the JSON side — which still return errors wrapping raw
  repository/DB failures (e.g. `"failed to create user: %w"`,
  `"failed to assign user role: %w"`, `"failed to claim token: %w"`). This is
  a gap in the sweep, not a regression the fix introduced — `internal/web/handler.go`
  was never touched by the M1 commit. Recommend the same `errors.Is`/static-message
  pattern here.
- **Low — `app_users_handler.go` still leaks `err.Error()`**, at ten call
  sites including SMTP/provider error detail on email-send failures. Severity
  is now Low rather than pass-1's Medium framing, since these routes are
  behind H1's `RequireAppAdmin` gate — exposure is limited to an authenticated
  app-admin, not the public — but it's an inconsistency with the
  no-raw-internal-errors principle M1 established elsewhere.
- **Medium (independently re-derived; the initial sub-agent report claimed
  High and was corrected)** — inconsistent IP-extraction between failed-login
  attribution and IP-block enforcement. `auth_handler.go`/`admin_auth_handler.go`
  attribute failed logins for auto-blocking via `middleware.GetClientIP(r)`;
  `IPBlockMiddleware` enforces blocks via `GetClientIPSafe(r, trustedCIDRs)`.
  **I traced both implementations by hand**: `GetClientIP(r)` is
  `GetClientIPSafe(r, nil)`, and since `len(nil) > 0` is false, it *never*
  honors `X-Forwarded-For` — it always returns the raw `RemoteAddr`. This
  means the originally-reported "attacker forges XFF to evade lockout or
  frame a third party" is **not actually exploitable** — an external caller
  cannot influence `GetClientIP`'s output via any header. The real, smaller
  issue: when genuinely deployed behind a trusted reverse proxy
  (`trustedCIDRs` configured), `GetClientIP` still never resolves XFF, so
  every request's `RemoteAddr` *is* the proxy's own IP — auto-defense then
  attributes every failed login across every real user to that one shared
  proxy IP, while `IPBlockMiddleware` correctly extracts each user's real IP
  via `GetClientIPSafe`. Net effect: per-client brute-force attribution
  collapses into one bucket in exactly the deployment topology
  (behind-a-trusted-proxy) where it matters most — diluting the lockout
  threshold for a real attacker, or risking a shared-IP block that takes out
  every user behind the proxy if aggregate failures trip it. Recommend
  `auth_handler.go`/`admin_auth_handler.go` and the audit-log sinks in
  `cmd/server/bootstrap.go` (lines ~654, ~685, same `GetClientIP` call) switch
  to `GetClientIPSafe(r, trustedCIDRs)` — the same function and config the
  enforcement middleware already uses.
- **Low — `GetClientIP`'s doc comment is factually wrong**, and it's exactly
  what caused the above finding to initially be mis-rated High: the comment
  reads "it always trusts proxy headers regardless of origin," but per the
  trace above it never does. A stale comment that inverts the actual security
  property is worth fixing on its own, independent of the finding above.
- **Medium — `handleClientCredentialsGrant` skips both scope validation and
  the DPoP requirement enforced on the other two grant types.** Confirmed by
  direct code read: `validateScope` is called in the authorization_code path
  (`oauth_service.go:298`) and `requireDPoP` in both authorization_code
  (`:489`) and refresh_token (`:642`), but neither is called in
  `handleClientCredentialsGrant` (`:786-826`) — it takes `req.Scope` verbatim
  (defaulting only to `"api"`) and never checks a per-app DPoP requirement.
  Confirmed this does not reach this server's own `/api/admin` routes today
  (`AuthMiddleware` requires a numeric `sub`; client-credentials tokens carry
  `sub="app:<id>"` and are rejected before any scope check runs) — but
  `client_credentials` is the standard grant for service-to-service access to
  *external* resource servers that trust this issuer's `scope` claim, and for
  any such consumer this is an unrestricted privilege-escalation path with
  zero enforcement at the issuer, and a client explicitly configured with
  `RequireDPoP=true` can still obtain a plain, non-sender-constrained bearer
  token via this grant. Likely an oversight given the explicit RFC 9449
  comments on the other two grants.

**Verified clean (no new High/Critical in the fresh pass):** refresh-token
rotation/replay (atomic, race-safe), authorization-code grant (atomic
redemption, PKCE, confidential-client secret enforcement, redirect-URI
binding), the `Introspect`/`Revoke` signature change has exactly one caller
each and no other grant path was missed, no `math/rand` anywhere outside
tests, no string-built SQL, no secrets in logs, `id_token_hint` handling
verifies signature before trusting audience for redirect validation, request
bodies are consistently capped.

**Build/test:** `go build ./...`, `go vet ./...` clean; `go test ./... -count=1`
— all 19 packages pass.

### 3.2 backendkit (non-`bff` findings — see §2 for the `bff` package)

Covered above (§2.6). `go build`/`go vet` clean; `go test -race ./jwtauth/...`
and `./bff/...` pass.

### 3.3 oauth2-admin

**All seven pass-1 findings (C-1, H-1, H-2, X-1/M-1, X-3, X-2, and the
dependency pin) verified fixed, and — the point of this pass — none were
regressed by the `backendkit/bff` migration.** C-1 was re-verified with an
actual production build: `dist/index.html` asset paths are root-relative
(`/assets/...`), confirmed by grep. The fail-closed proxy, CSRF, cookie
hardening (`__Host-`, `SameSite=Strict`, `HttpOnly`), logout revocation, and
rate limiting all survive the migration and are still exercised by
tests — `TestPhase2FullFlow`, `TestProxyFailClosed`,
`TestProxyPassThroughWhenFlagSet`, `TestLogoutRevokesTokens`,
`TestElevation`, and the new `TestEndToEndBrowserFlow` (a genuine
cookie-jar/redirect-following browser simulation, merged separately) all pass.
No leftover old-architecture landmines were found — grepped the whole `bff/`
package for direct field access on the pre-migration `Session` shape; none
found, everything routes through the new package's accessor methods.

**New findings:**

- **Medium — elevation-expiry absorption is fail-open on a malformed or
  already-expired `exp` claim.** `elevate.go`'s token-absorption computes
  `expiresIn := int(time.Until(time.Unix(int64(exp), 0)).Seconds())` from the
  elevated JWT's `exp` claim, then calls `SetTokens`. `bff.Session.applyTokens`
  (backendkit) only updates `accessExpiry` `if ts.ExpiresIn > 0`. If the
  elevated JWT's `exp` is missing, non-numeric, or already past (clock skew,
  or momentary staleness), `expiresIn` ends up `<= 0`, the guard skips
  updating `accessExpiry`, and the session **keeps its prior, longer**
  access-token expiry while the access token itself is now the elevated one.
  `AccessValid`/`EnsureFresh` then treat the elevated token as valid for that
  stale, longer window — instead of the short step-up TTL the code's own
  comment promises. Net effect on bad input: the code silently *extends* the
  elevated window instead of *reverting* to non-elevated, which is fail-open,
  not fail-closed. Actual blast radius depends on whether the upstream admin
  API independently re-validates the elevated JWT's own `exp` per call (out of
  this repo's scope to confirm) — if it does, this degrades to a confusing
  401; if it trusts the bearer without re-checking `exp`, this is a genuine
  elevated-privilege-duration extension. `TestElevation` only covers the
  happy path with a valid future-dated token; no test covers a
  malformed/expired `exp`. Recommend: on a missing/unparseable/already-past
  `exp`, explicitly set `accessExpiry` to `now` (or reject the elevate call
  outright) rather than silently keeping the old expiry.
- **Low — CSRF header name is hardcoded in `elevate.go`** (`"X-CSRF-Token"`
  literal) instead of using the Gateway's configured header name. Currently
  harmless (nothing overrides `Gateway.CSRFHeader`), but a landmine if it ever
  is — `/api/admin/*` and `/api/profile` CSRF checks would follow the
  override; `/bff/elevate`'s hand-rolled check would silently keep checking
  the old name. `Gateway.CSRFHeaderName()` isn't currently exported to fix
  this cleanly.
- **Info — Phase 1 (no `BFF_CLIENT_ID`) bypasses the Gateway entirely** and
  is a fully open bearer pass-through with no CSRF. Intentional/documented as
  a pre-Phase-2 bootstrap state, but a misconfigured or missing
  `BFF_CLIENT_ID` in production would silently drop back to this rather than
  failing closed. Worth a startup assertion or an explicit opt-in flag,
  analogous to `AllowPassthrough`.
- **Info, not a regression — roles are frozen at login and never refreshed on
  token refresh.** Diffed against pre-migration code; identical behavior
  existed before. If a user is de-privileged upstream mid-session, the BFF's
  cached `UserInfo.Roles` (surfaced via `/bff/session`, used for SPA-side UI
  gating) stays stale until re-login — a UI-defense-in-depth gap, not a
  server-side authorization bypass, since the actual bearer sent upstream is
  refreshed and carries current claims (assuming the admin API validates
  roles independently, which is outside this repo).

**Build/test:** `cd bff && go build/vet` clean; `go test -race ./...` — all
tests pass, including the new `e2e_test.go`.

### 3.4 oauth2-monitoring

**All eight pass-1 findings (F1/X-1, F2, F5, X-3/F7, X-2, CI, the pgx pin, and
the dependency pin) verified fixed and surviving the migration intact** — the
hardest of the two console migrations, since this BFF also persists sessions
to Postgres. The concurrency test (`TestSessionConcurrentGetAndMutate`, 64
goroutines) is a genuine mutation test, not a no-op, and was re-run 5× under
`-race`: clean every time. The `Sweep()` composition — the specific place a
capitalization mismatch between the embedded `bff.MemoryStore.Sweep()` and a
shadowing override could silently no-op — was checked carefully and found
correct on both `MemorySessionStore` and `PostgresSessionStore`; no bug
present. Multi-instance correctness holds: `PostgresSessionStore.Get` never
caches, always re-reads Postgres as source of truth.

**New findings (all Low):**

- `PostgresSessionStore.Get` silently swallows any transient DB error other
  than "row not found," with no logging — a real DB blip becomes
  indistinguishable in the logs from ordinary session expiry, which will slow
  incident diagnosis (e.g. a Postgres failover looks identical to mass normal
  logout).
- `Put()` similarly drops a `json.Marshal` failure with no logging. Low
  real-world likelihood (`SessionSnapshot` has no cyclic/unencodable data),
  same diagnosability gap as above.
- `handleElevate`'s `EnsureFresh`-failure path correctly deletes the
  server-side session but doesn't clear the cookie (unlike
  `ProxyWithSession`'s equivalent path, which does both). Not a
  vulnerability — the stale cookie just resolves to "no session" on the next
  request — but an inconsistency worth matching.
- Same frozen-roles-on-refresh property as oauth2-admin (§3.3), confirmed
  pre-existing, not a migration regression.

**§3.5 — one claim investigated and refuted.** The monitoring re-audit
initially reported that `backendkit`'s `v1.10.0` git tag "does not match the
module content actually consumed" — that checking out the tag locally showed
code missing `Session.Snapshot()`, while the real Go module proxy served
content that had it. I investigated this by hand rather than taking it at
face value, since a mutable release tag would be a serious supply-chain
finding. Root cause: this session's own sandbox had a **stale local git tag
object** for `v1.10.0` in its `backendkit` checkout, left over from an
earlier failed manual tag-push attempt during this engagement (the initial
`git push` for the tag was rejected with a permissions error; a local tag
object had already been created before that failure). A `git fetch origin
--tags --force` and a direct download from the real `proxy.golang.org` (not
GitHub, not this sandbox — the actual authoritative module source, with
`GOSUMDB` verification on) both confirm the real, currently-published
`v1.10.0` tag is an annotated tag correctly dereferencing to the PR #41 merge
commit, and does include `Session.Snapshot()`/`NewSessionFromSnapshot()`.
**This is not a real finding** — backendkit's tag is correct and reproducible.
It's included here only for transparency about a claim that was checked and
found not to hold.

**Build/test:** `cd bff && go build/vet` clean; `go test -race ./...` pass;
`go mod verify` — "all modules verified."

---

## 4. Suggested fix shape for the `bff` package findings (§2.1–2.3)

These three are small, targeted, and don't require an API redesign:

```go
// 2.1 — reject empty CSRF outright.
func (s *Session) MatchCSRF(token string) bool {
    s.mu.Lock()
    want := s.csrf
    s.mu.Unlock()
    if want == "" {
        return false
    }
    return ConstantTimeEqual(token, want)
}

// 2.2 — safe zero value. Either a constructor:
func NewGateway(store SessionStore, cookie CookieConfig, refresher TokenRefresher) *Gateway {
    return &Gateway{Store: store, Cookie: cookie, Refresher: refresher, AuthEnabled: true}
}
// ...or invert the flag so its zero value is safe:
//   DisableAuth bool   // zero value = auth enabled = fail-closed
// Either works; the constructor is the smaller diff for existing callers.

// 2.3 — singleflight per session key, mirroring jwtauth's H-1 fix.
type Gateway struct {
    ...
    refreshGroup singleflight.Group // new, unexported
}
func (g *Gateway) EnsureFresh(ctx context.Context, s *Session) (string, error) {
    if s.AccessValid(g.now(), g.refreshLeeway()) {
        return s.AccessToken(), nil
    }
    v, err, _ := g.refreshGroup.Do(s.ID(), func() (any, error) {
        // re-check inside the singleflight in case a sibling call already refreshed
        if s.AccessValid(g.now(), g.refreshLeeway()) {
            return s.AccessToken(), nil
        }
        ts, err := g.Refresher.RefreshToken(ctx, s.RefreshToken())
        if err != nil {
            return nil, err
        }
        s.SetTokens(ts, g.now())
        return s.AccessToken(), nil
    })
    if err != nil {
        return "", err
    }
    return v.(string), nil
}
```

This is scoped as a proposal, not yet implemented — flagging for a decision
on prioritization alongside the other new findings in the updated remediation
plan.

---

## 5. Overall verdict

The remediation round held. Every one of the ~25 findings closed by the 14
merged PRs in this engagement was independently re-verified against the
actual current code — not the PR descriptions — and every one is genuinely
fixed, including through a full architectural migration of both consoles'
security-critical BFF core onto new shared infrastructure. That migration was
the highest-risk single change in the round and it did not regress anything.

The fresh scan earned its keep: it found a real High-severity logic bug and a
real availability bug in the new shared package (empirically reproduced, not
theoretical), a real gap in the M1 error-sanitization sweep (the
server-rendered form handlers), a real gap in `handleClientCredentialsGrant`'s
enforcement, and a handful of Low-severity diagnosability/consistency items —
while also catching and correcting two claims that didn't hold up
(the IP-spoofing "High," downgraded to a real but different Medium; the
backendkit tag-governance claim, refuted entirely). Nothing found in this
pass is exploitable in the two consoles' current, as-deployed configuration.
The `bff` package findings are the ones worth prioritizing, since it's now
shared infrastructure and the fixes are cheap.

**No repo regressed. No prior fix was undone. The suite's maturity increased
this round**, not just its finding count.
