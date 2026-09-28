"""Security probes against the local stack (server direct and via Caddy+BFF)."""
import hashlib, hmac as _hmac, http.client
from flows import *

T = admin_token()
alice_pw = open(f"{E}/alice-pw.txt").read().strip()
root_pw = open(f"{E}/root-pw.txt").read().strip()
ip_n = [100]
def fresh_ip():
    ip_n[0] += 1; return {"X-Forwarded-For": f"198.18.0.{ip_n[0]}"}

def login(email, pw, client=CID):
    s, b = req("POST", f"{PUB}/api/auth/login", {"email": email, "password": pw, "app_client_id": client}, headers=fresh_ip())
    return b if s == 200 else None

def raw(method, host, port, path, headers=None, body=None):
    c = http.client.HTTPConnection(host, port, timeout=15)
    c.request(method, path, body=body, headers=headers or {})
    r = c.getresponse(); data = r.read(); c.close()
    return r.status, dict(r.getheaders()), data

# ── CORS ─────────────────────────────────────────────────────────────────────
for origin, allowed in [("http://evil.example", False), ("http://admin.localhost:9001", True)]:
    s, h, _ = raw("OPTIONS", "127.0.0.1", 8080, "/oauth/token", {"Origin": origin, "Access-Control-Request-Method": "POST"})
    acao = h.get("Access-Control-Allow-Origin")
    check(f"CORS preflight from {origin}", (acao == origin) if allowed else (acao in (None, "")), f"{s} ACAO={acao} ACAC={h.get('Access-Control-Allow-Credentials')}")
s, h, _ = raw("GET", "127.0.0.1", 8080, "/oauth/userinfo", {"Origin": "null"})
check("CORS: Origin null not reflected", h.get("Access-Control-Allow-Origin") not in ("null", "*"), f"ACAO={h.get('Access-Control-Allow-Origin')}")

# ── redirect_uri validation ─────────────────────────────────────────────────
good = "http://app.localhost:9003/bff/callback"
def authz(ru):
    q = urllib.parse.urlencode({"response_type": "code", "client_id": CID, "redirect_uri": ru, "scope": "openid", "state": "s",
                                "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "code_challenge_method": "S256"})
    s, h, b = raw("GET", "127.0.0.1", 8080, "/oauth/authorize?" + q)
    return s, h.get("Location", ""), b[:200]
s, loc, _ = authz(good)
check("authorize with the registered redirect_uri renders login", s == 200, f"{s}")
for bad in [good + "/../../evil", good + "x", good + "?next=http://evil.example", "http://evil.example/bff/callback",
            "http://app.localhost:9003.evil.example/bff/callback", good.replace("http://", "HTTP://"), good + "#frag", "javascript:alert(1)"]:
    s, loc, b = authz(bad)
    check(f"redirect_uri variant refused: {bad[:60]}", s != 200 and "evil" not in loc, f"{s} Location={loc[:60]}")
s, loc, _ = authz(good.replace("localhost", "127.0.0.1"))
check("redirect_uri host swap refused", s != 200, f"{s}")

# PKCE downgrade / plain
q = urllib.parse.urlencode({"response_type": "code", "client_id": CID, "redirect_uri": good, "scope": "openid", "state": "s", "code_challenge": "abc", "code_challenge_method": "plain"})
s, h, _ = raw("GET", "127.0.0.1", 8080, "/oauth/authorize?" + q)
check("PKCE method=plain refused", s != 200 or "invalid_request" in h.get("Location", ""), f"{s} {h.get('Location', '')[:80]}")
q = urllib.parse.urlencode({"response_type": "code", "client_id": CID, "redirect_uri": good, "scope": "openid", "state": "s"})
s, h, _ = raw("GET", "127.0.0.1", 8080, "/oauth/authorize?" + q)
check("authorize without PKCE refused (require_pkce client)", s != 200 or "invalid_request" in h.get("Location", ""), f"{s} {h.get('Location', '')[:80]}")
q = urllib.parse.urlencode({"response_type": "token", "client_id": CID, "redirect_uri": good, "scope": "openid", "state": "s"})
s, h, _ = raw("GET", "127.0.0.1", 8080, "/oauth/authorize?" + q)
check("implicit grant (response_type=token) refused", s != 200 or "unsupported_response_type" in h.get("Location", ""), f"{s} {h.get('Location', '')[:80]}")

# BFF return_to open redirect
for rt in ["//evil.example", "https://evil.example/", "/\\evil.example", "/%2F%2Fevil.example", "javascript:alert(1)"]:
    s, h, _ = raw("GET", "127.0.0.1", 8091, "/bff/login?return_to=" + urllib.parse.quote(rt, safe=""), {"Host": "admin.localhost:9001"})
    check(f"admin BFF return_to sanitised: {rt}", s == 302 and "evil" not in h.get("Location", "").split("?")[0], f"{s}")

# ── Authorisation ───────────────────────────────────────────────────────────
a = login("alice@e2e.test", alice_pw)
AT = a["access_token"]
for m, path, body in [("GET", "/api/admin/users", None), ("POST", "/api/admin/superadmins", {"email": "x@e.t", "name": "x", "password": "Xx-123456789!"}),
                      ("GET", "/api/apps/2/users", None), ("PUT", "/api/admin/policy", {"rules": []})]:
    s, b = req(m, f"{ADM}{path}", body, token=AT)
    check(f"plain/app-admin user refused: {m} {path}", s in (401, 403), f"{s} {str(b)[:80]}")
s, b = req("PUT", f"{ADM}/api/apps/3/users/2", {"role": "superadmin"}, token=AT)
check("app admin cannot grant a non-app role", s in (400, 403, 422), f"{s} {str(b)[:100]}")
s, b = req("PUT", f"{PUB}/api/profile", {"name": "Alice", "role": "superadmin", "email_verified": True}, token=AT)
s2, me = req("GET", f"{PUB}/oauth/userinfo", token=login("alice@e2e.test", alice_pw)["access_token"])
check("profile update cannot change own role (mass assignment)", "superadmin" not in json.dumps(me), f"PUT={s} userinfo role={me.get('role') if isinstance(me, dict) else me}")

# Audience confusion: a superadmin's token minted for a third-party app, replayed at the admin API
r = login("root@e2e.test", root_pw)
s, b = req("GET", f"{ADM}/api/admin/users", token=r["access_token"])
check("superadmin token issued to another app is refused by the admin API (audience)", s in (401, 403), f"{s} aud={jwt_claims(r['access_token']).get('aud')}")

# ── JWT attacks ─────────────────────────────────────────────────────────────
h, p, sig = AT.split(".")
claims = jwt_claims(AT)
def b64(d): return base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).rstrip(b"=").decode()
jwks = req("GET", f"{PUB}/.well-known/jwks.json")[1]
tampered = h + "." + b64({**claims, "role": "superadmin"}) + "." + sig
check("payload tampering (role=superadmin) refused", req("GET", f"{PUB}/oauth/userinfo", token=tampered)[0] == 401)
hs = b64({"alg": "HS256", "typ": "JWT", "kid": json.loads(base64.urlsafe_b64decode(h + "=="))["kid"]})
key = json.dumps(jwks).encode()
hs_tok = hs + "." + p + "." + base64.urlsafe_b64encode(_hmac.new(key, (hs + "." + p).encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
check("alg confusion (HS256 keyed with the public JWKS) refused", req("GET", f"{PUB}/oauth/userinfo", token=hs_tok)[0] == 401)
unk = b64({"alg": "RS256", "typ": "JWT", "kid": "no-such-kid"}) + "." + p + "." + sig
check("unknown kid refused", req("GET", f"{PUB}/oauth/userinfo", token=unk)[0] == 401)
jku = b64({"alg": "RS256", "typ": "JWT", "jku": "http://evil.example/jwks.json", "kid": "x"}) + "." + p + "." + sig
check("jku header ignored/refused", req("GET", f"{PUB}/oauth/userinfo", token=jku)[0] == 401)
RT = a["refresh_token"]
check("refresh token not accepted as an access token", req("GET", f"{PUB}/oauth/userinfo", token=RT)[0] == 401)
IDT = a.get("id_token")
if IDT:
    check("ID token not accepted as an access token", req("GET", f"{PUB}/oauth/userinfo", token=IDT)[0] == 401)

# ── Injection probes (must not 500, must not leak SQL) ─────────────────────
for path in ["/api/admin/security/events?ip_address=%27%20OR%201%3D1--", "/api/admin/security/events?event_type=login_failed%27;DROP%20TABLE%20users;--",
             "/api/admin/users?search=%27%29%20OR%20%281%3D1", "/api/admin/logs?action=x%27%20UNION%20SELECT%201--", "/api/admin/security/events?sort=id;DROP", "/api/admin/security/events?page_size=100000000"]:
    s, b = req("GET", f"{ADM}{path}", token=T)
    check(f"injection probe handled: {path[:60]}", s < 500 and "SQLSTATE" not in json.dumps(b) and "syntax" not in json.dumps(b).lower(), f"{s} {json.dumps(b)[:80]}")
s, b = req("POST", f"{PUB}/api/auth/login", {"email": "' OR '1'='1", "password": "' OR '1'='1", "app_client_id": CID}, headers=fresh_ip())
check("SQLi in login refused cleanly", s in (400, 401), f"{s} {b}")

# ── BFF path traversal / smuggling ──────────────────────────────────────────
for pth in ["/api/admin/%2e%2e/%2e%2e/health", "/api/admin/..%2f..%2fhealth", "/api/apps/%2e%2e/admin/users", "/api/admin//users", "/api/profile/../admin/users"]:
    s, h2, b = raw("GET", "127.0.0.1", 8091, pth, {"Host": "admin.localhost:9001"})
    check(f"BFF refuses non-canonical path {pth}", s in (301, 308, 400, 401, 404), f"{s}")

# ── Enumeration ─────────────────────────────────────────────────────────────
s1, b1 = req("POST", f"{PUB}/api/auth/login", {"email": "alice@e2e.test", "password": "wrong-pw", "app_client_id": CID}, headers=fresh_ip())
s2, b2 = req("POST", f"{PUB}/api/auth/login", {"email": "nobody-xyz@e2e.test", "password": "wrong-pw", "app_client_id": CID}, headers=fresh_ip())
check("login: unknown email and wrong password answer identically", (s1, b1) == (s2, b2), f"{s1} {b1} vs {s2} {b2}")
s, b = req("POST", f"{PUB}/api/auth/signup", {"name": "x", "email": "alice@e2e.test", "password": "Very-Strong-Pw-123!", "client_id": CID}, headers=fresh_ip())
check("signup with an existing email does not reveal it (or is documented)", s in (200, 201, 202) or "exist" not in json.dumps(b).lower(), f"{s} {b}")

# ── Password policy ─────────────────────────────────────────────────────────
for pw in ["short", "password", "12345678", "aaaaaaaaaaaa"]:
    s, b = req("POST", f"{PUB}/api/auth/signup", {"name": "w", "email": f"weak{int(time.time()*1000)}@e2e.test", "password": pw, "client_id": CID}, headers=fresh_ip())
    check(f"weak password refused: {pw}", s == 400, f"{s} {b}")

# ── MFA code brute force is bounded ─────────────────────────────────────────
c = json.load(open(f"{E}/carol.json"))
cl = login(c["email"], c["password"])
enr = req("POST", f"{PUB}/api/profile/mfa/enroll", {}, token=cl["access_token"])[1]
req("POST", f"{PUB}/api/profile/mfa/confirm", {"code": totp(enr["secret"])}, token=cl["access_token"])
codes = [req("POST", f"{PUB}/api/auth/login", {"email": c["email"], "password": c["password"], "app_client_id": CID, "mfa_code": f"{i:06d}"}, headers=fresh_ip())[0] for i in range(8)]
s, b = req("POST", f"{PUB}/api/auth/login", {"email": c["email"], "password": c["password"], "app_client_id": CID, "mfa_code": totp(enr["secret"])}, headers=fresh_ip())
check("TOTP brute force locks the account", 403 in codes or s == 403, f"wrong codes → {codes}; right code then → {s} {b}")
req("POST", f"{ADM}/api/admin/users/{c['user_id']}/unlock", {}, token=T)
cl = login(c["email"], c["password"]) or {}
if not cl:
    s, cl = req("POST", f"{PUB}/api/auth/login", {"email": c["email"], "password": c["password"], "app_client_id": CID, "mfa_code": totp(enr["secret"])}, headers=fresh_ip())
req("POST", f"{PUB}/api/profile/mfa/disable", {"password": c["password"], "code": totp(enr["secret"], time.time() + 30)}, token=cl.get("access_token"))

# ── Response hygiene ────────────────────────────────────────────────────────
s, h, b = raw("POST", "127.0.0.1", 8080, "/oauth/token", {"Content-Type": "application/x-www-form-urlencoded", "Authorization": "Basic " + base64.b64encode(f"{CID}:{CSEC}".encode()).decode()}, "grant_type=client_credentials")
check("token response has Cache-Control: no-store", "no-store" in h.get("Cache-Control", ""), f"Cache-Control={h.get('Cache-Control')} Pragma={h.get('Pragma')}")
s, h, b = raw("GET", "127.0.0.1", 8080, "/does-not-exist")
check("404 does not leak stack/framework", s == 404 and b"goroutine" not in b and b"panic" not in b, f"{s} {b[:60]}")
s, h, b = raw("POST", "127.0.0.1", 8080, "/api/auth/login", {"Content-Type": "application/json"}, "{not json")
check("malformed JSON → 400 without internals", s == 400 and b"json:" not in b, f"{s} {b[:80]}")

print(f"\n{sum(bool(ok) for _, ok in results)}/{len(results)} passed")
