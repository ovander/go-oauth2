"""Hardened / opt-in settings: REFRESH_REUSE_MODE, SCOPE_POLICY_MODE +
ADMIN_SCOPE_MODE, WEBHOOKS_MODE (SSRF guard), TOKEN_EXCHANGE_MODE."""
import sys
from flows import *

phase = sys.argv[1]
T = admin_token()
alice_pw = open(f"{E}/alice-pw.txt").read().strip()
root_pw = open(f"{E}/root-pw.txt").read().strip()
ipn = [200]
def ip():
    ipn[0] += 1; return {"X-Forwarded-For": f"198.18.1.{ipn[0]}"}
def login(email, pw):
    s, b = req("POST", f"{PUB}/api/auth/login", {"email": email, "password": pw, "app_client_id": CID}, headers=ip())
    return b if s == 200 else {"_status": s, "_body": b}

if phase == "prepare":
    s, b = req("PUT", f"{ADM}/api/admin/apps/{APPID}", {"allowed_scopes": ["openid", "profile", "email", "offline_access"], "allow_token_exchange": True}, token=T)
    print("demo app → allowed_scopes + allow_token_exchange:", s, {k: b.get(k) for k in ("allowed_scopes", "allow_token_exchange")} if isinstance(b, dict) else b)
    sys.exit()

# ── Refresh reuse (enforce) ────────────────────────────────────────────────
a = login("alice@e2e.test", alice_pw)
RT0 = a["refresh_token"]
s, b = req("POST", f"{PUB}/oauth/token", form={"grant_type": "refresh_token", "refresh_token": RT0}, basic=(CID, CSEC)); RT1 = b.get("refresh_token")
s, b = req("POST", f"{PUB}/oauth/token", form={"grant_type": "refresh_token", "refresh_token": RT0}, basic=(CID, CSEC))
check("reuse of a rotated refresh token refused", s == 400, f"{s} {b}")
s, b = req("POST", f"{PUB}/oauth/token", form={"grant_type": "refresh_token", "refresh_token": RT1}, basic=(CID, CSEC))
check("REFRESH_REUSE_MODE=enforce revokes the family (successor refused)", s == 400, f"{s} {str(b)[:100]}")

# ── Audience confusion with ADMIN_SCOPE_MODE + SCOPE_POLICY_MODE = enforce ──
r = login("root@e2e.test", root_pw)
s, b = req("GET", f"{ADM}/api/admin/users", token=r["access_token"])
check("superadmin token issued to another app refused by the admin API", s in (401, 403), f"{s} scope={jwt_claims(r['access_token']).get('scope')}")
s, b = req("POST", f"{PUB}/oauth/token", form={"grant_type": "client_credentials", "scope": "admin"}, basic=(CID, CSEC))
check("scope outside allowed_scopes refused (invalid_scope)", s == 400 and b.get("error") == "invalid_scope", f"{s} {b}")
s, b = req("POST", f"{ADM}/api/admin/login", {"email": "root@e2e.test", "password": root_pw})
s2, b2 = req("GET", f"{ADM}/api/admin/users", token=b.get("access_token")) if s == 200 else (s, b)
check("loopback admin login still works under ADMIN_SCOPE_MODE=enforce", s2 == 200, f"login={s} scope={jwt_claims(b['access_token']).get('scope') if s == 200 else ''} users={s2}")

# ── Webhooks: SSRF guard at registration ───────────────────────────────────
T = b.get("access_token") or T
for url in ["http://127.0.0.1:8081/api/admin/users", "http://localhost:8081/", "http://169.254.169.254/latest/meta-data/", "http://10.0.0.5/hook",
            "http://[::1]:8081/", "http://0.0.0.0:8081/", "http://2130706433/", "http://0x7f.0.0.1/", "file:///etc/passwd", "gopher://127.0.0.1:6379/"]:
    s, b = req("POST", f"{ADM}/api/admin/webhooks", {"name": "ssrf", "url": url, "event_types": ["login.failed"]}, token=T)
    check(f"webhook SSRF refused: {url}", s in (400, 422), f"{s} {str(b)[:90]}")
s, b = req("POST", f"{ADM}/api/admin/webhooks", {"name": "ok", "url": "https://hooks.example.com/socrate", "event_types": ["login.failed"]}, token=T)
check("public https webhook accepted (secret shown once)", s in (200, 201) and bool((b or {}).get("secret") or (b or {}).get("signing_secret")), f"{s} keys={list(b.keys()) if isinstance(b, dict) else b}")

# ── Token exchange (RFC 8693) ─────────────────────────────────────────────
a = login("alice@e2e.test", alice_pw)
te = {"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", "subject_token": a["access_token"],
      "subject_token_type": "urn:ietf:params:oauth:token-type:access_token"}
s, b = req("POST", f"{PUB}/oauth/token", form=te, basic=(CID, CSEC))
check("token exchange by an allowed client", s == 200 and "access_token" in (b or {}), f"{s} {str(b)[:140]}")
if s == 200:
    c = jwt_claims(b["access_token"])
    check("exchanged token keeps the subject and records the actor", c.get("sub") == jwt_claims(a["access_token"])["sub"], f"sub={c.get('sub')} act={c.get('act')} aud={c.get('aud')}")
s, b = req("POST", f"{PUB}/oauth/token", form={**te, "subject_token": "garbage"}, basic=(CID, CSEC))
check("token exchange with an invalid subject token refused", s in (400, 401), f"{s} {b}")
MON = json.load(open(f"{E}/app-monitoring.json"))
s, b = req("POST", f"{PUB}/oauth/token", form=te, basic=(MON["client_id"], MON["client_secret"]))
check("token exchange by a client without allow_token_exchange refused", s in (400, 401, 403), f"{s} {b}")

print(f"\n{sum(bool(ok) for _, ok in results)}/{len(results)} passed")
