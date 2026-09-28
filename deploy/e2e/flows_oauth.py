"""OAuth/OIDC details: recovery codes, refresh rotation + reuse, introspect, revoke, end-session."""
from flows import *

c = json.load(open(f"{E}/carol.json"))
EMAIL, PW = c["email"], c["password"]

def login(**extra):
    return req("POST", f"{PUB}/api/auth/login", {"email": EMAIL, "password": PW, "app_client_id": CID, **extra})

# ── Recovery codes ──────────────────────────────────────────────────────────
s, b = login(); AT = b["access_token"]
s, b = req("POST", f"{PUB}/api/profile/mfa/enroll", {}, token=AT); secret = b["secret"]
s, b = req("POST", f"{PUB}/api/profile/mfa/confirm", {"code": totp(secret)}, token=AT)
check("MFA re-enrol + confirm", s in (200, 204), f"{s}")
s, b = login(mfa_code=totp(secret)); AT = b["access_token"]
s, b = req("POST", f"{PUB}/api/profile/mfa/recovery-codes", {"password": PW, "code": totp(secret)}, token=AT)
codes = (b or {}).get("recovery_codes") or (b or {}).get("codes") if isinstance(b, dict) else None
check("recovery codes issued", s == 200 and bool(codes), f"{s} n={len(codes or [])} {'' if codes else str(b)[:120]}")
if codes:
    s, b = login(mfa_code=codes[0]); check("login with a recovery code", s == 200, f"{s} {'' if s == 200 else b}")
    s, b = login(mfa_code=codes[0]); check("recovery code is single-use", s == 401, f"{s} {b}")
    if s != 200:
        s, b = login(mfa_code=totp(secret))
    AT = b.get("access_token", AT) if isinstance(b, dict) else AT
s, b = req("POST", f"{PUB}/api/profile/mfa/disable", {"password": PW, "code": totp(secret, time.time() + 30)}, token=AT)
check("MFA disabled again", s in (200, 204), f"{s}")

# ── Refresh rotation + reuse detection (confidential client, /oauth/token) ─
s, b = login(); RT0 = b["refresh_token"]; AT0 = b["access_token"]
s, b = req("POST", f"{PUB}/oauth/token", form={"grant_type": "refresh_token", "refresh_token": RT0}, basic=(CID, CSEC))
check("refresh_token grant", s == 200, f"{s} {'' if s == 200 else b}")
RT1 = b.get("refresh_token") if isinstance(b, dict) else None
check("refresh token rotated", bool(RT1) and RT1 != RT0)
s, b = req("POST", f"{PUB}/oauth/token", form={"grant_type": "refresh_token", "refresh_token": RT0}, basic=(CID, CSEC))
check("reuse of a rotated refresh token refused", s in (400, 401), f"{s} {b}")
s, b = req("POST", f"{PUB}/oauth/token", form={"grant_type": "refresh_token", "refresh_token": RT1}, basic=(CID, CSEC))
check("reuse detection revokes the family (successor refused too)", s in (400, 401), f"{s} {b}")
s, b = req("POST", f"{PUB}/oauth/token", form={"grant_type": "refresh_token", "refresh_token": RT0}, basic=(CID, "wrong-secret"))
check("refresh with a wrong client secret refused", s == 401, f"{s} {b}")

# ── Introspect + revoke ────────────────────────────────────────────────────
s, b = login(); AT, RT = b["access_token"], b["refresh_token"]
s, b = req("POST", f"{PUB}/oauth/introspect", form={"token": AT}, basic=(CID, CSEC))
check("introspect active access token", s == 200 and b.get("active") is True, f"{s} {str(b)[:120]}")
s, b = req("POST", f"{PUB}/oauth/introspect", form={"token": AT})
check("introspect without client auth refused", s == 401, f"{s} {b}")
s, b = req("POST", f"{PUB}/oauth/revoke", form={"token": RT, "token_type_hint": "refresh_token"}, basic=(CID, CSEC))
check("revoke refresh token", s == 200, f"{s}")
s, b = req("POST", f"{PUB}/oauth/token", form={"grant_type": "refresh_token", "refresh_token": RT}, basic=(CID, CSEC))
check("revoked refresh token refused", s in (400, 401), f"{s} {b}")
s, b = req("POST", f"{PUB}/oauth/introspect", form={"token": "not-a-token"}, basic=(CID, CSEC))
check("introspect garbage → inactive", s == 200 and b.get("active") is False, f"{s} {b}")

# ── Access-token lifetime (ACCESS_TOKEN_TTL=30 in this run) ─────────────────
s, b = login(); AT = b["access_token"]
exp = jwt_claims(AT)["exp"] - jwt_claims(AT)["iat"]
check("access token lifetime honours ACCESS_TOKEN_TTL", exp == 30, f"exp-iat={exp}")
time.sleep(32)
s, b = req("GET", f"{PUB}/oauth/userinfo", token=AT)
check("expired access token refused", s == 401, f"{s}")

# ── End-session (logout) ───────────────────────────────────────────────────
s, b = login(); AT, RT = b["access_token"], b["refresh_token"]
s, b = req("POST", f"{PUB}/api/auth/logout", {}, token=AT)
check("API logout", s in (200, 204), f"{s} {b}")
s, b = req("GET", f"{PUB}/oauth/userinfo", token=AT)
check("access token dead after logout", s == 401, f"{s}")
s, b = req("POST", f"{PUB}/oauth/token", form={"grant_type": "refresh_token", "refresh_token": RT}, basic=(CID, CSEC))
check("refresh token dead after logout", s in (400, 401), f"{s} {b}")
s, b = req("GET", f"{PUB}/oauth/logout?post_logout_redirect_uri=" + urllib.parse.quote("https://evil.example/"))
check("OIDC end-session refuses an unregistered post-logout redirect", s != 302 or "evil" not in str(b), f"{s} {str(b)[:100]}")

print(f"\n{sum(bool(ok) for _, ok in results)}/{len(results)} passed")
