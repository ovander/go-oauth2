"""Account flows: signup → verify → login → MFA → reset password → magic link → lockout."""
import time
from flows import *

stamp = str(int(time.time()))
EMAIL = f"carol{stamp}@e2e.test"
PW = f"Carol-{stamp}-Pw!x"

# ── Signup + email verification ─────────────────────────────────────────────
n = len(mails_to(EMAIL))
s, b = req("POST", f"{PUB}/api/auth/signup", {"name": "Carol", "email": EMAIL, "password": PW, "client_id": CID})
check("signup accepted", s in (200, 201), f"{s} {str(b)[:120]}")
s, b = req("POST", f"{PUB}/api/auth/login", {"email": EMAIL, "password": PW, "app_client_id": CID})
check("login refused before email verification", s in (401, 403), f"{s} {b}")
link = wait_mail(EMAIL, n, r'href="([^"]*verify[^"]*)"')
check("verification email received", bool(link), (link or "")[:60])
if link:
    tok = urllib.parse.parse_qs(urllib.parse.urlparse(link).query).get("token", [""])[0]
    s, b = req("GET", f"{PUB}/auth/verify-email?token={urllib.parse.quote(tok)}")
    check("verification link accepted", s == 200, f"{s}")
s, b = req("POST", f"{PUB}/api/auth/login", {"email": EMAIL, "password": PW, "app_client_id": CID})
check("login after verification", s == 200 and isinstance(b, dict) and "access_token" in b, f"{s}")
AT = b.get("access_token") if isinstance(b, dict) else None
RT = b.get("refresh_token") if isinstance(b, dict) else None
if AT:
    c = jwt_claims(AT)
    check("access token claims", c.get("iss") == "http://auth.localhost:9000" and c.get("sub"), f"iss={c.get('iss')} aud={c.get('aud')} role={c.get('role')}")

# ── Userinfo ────────────────────────────────────────────────────────────────
s, b = req("GET", f"{PUB}/oauth/userinfo", token=AT)
check("userinfo (GET)", s == 200 and isinstance(b, dict) and b.get("email") == EMAIL, f"{s} {str(b)[:100]}")

# ── MFA enrol → confirm → login needs code → recovery code → disable ────────
s, b = req("POST", f"{PUB}/api/profile/mfa/enroll", {}, token=AT)
secret = (b or {}).get("secret") if isinstance(b, dict) else None
check("MFA enrol returns a secret", s == 200 and bool(secret), f"{s} keys={list(b.keys()) if isinstance(b, dict) else b}")
recovery = []
if secret:
    s, b = req("POST", f"{PUB}/api/profile/mfa/confirm", {"code": totp(secret)}, token=AT)
    recovery = (b or {}).get("recovery_codes", []) if isinstance(b, dict) else []
    check("MFA confirm", s == 200, f"{s} recovery_codes={len(recovery)}")
    s, b = req("POST", f"{PUB}/api/auth/login", {"email": EMAIL, "password": PW, "app_client_id": CID})
    check("login without code → mfa_required", s == 401 and "mfa" in str(b), f"{s} {b}")
    s, b = req("POST", f"{PUB}/api/auth/login", {"email": EMAIL, "password": PW, "app_client_id": CID, "mfa_code": "000000"})
    check("login with wrong code refused", s == 401, f"{s} {b}")
    s, b = req("POST", f"{PUB}/api/auth/login", {"email": EMAIL, "password": PW, "app_client_id": CID, "mfa_code": totp(secret)})
    check("login with TOTP", s == 200, f"{s}")
    if s == 200:
        AT = b["access_token"]
        check("amr carries mfa after TOTP login", "mfa" in str(jwt_claims(AT).get("amr")) or "otp" in str(jwt_claims(AT).get("amr")), f"amr={jwt_claims(AT).get('amr')}")
    if recovery:
        s, b = req("POST", f"{PUB}/api/auth/login", {"email": EMAIL, "password": PW, "app_client_id": CID, "mfa_code": recovery[0]})
        check("login with a recovery code", s == 200, f"{s}")
        s, b = req("POST", f"{PUB}/api/auth/login", {"email": EMAIL, "password": PW, "app_client_id": CID, "mfa_code": recovery[0]})
        check("recovery code is single-use", s == 401, f"{s}")
    s, b = req("POST", f"{PUB}/api/profile/mfa/disable", {}, token=AT)
    check("MFA disable without password+code refused", s in (400, 401), f"{s} {b}")
    s, b = req("POST", f"{PUB}/api/profile/mfa/disable", {"password": PW, "code": totp(secret, time.time() + 30)}, token=AT)
    check("MFA disable with password+code", s == 200, f"{s} {b}")

# ── Forgot / reset password ─────────────────────────────────────────────────
n = len(mails_to(EMAIL))
s, b = req("POST", f"{PUB}/api/auth/request-password-reset", {"email": EMAIL})
check("password-reset request accepted", s == 200, f"{s}")
s2, b2 = req("POST", f"{PUB}/api/auth/request-password-reset", {"email": "nobody-" + stamp + "@e2e.test"})
check("unknown email gets the same answer (no enumeration)", s2 == s and b2 == b, f"{s2} {b2}")
link = wait_mail(EMAIL, n, r'href="([^"]*reset[^"]*)"')
check("reset email received", bool(link), (link or "")[:60])
NEWPW = PW + "2"
if link:
    tok = urllib.parse.parse_qs(urllib.parse.urlparse(link).query).get("token", [""])[0]
    s, b = req("POST", f"{PUB}/api/auth/reset-password", {"token": tok, "password": NEWPW})
    check("password reset with emailed token", s == 200, f"{s} {b}")
    s, b = req("POST", f"{PUB}/api/auth/reset-password", {"token": tok, "password": NEWPW + "3"})
    check("reset token is single-use", s in (400, 401), f"{s} {b}")
    s, b = req("GET", f"{PUB}/oauth/userinfo", token=AT)
    check("old access token revoked after reset", s == 401, f"{s}")
    s, b = req("POST", f"{PUB}/api/auth/login", {"email": EMAIL, "password": PW, "app_client_id": CID})
    check("old password refused", s == 401, f"{s}")
    s, b = req("POST", f"{PUB}/api/auth/login", {"email": EMAIL, "password": NEWPW, "app_client_id": CID})
    check("new password works", s == 200, f"{s}")
    PW = NEWPW

# ── Magic link (requested by the app backend with its service token) ───────
s, b = req("POST", f"{PUB}/oauth/token", form={"grant_type": "client_credentials"}, basic=(CID, CSEC))
CC = b.get("access_token") if isinstance(b, dict) else None
check("client_credentials token", s == 200 and bool(CC), f"{s}")
n = len(mails_to(EMAIL))
s, b = req("POST", f"{ADM}/api/apps/{APPID}/service/magic-link", {"email": EMAIL}, token=CC)
check("magic link requested by the app (service token)", s in (200, 202), f"{s} {b}")
link = wait_mail(EMAIL, n, r'href="([^"]*token=[^"]*)"')
check("magic-link email received", bool(link), (link or "")[:70])
if link:
    tok = urllib.parse.parse_qs(urllib.parse.urlparse(link).query).get("token", [""])[0]
    s, b = req("POST", f"{PUB}/api/auth/magic-link/verify", {"token": tok})
    check("magic link verifies → tokens", s == 200 and isinstance(b, dict) and "access_token" in b, f"{s} {str(b)[:100]}")
    s, b = req("POST", f"{PUB}/api/auth/magic-link/verify", {"token": tok})
    check("magic link is single-use", s in (400, 401), f"{s}")
s, b = req("POST", f"{ADM}/api/apps/{int(APPID) + 100}/service/magic-link", {"email": EMAIL}, token=CC)
check("service token refused for another app id", s in (401, 403, 404), f"{s}")

# ── Lockout → admin unlock ─────────────────────────────────────────────────
codes = []
for i in range(7):
    s, b = req("POST", f"{PUB}/api/auth/login", {"email": EMAIL, "password": "wrong-" + str(i), "app_client_id": CID})
    codes.append(s)
s, b = req("POST", f"{PUB}/api/auth/login", {"email": EMAIL, "password": PW, "app_client_id": CID})
check("account locked after repeated failures (right password refused)", s == 403 and "lock" in str(b), f"failures={codes} then {s} {b}")
T = admin_token()
uid = jwt_claims(AT)["sub"] if AT else None
s, b = req("POST", f"{ADM}/api/admin/users/{uid}/unlock", {}, token=T)
check("admin unlock", s == 200, f"{s} {str(b)[:80]}")
s, b = req("POST", f"{PUB}/api/auth/login", {"email": EMAIL, "password": PW, "app_client_id": CID})
check("login works after unlock", s == 200, f"{s}")

open(f"{E}/carol.json", "w").write(json.dumps({"email": EMAIL, "password": PW, "user_id": uid}))
print(f"\n{sum(bool(ok) for _, ok in results)}/{len(results)} passed")
