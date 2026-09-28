"""Trigger every defensive mechanism and record its effect.

Attackers are simulated as distinct client IPs via X-Forwarded-For sent from
loopback — the server trusts it from 127.0.0.1 exactly as it does from Caddy.
"""
import subprocess
from flows import *

def as_ip(ip):
    return {"X-Forwarded-For": ip}

def events(since_id, types=None):
    q = f"select event_type, coalesce(ip_address,''), count(*) from security_audit_logs where id > {since_id}"
    if types:
        q += " and event_type in (" + ",".join(f"'{t}'" for t in types) + ")"
    q += " group by 1,2 order by 1,2"
    out = subprocess.run(["psql", "-h", "127.0.0.1", "-U", "postgres", "-d", "socrate_e2e", "-tAc", q], capture_output=True, text=True).stdout
    return [l.split("|") for l in out.strip().splitlines() if l]

def max_event_id():
    out = subprocess.run(["psql", "-h", "127.0.0.1", "-U", "postgres", "-d", "socrate_e2e", "-tAc", "select coalesce(max(id),0) from security_audit_logs"], capture_output=True, text=True).stdout
    return int(out.strip() or 0)

carol = json.load(open(f"{E}/carol.json"))
start = max_event_id()
T = admin_token()
print(f"events before: max id {start}")

# ── 1. Rate limit on login (5/min per IP) ───────────────────────────────────
IP1 = "198.51.100.11"
codes = [req("POST", f"{PUB}/api/auth/login", {"email": "ghost@e2e.test", "password": "x", "app_client_id": CID}, headers=as_ip(IP1))[0] for _ in range(8)]
check("login rate limit per IP → 429 after 5", codes[:5].count(429) == 0 and codes[5:].count(429) == 3, f"{codes}")
s, _ = req("POST", f"{PUB}/api/auth/login", {"email": "ghost@e2e.test", "password": "x", "app_client_id": CID}, headers=as_ip("198.51.100.12"))
check("another IP is not affected", s != 429, f"{s}")

# ── 2. Account lockout (5 wrong passwords, spread over IPs so rate limits don't mask it) ─
codes = []
for i in range(6):
    codes.append(req("POST", f"{PUB}/api/auth/login", {"email": carol["email"], "password": f"wrong{i}", "app_client_id": CID}, headers=as_ip(f"198.51.100.{20 + i}"))[0])
s, b = req("POST", f"{PUB}/api/auth/login", {"email": carol["email"], "password": carol["password"], "app_client_id": CID}, headers=as_ip("198.51.100.30"))
check("account locked after 5 failures (from 6 different IPs)", s == 403 and "lock" in str(b), f"{codes} → {s} {b}")

# ── 3. Auto-defense IP block (10 failures from one IP within 10 min) ────────
ATT = "203.0.113.66"
codes = []
t0 = time.time()
while len(codes) < 12 and time.time() - t0 < 200:
    s, b = req("POST", f"{PUB}/api/auth/login", {"email": f"victim{len(codes)}@e2e.test", "password": "guess", "app_client_id": CID}, headers=as_ip(ATT))
    if s == 429:
        time.sleep(13)       # respect the 5/min budget so the failures actually count
        continue
    codes.append(s)
    if s == 403:
        break
s, b = req("GET", f"{PUB}/.well-known/openid-configuration", headers=as_ip(ATT))
check("auto-defense blocks the attacking IP", s == 403, f"failures={codes} then discovery from {ATT} → {s} {str(b)[:80]}")
s, b = req("GET", f"{PUB}/.well-known/openid-configuration", headers=as_ip("203.0.113.67"))
check("neighbouring IP not blocked", s == 200, f"{s}")
s, b = req("GET", f"{ADM}/api/admin/security/blocked-ips", token=T)
auto = [x for x in (b.get("blocked_ips") or b.get("items") or b if isinstance(b, dict) else b) if isinstance(x, dict) and x.get("ip_address") == ATT]
check("auto block listed in admin API", bool(auto), json.dumps(auto)[:200])

# ── 4. Manual IP block ─────────────────────────────────────────────────────
MAN = "192.0.2.77"
s, b = req("POST", f"{ADM}/api/admin/security/blocked-ips", {"ip_address": MAN, "reason": "e2e manual", "duration_hours": 1}, token=T)
mid = b.get("id") if isinstance(b, dict) else None
time.sleep(2)
s2, _ = req("GET", f"{PUB}/.well-known/openid-configuration", headers=as_ip(MAN))
check("manually blocked IP refused", s in (200, 201) and s2 == 403, f"block={s} then request → {s2}")

# ── 5. Invalid / forged tokens ─────────────────────────────────────────────
forged = AT = None
s, b = req("POST", f"{PUB}/api/auth/login", {"email": "alice@e2e.test", "password": open(f"{E}/alice-pw.txt").read().strip(), "app_client_id": CID}, headers=as_ip("198.51.100.40"))
if s == 200:
    AT = b["access_token"]; h, p, sig = AT.split(".")
    forged = h + "." + p + "." + sig[:-4] + ("AAAA" if not sig.endswith("AAAA") else "BBBB")
codes = [req("GET", f"{PUB}/oauth/userinfo", token=forged, headers=as_ip("198.51.100.41"))[0] for _ in range(3)]
check("forged signature refused", codes == [401, 401, 401], f"{codes}")
none_alg = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode() + "." + AT.split(".")[1] + "."
s, _ = req("GET", f"{PUB}/oauth/userinfo", token=none_alg, headers=as_ip("198.51.100.41"))
check("alg=none token refused", s == 401, f"{s}")

# ── 6. Client authentication failures ──────────────────────────────────────
codes = [req("POST", f"{PUB}/oauth/token", form={"grant_type": "client_credentials"}, basic=(CID, "wrong"), headers=as_ip("198.51.100.50"))[0] for _ in range(3)]
check("bad client secret refused", codes == [401, 401, 401], f"{codes}")

# ── 7. Policy enforce denial (non-admin on invoice.approve via decide API) ──
s, b = req("POST", f"{PUB}/oauth/token", form={"grant_type": "client_credentials"}, basic=(CID, CSEC))
CC = b.get("access_token")
s, b = req("POST", f"{ADM}/api/apps/{APPID}/service/policy/decide", {"subject": {"user_id": 3}, "action": "invoice.approve", "resource": {"type": "invoice", "id": "x"}}, token=CC)
check("policy decide in enforce → deny", s == 200 and b.get("allow") is False and b.get("mode") == "enforce", f"{s} {b}")

# ── Unlock Carol so later tests can use her; remove the manual block ───────
req("POST", f"{ADM}/api/admin/users/{carol['user_id']}/unlock", {}, token=T)
if mid:
    req("DELETE", f"{ADM}/api/admin/security/blocked-ips/{mid}", token=T)

print("\nsecurity events recorded during this run:")
for t, ip, n in events(start):
    print(f"   {t:28s} {ip:16s} {n}")
json.dump({"since": start, "attacker": ATT, "manual": MAN}, open(f"{E}/defenses.json", "w"))
print(f"\n{sum(bool(ok) for _, ok in results)}/{len(results)} passed")
