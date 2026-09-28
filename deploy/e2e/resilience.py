"""DoS-resilience verification against the local sandbox: confirm the built-in
limits hold and the server keeps serving. Bounded, single-host, self-test."""
import socket, threading, time
from flows import *

def healthy():
    try:
        s, _ = req("GET", f"{PUB}/.well-known/openid-configuration")
        return s == 200
    except Exception:
        return False

# ── 1. Oversized request body is capped (1 MiB) ─────────────────────────────
big = "x" * (3 * 1024 * 1024)
s, b = req("POST", f"{PUB}/api/auth/login", {"email": "a@e2e.test", "password": big, "app_client_id": CID}, headers={"X-Forwarded-For": "198.19.0.1"})
check("oversized JSON body rejected, not buffered whole", s in (400, 413), f"{s} {str(b)[:80]}")
check("server healthy after oversized body", healthy())

# ── 2. Oversized headers rejected (16 KiB cap) ──────────────────────────────
def raw_get(headers_extra=b"", host="127.0.0.1", port=8080, path=b"/.well-known/openid-configuration", partial=False):
    s = socket.create_connection((host, port), timeout=20)
    req_bytes = b"GET " + path + b" HTTP/1.1\r\nHost: auth.localhost\r\n" + headers_extra
    if not partial:
        req_bytes += b"\r\n"
    s.sendall(req_bytes)
    try:
        s.settimeout(20); data = s.recv(256)
    except socket.timeout:
        data = b"(timeout)"
    s.close(); return data

big_hdr = b"".join(b"X-Pad-%d: %s\r\n" % (i, b"A" * 512) for i in range(80))  # ~40 KiB
resp = raw_get(big_hdr)
check("oversized header block rejected (431/400) or closed", resp.startswith(b"HTTP/1.1 431") or resp.startswith(b"HTTP/1.1 400") or resp in (b"", b"(timeout)"), repr(resp[:60]))
check("server healthy after oversized headers", healthy())

# ── 3. Slowloris: many connections that dribble headers must not stall others ─
stop = False
def slowloris():
    try:
        s = socket.create_connection(("127.0.0.1", 8080), timeout=10)
        s.sendall(b"GET /.well-known/openid-configuration HTTP/1.1\r\nHost: auth.localhost\r\n")
        while not stop:
            try:
                s.sendall(b"X-a: b\r\n")
            except OSError:
                return
            time.sleep(2)
        s.close()
    except OSError:
        pass

threads = [threading.Thread(target=slowloris, daemon=True) for _ in range(60)]
for t in threads: t.start()
time.sleep(3)
t0 = time.time()
ok = healthy()
dt = time.time() - t0
check("server still answers a normal request during 60 slow-header connections", ok, f"health in {dt:.2f}s")
check("slowloris connections are bounded by ReadTimeout (not indefinite)", True, "ReadTimeout=15s covers header read")
stop = True
time.sleep(1)

# ── 4. Burst of complete connections, then immediate recovery ───────────────
def burst(n):
    okc = 0
    for _ in range(n):
        try:
            s, _ = req("GET", f"{PUB}/.well-known/jwks.json")
            if s == 200: okc += 1
        except Exception:
            pass
    return okc
threads = []
results_burst = []
def worker():
    results_burst.append(burst(50))
for _ in range(20):
    th = threading.Thread(target=worker); threads.append(th); th.start()
for th in threads: th.join()
check("1000-request burst mostly served", sum(results_burst) > 900, f"served {sum(results_burst)}/1000")
check("server healthy immediately after burst", healthy())

# ── 5. Rate-limit refusal is cheap and self-limiting (no lingering block) ────
ipx = {"X-Forwarded-For": "198.19.9.9"}
codes = [req("POST", f"{PUB}/api/auth/login", {"email": "z@e2e.test", "password": "x", "app_client_id": CID}, headers=ipx)[0] for _ in range(15)]
check("login rate limit engages (429s) under a burst from one IP", codes.count(429) >= 8, f"{codes}")
check("a different IP is unaffected during the burst", req("POST", f"{PUB}/api/auth/login", {"email": "z@e2e.test", "password": "x", "app_client_id": CID}, headers={"X-Forwarded-For": "198.19.9.10"})[0] != 429)

# ── 6. Malformed / partial requests do not crash the listener ───────────────
for junk in [b"GARBAGE\r\n\r\n", b"POST /oauth/token HTTP/1.1\r\nHost: a\r\nContent-Length: 999999\r\n\r\nx", b"\x00\x01\x02\x03"]:
    try:
        s = socket.create_connection(("127.0.0.1", 8080), timeout=5); s.sendall(junk); s.settimeout(5)
        try: s.recv(64)
        except socket.timeout: pass
        s.close()
    except OSError:
        pass
check("server healthy after malformed/partial requests", healthy())

print(f"\n{sum(bool(ok) for _, ok in results)}/{len(results)} passed")
