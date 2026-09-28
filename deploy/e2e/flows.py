"""API-level functional flows against the local stack (stdlib only).

Each check prints PASS/FAIL with the observed status so the run doubles as a
record. Emails are read from the SMTP sink's mail/ directory.
"""
import base64, glob, hashlib, hmac, json, os, re, struct, sys, time, urllib.error, urllib.parse, urllib.request

E = os.path.dirname(os.path.abspath(__file__))
PUB, ADM = "http://127.0.0.1:8080", "http://127.0.0.1:8081"
env = dict(l.strip().split("=", 1) for l in open(f"{E}/demoapp.env") if "=" in l)
CID, CSEC, APPID = env["SOCRATE_CLIENT_ID"], env["SOCRATE_CLIENT_SECRET"], env["SOCRATE_APP_ID"]
results = []


def check(name, ok, detail=""):
    results.append((name, ok))
    print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}")


def req(method, url, body=None, token=None, form=None, basic=None, headers=None):
    h = dict(headers or {})
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        h["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    if token:
        h["Authorization"] = "Bearer " + token
    if basic:
        h["Authorization"] = "Basic " + base64.b64encode(f"{basic[0]}:{basic[1]}".encode()).decode()
    r = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            raw = resp.read()
            status = resp.status
    except urllib.error.HTTPError as e:
        raw, status = e.read(), e.code
    try:
        return status, json.loads(raw or b"null")
    except ValueError:
        return status, raw.decode(errors="replace")[:300]


def mails_to(addr):
    out = []
    for f in sorted(glob.glob(f"{E}/mail/*.eml")):
        m = open(f, encoding="utf-8", errors="replace").read()
        if re.search(rf"^To: .*{re.escape(addr)}", m, re.M):
            out.append(m)
    return out


def wait_mail(addr, n_before, pattern, timeout=15):
    t = time.time()
    while time.time() - t < timeout:
        ms = mails_to(addr)
        if len(ms) > n_before:
            m = re.search(pattern, ms[-1])
            if m:
                return urllib.parse.unquote(m.group(1).replace("&amp;", "&"))
        time.sleep(0.5)
    return None


def totp(secret, t=None):
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    ctr = struct.pack(">Q", int((t or time.time()) // 30))
    h = hmac.new(key, ctr, hashlib.sha1).digest()
    o = h[-1] & 0xF
    return f"{(struct.unpack('>I', h[o:o + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"


def jwt_claims(tok):
    p = tok.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))


def admin_token():
    pw = open(f"{E}/root-pw.txt").read().strip()
    s, b = req("POST", f"{ADM}/api/admin/login", {"email": "root@e2e.test", "password": pw})
    return b["access_token"]
