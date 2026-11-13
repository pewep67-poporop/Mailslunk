"""Comprehensive audit of the MailSleuth Python server (running on :8100)."""
import http.cookiejar, json, os, sys, time, urllib.request, urllib.error, uuid, hashlib

BASE = os.getenv("SMOKE_BASE", "http://127.0.0.1:8100")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
p = f = 0


def ok(name, cond, extra=""):
    global p, f
    if cond:
        p += 1
        print("  PASS  " + name)
    else:
        f += 1
        print("  FAIL  " + name + ((" :: " + str(extra)[:200]) if extra else ""))


cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
anon = urllib.request.build_opener()
csrf = ""


def call(path, data=None, headers=None, opener=None, method=None):
    req = urllib.request.Request(BASE + path, data=data, headers=headers or {}, method=method)
    o = opener or op
    try:
        with o.open(req, timeout=120) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def jcall(path, data=None, headers=None, opener=None, method=None):
    s, h, b = call(path, data, headers, opener, method)
    try:
        return s, h, json.loads(b)
    except Exception:
        return s, h, {}


# ---------- 1. structure / static ----------
print("\n[1] Cấu trúc dự án")
py = sorted(f for f in os.listdir(os.path.join(ROOT, "app")) if f.endswith(".py"))
loc = 0
for name in py:
    with open(os.path.join(ROOT, "app", name), encoding="utf-8") as fh:
        loc += sum(1 for _ in fh)
ui = 0
for name in ("app.js", "index.html", "app.css"):
    with open(os.path.join(ROOT, "public", name), encoding="utf-8") as fh:
        ui += sum(1 for _ in fh)
print(f"  app/*.py: {len(py)} module, {loc} dòng | public/*: {ui} dòng")
ok("module lõi đủ", all(m in py for m in ("main.py", "parsers.py", "bodies.py", "attachments.py",
   "authcheck.py", "headers.py", "routing.py", "urls.py", "ioc.py", "siem.py", "enrichment.py",
   "dns_real.py", "db.py", "auth.py", "report.py", "mapgen.py", "mapglot.py")))
req_txt = open(os.path.join(ROOT, "requirements.txt"), encoding="utf-8").read().lower()
needed = ["fastapi", "uvicorn", "bcrypt", "dnspython", "pyspf", "dkimpy", "geoip2", "oletools",
          "extract-msg", "python-multipart", "olefile", "requests"]
ok("requirements.txt có các gói cốt lõi", all(n in req_txt for n in needed),
   [n for n in needed if n not in req_txt])
ok("không còn TODO/FIXME trong app/", not any(
    tok in open(os.path.join(ROOT, "app", name), encoding="utf-8").read()
    for name in py for tok in ("TODO", "FIXME", "XXX")))

# ---------- 2. auth / security ----------
print("\n[2] Bảo mật")
s, h, b = call("/api/health")
ok("health 200", s == 200)
ok("security headers", h.get("x-content-type-options") == "nosniff" and h.get("referrer-policy") == "no-referrer",
   {k: v for k, v in h.items() if k.lower() in ("x-content-type-options", "referrer-policy")})

s, h, b = jcall("/api/profile", opener=anon)
ok("thiếu phiên -> 401 + mã lỗi phẳng", s == 401 and b.get("error") == "auth", (s, b))
s, h, b = jcall("/api/cases", opener=anon)
ok("lịch sử thiếu phiên -> 401 auth", s == 401 and b.get("error") == "auth", (s, b))
s, h, b = jcall("/api/nosuchroute", opener=anon)
ok("route lạ -> 404 not_found phẳng", s == 404 and b.get("error") == "not_found", (s, b))

s, h, b = jcall("/api/login", json.dumps({"user": "admin", "pass": "TestSmoke-123456"}).encode(),
                {"Content-Type": "application/json"})
# the server rate-limits login to 10/minute per IP: wait for the window if needed
tries = 0
while s == 429 and tries < 2:
    print("   (rate-limit đăng nhập — chờ 62s)")
    time.sleep(62)
    s, h, b = jcall("/api/login", json.dumps({"user": "admin", "pass": "TestSmoke-123456"}).encode(),
                    {"Content-Type": "application/json"})
    tries += 1
ok("login 200 + csrf + cookie", s == 200 and b.get("csrf") and "sid" in (h.get("set-cookie") or ""), (s, b))
csrf = b.get("csrf")
s, h, b = jcall("/api/me")
ok("/api/me 200", s == 200 and b.get("user") == "admin", (s, b))

# CSRF: POST with cookie but without x-csrf
s, h, b = jcall("/api/profile/avatar", b"x", {"Content-Type": "application/json"})
ok("POST thiếu x-csrf -> 403 csrf phẳng", s == 403 and b.get("error") == "csrf", (s, b))

# rate limit presence (runs LAST: it deliberately burns the login bucket)
RATE = []

# path traversal on the message endpoint
s, h, b = jcall("/api/case/..%2F..%2Fetc/message/0")
ok("path traversal bị chặn", s in (400, 404) and "etc" not in json.dumps(b), (s, b))

# ---------- 3. analyze + features ----------
print("\n[3] Phân tích & tính năng")
eml = (b"From: \"PayPal\" <support@paypa1-secure.com>\r\nTo: v@x.org\r\n"
       b"Return-Path: <bounce@evil-mailer.com>\r\nSubject: Verify\r\n"
       b"Received: from mail.evil-mailer.com (unknown [93.184.216.34]) by mx.test with ESMTP; Mon, 10 Nov 2026 10:00:00 +0000\r\n"
       b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n"
       b"--B\r\nContent-Type: text/html\r\n\r\n<p>verify now http://203.0.113.5/login.php</p>\r\n"
       b"--B\r\nContent-Type: application/octet-stream; name=\"eicar.bin\"\r\n"
       b"Content-Disposition: attachment; filename=\"eicar.bin\"\r\n\r\n"
       b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\r\n--B--\r\n")
bd = uuid.uuid4().hex
body = (f"--{bd}\r\nContent-Disposition: form-data; name=\"files\"; filename=\"a.eml\"\r\n"
        f"Content-Type: text/plain\r\n\r\n").encode() + eml + f"\r\n--{bd}--\r\n".encode()
s, h, b = jcall("/api/analyze", body, {"Content-Type": f"multipart/form-data; boundary={bd}", "X-CSRF": csrf})
r = (b.get("results") or [{}])[0]
ok("analyze 200 + verdict", s == 200 and r.get("verdict") == "malicious_or_phishing", (s, r.get("verdict")))
ok("có findings/attachments/urls/ioc", r.get("findings") and r.get("attachments") and r.get("urls") and r.get("ioc"))
ok("có headerAnalysis/routing/auth/dns/ipInfo", all(k in r for k in ("headerAnalysis", "routing", "auth", "dns", "ipInfo")))
ok("có IOC file (attachment sha256)", any(i.get("type") == "file" for i in (r.get("ioc") or {}).get("iocs", [])))
cid = (r.get("custody") or {}).get("caseId")

# body preview of the message (M8)
s, h, b = jcall(f"/api/case/{cid}/message/0")
ok("M8 body thư: 200 + text/html", s == 200 and b.get("hasHtml") and b.get("hasText"), (s, b))
ok("M8 body không chứa script", "<script" not in (b.get("html") or "").lower())

# reports + exports
for q, label in (("", "báo cáo HTML"), ("?format=json", "JSON"), ("?format=csv", "CSV")):
    s, h, b = call(f"/api/report/{cid}{q}")
    ok(label + " 200", s == 200 and len(b) > 50, (s, len(b)))
s, h, b = call(f"/api/ioc/{cid}")
ok("IOC JSON 200", s == 200)
s, h, b = call(f"/api/ioc/{cid}.csv")
ok("IOC CSV 200", s == 200 and b"type" in b.lower())
s, h, b = call(f"/api/ioc/{cid}?format=stix")
ok("IOC STIX 200", s == 200 and b"stix" in b.lower() or s == 200)
for fmt in ("cef", "syslog", "ecs", "elastic", "splunk"):
    s, h, b = call(f"/api/export/{cid}?format={fmt}")
    ok("export SIEM " + fmt, s == 200 and len(b) > 20, (s, len(b)))
s, h, b = jcall("/api/cases?q=a.eml")
ok("lịch sử có case", s == 200 and any(c["id"] == cid for c in b.get("cases", [])))

# ---------- 4. tools ----------
print("\n[4] Công cụ tra cứu")
s, h, b = jcall("/api/dns", json.dumps({"domain": "example.com"}).encode(),
                {"Content-Type": "application/json", "X-CSRF": csrf})
ok("/api/dns 200", s == 200, (s, b))
s, h, b = jcall("/api/ip", json.dumps({"ip": "93.184.216.34"}).encode(),
                {"Content-Type": "application/json", "X-CSRF": csrf})
ok("/api/ip 200", s == 200, (s, b))
s, h, b = jcall("/api/map?ips=93.184.216.34")
ok("/api/map 200 (theo ips)", s == 200, (s, b if isinstance(b, dict) else len(b)))
s, h, b = jcall("/api/map")
ok("/api/map thiếu ips -> 400 ips", s == 400 and b.get("error") == "ips", (s, b))
s, h, b = jcall("/api/settings/map")
ok("/api/settings/map 200", s == 200, (s, b))
s, h, b = jcall("/api/admin/logs")
ok("/api/admin/logs (admin) 200", s == 200, (s, b))
s, h, b = jcall("/api/admin/sessions")
ok("/api/admin/sessions (admin) 200", s == 200, (s, b))

# ---------- 5. storage on disk ----------
print("\n[5] Lưu trữ trên đĩa")
data = os.path.join(ROOT, os.getenv("DATA_DIR", "./data").replace("./", ""))
ev = os.path.join(data, "evidence", cid + ".bin")
ok("evidence gốc được lưu", os.path.exists(ev), ev)
if os.path.exists(ev):
    ok("sha256 evidence khớp", hashlib.sha256(open(ev, "rb").read()).hexdigest() == (r.get("custody") or {}).get("sha256"))
msgs = os.path.join(data, "messages", cid)
ok("body thư lưu rời (M8)", os.path.isdir(msgs) and os.path.exists(os.path.join(msgs, "0.json")),
   os.listdir(msgs) if os.path.isdir(msgs) else "missing")
q = os.path.join(data, "quarantine")
ok("attachment độc hại bị cách ly", os.path.isdir(q) and len(os.listdir(q)) >= 1, os.listdir(q) if os.path.isdir(q) else "-")

print(f"\n{p}/{p + f} PASS  (audit)")

# ---- rate limit check LAST (burns the login bucket for this IP) ----
for i in range(12):
    s, h, b = jcall("/api/login", json.dumps({"user": "admin", "pass": "wrong"}).encode(),
                    {"Content-Type": "application/json"}, opener=anon)
    RATE.append(s)
ok("rate-limit login (10/phút)", 429 in RATE, RATE)
print(f"{p}/{p + f} PASS  (audit + rate-limit)")
sys.exit(1 if f else 0)
