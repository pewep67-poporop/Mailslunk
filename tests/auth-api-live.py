"""End-to-end check of M2 (SPF/DKIM/DMARC) through the API with LIVE_DNS=1."""
import json
import os
import sys
import time
import http.cookiejar
import urllib.request
import urllib.error
import uuid

BASE = os.getenv("SMOKE_BASE", "http://127.0.0.1:8100")
p = f = 0
csrf = ""
_cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(_cj))


def ok(name, cond, extra=""):
    global p, f
    if cond:
        p += 1
        print("  PASS  " + name)
    else:
        f += 1
        print("  FAIL  " + name + ((" :: " + str(extra)[:300]) if extra else ""))


def call(path, data=None, headers=None):
    req = urllib.request.Request(BASE + path, data=data, headers=headers or {})
    try:
        with op.open(req, timeout=180) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def post_json(path, obj):
    return call(path, json.dumps(obj).encode(), {"Content-Type": "application/json"})


def upload(fname, blob):
    b = uuid.uuid4().hex
    body = (f"--{b}\r\nContent-Disposition: form-data; name=\"files\"; filename=\"{fname}\"\r\n"
            f"Content-Type: message/rfc822\r\n\r\n").encode() + blob + f"\r\n--{b}--\r\n".encode()
    return call("/api/analyze", body,
                {"Content-Type": f"multipart/form-data; boundary={b}", "X-CSRF": csrf})


for _ in range(60):
    try:
        if call("/api/health")[0] == 200:
            break
    except Exception:
        pass
    time.sleep(0.5)

s, raw = post_json("/api/login", {"user": "admin", "pass": "TestSmoke-123456"})
csrf = json.loads(raw)["csrf"]
ok("login", s == 200)

# A message that looks like it came from Gmail (real SPF + DMARC records exist)
gmail = (b"Return-Path: <bounce@gmail.com>\r\n"
         b"Received: from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41])\r\n"
         b" by mx.local with ESMTP id a1; Mon, 10 Nov 2026 10:00:00 +0000\r\n"
         b"From: Alice <alice@gmail.com>\r\nTo: bob@example.org\r\nSubject: hi\r\n\r\nhello\r\n")

t0 = time.time()
s, raw = upload("gmail.eml", gmail)
dt = time.time() - t0
j = json.loads(raw)
r = (j.get("results") or [{}])[0]
auth = r.get("auth") or {}
ok("analyze 200 (LIVE_DNS=1)", s == 200 and not j.get("errors"), j.get("errors"))
ok("SPF = pass (DNS thật)", auth.get("spf", {}).get("result") == "pass", auth.get("spf"))
ok("SPF client IP đúng", auth.get("spf", {}).get("clientIp") == "209.85.220.41", auth.get("spf"))
ok("SPF domain = MAIL FROM", auth.get("spf", {}).get("domain") == "gmail.com", auth.get("spf"))
ok("SPF record hiển thị", "v=spf1" in (auth.get("spf", {}).get("record") or ""), auth.get("spf", {}).get("record"))
ok("DMARC = pass", auth.get("dmarc", {}).get("result") == "pass", auth.get("dmarc"))
ok("DMARC policy đọc đúng (gmail.com: p=none, sp=quarantine)",
   auth.get("dmarc", {}).get("policy") == "none" and auth.get("dmarc", {}).get("subdomainPolicy") == "quarantine",
   auth.get("dmarc"))
ok("DMARC record hiển thị", "v=DMARC1" in (auth.get("dmarc", {}).get("record") or ""), auth.get("dmarc", {}).get("record"))
ok("alignment spf/dkim có giá trị", auth.get("alignment", {}).get("spf") is True, auth.get("alignment"))
ok("authSeen = True", auth.get("authSeen") is True)
ok("authservId/overall có trong kết quả", "overall" in auth, list(auth.keys()))
ok("thời gian phân tích hợp lý (< 20s)", dt < 20, "%.1fs" % dt)

# A message whose From does not align with the SPF-authenticated domain
spoof = gmail.replace(b"alice@gmail.com", b"alice@google.com").replace(
    b"Subject: hi", b"Subject: hi\r\nAuthentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass")
s, raw = upload("spoof.eml", spoof)
j = json.loads(raw)
r2 = (j.get("results") or [{}])[0]
a2 = r2.get("auth") or {}
ok("DMARC fail khi From lệch SPF", a2.get("dmarc", {}).get("result") == "fail", a2.get("dmarc"))
ok("upstream Authentication-Results được đọc",
   (a2.get("upstream") or {}).get("spf") == "pass", a2.get("upstream"))
ok("authservId lấy từ header", a2.get("authservId") == "mx.google.com", a2.get("authservId"))
ok("có finding dmarc_fail", any(f.get("type") == "dmarc_fail" for f in r2.get("findings", [])),
   [f.get("type") for f in r2.get("findings", [])])

# second identical upload -> DNS cache phải làm nhanh hơn
t0 = time.time()
upload("gmail2.eml", gmail)
dt2 = time.time() - t0
ok("lần thứ hai nhanh hơn (DNS cache)", dt2 <= dt + 0.5, "%.2fs vs %.2fs" % (dt2, dt))

# report hiển thị kết quả auth
cid = (r.get("custody") or {}).get("caseId")
s, raw = call(f"/api/report/{cid}")
ok("báo cáo có dòng SPF/DKIM/DMARC", b"SPF" in raw and b"DMARC" in raw)
s, raw = call(f"/api/report/{cid}?format=csv")
ok("CSV có cột spf/dkim/dmarc", b"spf_result" in raw and b"dmarc_policy" in raw)

print(f"\n{p}/{p + f} PASS  (M2 API, LIVE_DNS=1)")
sys.exit(1 if f else 0)
