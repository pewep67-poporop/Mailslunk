"""End-to-end check for the PST port (server on 127.0.0.1:8100)."""
import http.cookiejar, json, os, sys, time, urllib.request, urllib.error, uuid

BASE = "http://127.0.0.1:8100"
USER, PASS = "admin", "TestSmoke-123456"
ROOT = os.path.dirname(os.path.abspath(__file__))
PST = os.path.join(ROOT, "sample.pst")
STUB = os.path.join(ROOT, "pstbin", "readpst.cmd")

if not os.path.exists(PST):  # synthetic PST/OST container: magic "!BDN" + filler
    with open(PST, "wb") as fh:
        fh.write(b"!BDN" + os.urandom(8192))

cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
passed = failed = 0
csrf = ""


def check(name, cond, extra=""):
    global passed, failed
    if cond:
        passed += 1
        print("PASS", name)
    else:
        failed += 1
        print("FAIL", name, extra)


def call(path, data=None, headers=None, method=None):
    req = urllib.request.Request(BASE + path, data=data, headers=headers or {}, method=method)
    try:
        with op.open(req, timeout=180) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def post_json(path, obj):
    return call(path, json.dumps(obj).encode(), {"Content-Type": "application/json"})


def upload(fname, blob):
    b = uuid.uuid4().hex
    body = (
        f"--{b}\r\nContent-Disposition: form-data; name=\"files\"; filename=\"{fname}\"\r\n"
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + blob + f"\r\n--{b}--\r\n".encode()
    return call("/api/analyze", body,
                {"Content-Type": f"multipart/form-data; boundary={b}", "X-CSRF": csrf})


# wait for the server
for _ in range(60):
    try:
        s, _, raw = call("/api/health")
        if s == 200:
            break
    except Exception:
        pass
    time.sleep(0.5)
else:
    sys.exit("server not up")

s, _, raw = post_json("/api/login", {"user": USER, "pass": PASS})
check("login", s == 200, raw[:200])
csrf = json.loads(raw)["csrf"]

blob = open(PST, "rb").read()
s, _, raw = upload("sample.pst", blob)
j = json.loads(raw)
check("analyze status", s == 200, raw[:300])
check("no per-file errors", j.get("errors") == [], j.get("errors"))
r = (j.get("results") or [{}])[0]
check("format=pst", r.get("format") == "pst", r.get("format"))
check("count=4 (recursive walk)", r.get("count") == 4, r.get("count"))
check("truncated=false", r.get("truncated") is False, r.get("truncated"))
check("verdict malicious", r.get("verdict") == "malicious_or_phishing", r.get("verdict"))
check("score numeric", isinstance(r.get("score"), int), r.get("score"))
check("messages 4", len(r.get("messages") or []) == 4, len(r.get("messages") or []))
check("messages have score/verdict", all("score" in m and "verdict" in m for m in r["messages"]))
check("findings present", len(r.get("findings") or []) > 0, len(r.get("findings") or []))
check("findings carry m", all("m" in f for f in r["findings"]))
atts = r.get("attachments") or []
att = next((a for a in atts if a.get("name") == "invoice.pdf.exe"), None)
check("attachment extracted", att is not None, [a.get("name") for a in atts])
check("attachment flagged", att and att.get("verdict") in ("malicious", "suspicious"), att and att.get("verdict"))
check("attachment sha256", att and len(att.get("sha256") or "") == 64)
urgent = next((i for i, m in enumerate(r["messages"]) if "URGENT" in (m.get("subject") or "")), -1)
check("urgent message present", urgent >= 0, urgent)
check("attachment m = message idx", att and att.get("m") == urgent, (att or {}).get("m"))
urls = r.get("urls") or []
check("link extracted", any(u.get("host") == "203.0.113.7" for u in urls), [u.get("host") for u in urls])
ips = r.get("originIPs") or []
for ip in ("8.8.8.8", "93.184.216.34", "93.184.216.35"):
    check("origin ip " + ip, ip in ips, ips)
check("headerAnalysis from worst", (r.get("headerAnalysis") or {}).get("fromDomain") == "paypa1-secure.example",
      (r.get("headerAnalysis") or {}).get("fromDomain"))
check("auth shape", all(k in (r.get("auth") or {}) for k in ("spf", "dkim", "dmarc", "authSeen")))
check("custody original", (r.get("custody") or {}).get("original") == "sample.pst")
check("custody sha", (r.get("custody") or {}).get("sha256") == __import__("hashlib").sha256(blob).hexdigest())
iocs = (r.get("ioc") or {}).get("iocs") or []
types = {x.get("type") for x in iocs}
check("ioc has url/ip/file", {"url", "ip", "file"}.issubset(types), sorted(types))

case_id = (r.get("custody") or {}).get("caseId")
s, _, raw = call("/api/cases?q=sample.pst")
check("case listed", s == 200 and any(c["id"] == case_id for c in json.loads(raw)["cases"]), raw[:200])
s, _, raw = call(f"/api/report/{case_id}")
check("report includes attachment", s == 200 and b"invoice.pdf.exe" in raw)

# MBOX regression (mailbox.mbox needs a real path; was broken before)
mbox = (
    b"From a@b.c Mon Jan  1 00:00:00 2026\nFrom: A <a@b.c>\nSubject: one\n"
    b"Date: Mon, 1 Jan 2026 00:00:00 +0000\nReceived: from x (x [8.8.4.4]) by y\n\n"
    b"body one\n\n"
    b"From c@d.e Mon Jan  1 00:00:01 2026\nFrom: C <c@d.e>\nSubject: two\n"
    b"Date: Mon, 1 Jan 2026 00:00:01 +0000\n\nbody two\n\n"
)
s, _, raw = upload("sample.mbox", mbox)
j = json.loads(raw)
r2 = (j.get("results") or [{}])[0]
check("mbox format/count", s == 200 and r2.get("format") == "mbox" and r2.get("count") == 2, raw[:300])
check("mbox keeps both subjects", [m.get("subject") for m in (r2.get("messages") or [])] == ["one", "two"],
      r2.get("messages"))
s, _, raw = call(f"/api/case/{r2['custody']['caseId']}/message/0")
mj = json.loads(raw)
check("mbox body stored", s == 200 and "body one" in (mj.get("text") or ""), raw[:200])

# message bodies of a PST case (M8)
s, _, raw = call(f"/api/case/{case_id}/message/{urgent}")
mj = json.loads(raw)
check("pst message body 200", s == 200 and mj.get("index") == urgent, raw[:200])
check("pst body has html+text", mj.get("hasHtml") and mj.get("hasText"), raw[:200])
check("pst body text from html", "invoice" in (mj.get("text") or "").lower(), (mj.get("text") or "")[:120])
check("pst body html sanitised", "<script" not in (mj.get("html") or "").lower()
      and "onclick" not in (mj.get("html") or "").lower(), (mj.get("html") or "")[:120])
s, _, raw = call(f"/api/case/{case_id}/message/999")
check("pst message index out of range -> 404", s == 404, str(s))
try:  # no cookie jar -> must be rejected
    req = urllib.request.Request(BASE + f"/api/case/{case_id}/message/0")
    with urllib.request.build_opener().open(req, timeout=30) as rr:
        s = rr.status
except urllib.error.HTTPError as e:
    s = e.code
check("pst message endpoint needs auth -> 401", s == 401, str(s))

# format mismatch: .pst that does not start with !BDN
s, _, raw = upload("fake.pst", b"not a pst at all" * 10)
j = json.loads(raw)
check("format_mismatch", s == 200 and j.get("errors", [{}])[0].get("error") == "format_mismatch", raw[:200])

# readpst missing: hide the stub while the server keeps its PATH
os.rename(STUB, STUB + ".bak")
try:
    s, _, raw = upload("sample.pst", blob)
    j = json.loads(raw)
    check("readpst_missing", s == 200 and j.get("errors", [{}])[0].get("error") == "readpst_missing", raw[:200])
finally:
    os.rename(STUB + ".bak", STUB)

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
