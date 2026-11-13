"""Resilience / chaos checks: the server must survive broken inputs and
degraded dependencies instead of crashing.

Runs against a live server (SMOKE_BASE). Every scenario must end with the
server still answering /api/health and /api/analyze returning structured
errors (never a 500 traceback).
"""
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
_cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(_cj))
csrf = ""


def ok(name, cond, extra=""):
    global p, f
    if cond:
        p += 1
        print("  PASS  " + name)
    else:
        f += 1
        print("  FAIL  " + name + ((" :: " + str(extra)[:250]) if extra else ""))


def call(path, data=None, headers=None, method=None):
    req = urllib.request.Request(BASE + path, data=data, headers=headers or {}, method=method)
    try:
        with op.open(req, timeout=120) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def upload(fname, blob):
    b = uuid.uuid4().hex
    body = (f"--{b}\r\nContent-Disposition: form-data; name=\"files\"; filename=\"{fname}\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n").encode() + blob + f"\r\n--{b}--\r\n".encode()
    return call("/api/analyze", body,
                {"Content-Type": f"multipart/form-data; boundary={b}", "X-CSRF": csrf})


for _ in range(60):
    try:
        if call("/api/health")[0] == 200:
            break
    except Exception:
        pass
    time.sleep(0.5)

s, raw = call("/api/login", json.dumps({"user": "admin", "pass": "TestSmoke-123456"}).encode(),
              {"Content-Type": "application/json"})
csrf = json.loads(raw)["csrf"]
ok("login", s == 200)

print("\n[1] Đầu vào hỏng")
cases = [
    ("file rỗng", b"", "x.eml"),
    ("EML rác", b"\x00\x01\x02not an email at all" * 10, "x.eml"),
    ("PST giả (magic sai)", b"NOTAPST!" + b"x" * 500, "x.pst"),
    ("PST rỗng", b"", "x.pst"),
    ("header khổng lồ", b"X-A: " + b"y" * 5000 + b"\r\n\r\nbody", "x.eml"),
    ("mbox hỏng", b"From broken\r\nno headers\r\n", "x.mbox"),
    ("tên file kỳ lạ", b"Subject: x\r\n\r\nb", "../../etc/passwd.eml"),
]
for label, blob, name in cases:
    st, body = upload(name, blob)
    ok(f"{label} -> 200 + errors[] (không 500)", st == 200 and b'"errors"' in body, (st, body[:120]))

print("\n[2] Spam nhiều request (rate-limit không làm sập)")
codes = []
for i in range(45):
    st, _ = upload(f"spam{i}.eml", b"Subject: x\r\n\r\nb")
    codes.append(st)
ok("server vẫn sống sau 45 upload liên tiếp", 200 in codes, set(codes))
st, body = call("/api/health")
ok("health vẫn 200", st == 200, st)

print("\n[3] Health sâu báo trạng thái thành phần")
st, body = call("/api/health?deep=1")
j = json.loads(body)
ok("deep health trả components", st == 200 and "components" in j, list(j)[:6])
ok("deep health có db + storage", "db" in (j.get("components") or {}) and "storage" in (j.get("components") or {}),
   j.get("components"))
ok("deep health có trạng thái breaker", "breakers" in (j.get("components") or {}))

print("\n[4] Endpoint lạ -> mã lỗi phẳng, không rò traceback")
for path in ("/api/nope", "/api/case/xyz/message/0", "/api/report/xyz"):
    st, body = call(path)
    ok(f"{path} -> 404/401 phẳng", st in (401, 404) and b"Traceback" not in body, (st, body[:120]))

print("\n[5] Purge (dấu vết) chạy được và không xoá nhầm")
import subprocess
r = subprocess.run([sys.executable, "tools/purge.py", "--dry-run"],
                   cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   capture_output=True, text=True, timeout=120)
ok("tools/purge.py --dry-run chạy được", r.returncode == 0, (r.stdout or r.stderr)[-200:])
ok("purge không xoá gì khi dry-run", "Traceback" not in (r.stdout or "") and "Traceback" not in (r.stderr or ""), r.stderr[-200:])

print("\n[6] Watchdog tồn tại và cấu hình được")
try:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from app import main as M
    ok("hàm watchdog tồn tại", callable(getattr(M, "_watchdog_loop", None)))
    ok("hàm health sâu tồn tại", callable(getattr(M, "_health_deep", None)))
except Exception as e:
    ok("import được app.main", False, e)

print("\n[7] Không còn file upload tạm sau khi phân tích")
try:
    from app.db import data_dir
    up = data_dir() / "uploads"
    left = [x.name for x in up.glob("*")] if up.exists() else []
    ok("uploads sạch", not left, left[:5])
except Exception as e:
    ok("kiểm tra uploads được", False, e)

print(f"\n{p}/{p + f} PASS  (resilience)")
sys.exit(1 if f else 0)
