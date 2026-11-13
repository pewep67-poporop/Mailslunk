"""Leak / data-hygiene audit — what must never leave the machine or stay on disk.

Checks
  1. no secrets hard-coded in the repository
  2. the audit log never contains raw mail content (only metadata)
  3. the case JSON stored in SQLite carries no raw body
  4. evidence / quarantine / message bodies have restrictive permissions
  5. the LLM payload is redacted before it leaves the process
  6. upload staging files are removed after every analyze
"""
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

p = f = 0


def ok(name, cond, extra=""):
    global p, f
    if cond:
        p += 1
        print("  PASS  " + name)
    else:
        f += 1
        print("  FAIL  " + name + ((" :: " + str(extra)[:220]) if extra else ""))


SECRET_PATTERNS = [
    (re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"), "hard-coded secret"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "openai-style key"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "aws key"),
]

print("[1] Không có secret hard-code trong mã nguồn")
skip_dirs = {".git", "__pycache__", "node_modules", "data", "datasets", ".venv"}
hits = []
for path in ROOT.rglob("*"):
    if not path.is_file() or path.suffix not in (".py", ".js", ".mjs", ".html", ".css", ".md", ".json", ".txt", ".ps1"):
        continue
    if any(part in skip_dirs for part in path.parts):
        continue
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        continue
    for rx, label in SECRET_PATTERNS:
        for m in rx.finditer(text):
            hits.append(f"{path.relative_to(ROOT)}: {label}: {m.group(0)[:60]}")
ok("không tìm thấy secret hard-code", not hits, hits[:5])

print("\n[2] Audit log không chứa nội dung thư")
try:
    from app.db import connect, init_db, data_dir
    init_db()
    con = connect()
    rows = con.execute("SELECT action, detail FROM audit ORDER BY id DESC LIMIT 500").fetchall()
    con.close()
    long_details = [r["detail"] for r in rows if len(r["detail"] or "") > 300]
    ok("không có audit detail quá dài (nội dung thư)", not long_details, long_details[:2])
    # body-like markers in the audit log
    bodyish = [r["detail"] for r in rows
               if re.search(r"(?i)content-type:\s*text|boundary=|<html|<body", r["detail"] or "")]
    ok("không có nội dung MIME/HTML trong audit log", not bodyish, bodyish[:2])
except Exception as e:
    ok("audit log đọc được", False, e)

print("\n[3] Case JSON không chứa raw body")
try:
    from app.db import connect
    con = connect()
    rows = con.execute("SELECT id, result FROM cases ORDER BY ts DESC LIMIT 50").fetchall()
    con.close()
    bad = []
    for r in rows:
        blob = r["result"] or ""
        if re.search(r"(?i)content-type:\s*multipart|boundary=\"|BEGIN:VEVENT", blob):
            bad.append(r["id"])
        if len(blob) > 3_000_000:
            bad.append(r["id"] + " (quá lớn)")
    ok("không case nào nhúng raw MIME / quá lớn", not bad, bad[:3])
except Exception as e:
    ok("đọc case được", False, e)

print("\n[4] Quyền tệp trên đĩa")
if os.name == "posix":
    from app.db import data_dir
    d = data_dir()
    ev = list((d / "evidence").glob("*"))[:3]
    ok("evidence là read-only (444)", all(oct(os.stat(p).st_mode)[-3:] == "444" for p in ev) if ev else True,
       [oct(os.stat(p).st_mode)[-3:] for p in ev])
    ms = list((d / "messages").glob("*/*"))[:3]
    ok("body thư là owner-only (600/700)",
       all(oct(os.stat(p).st_mode)[-3:] in ("600", "700") for p in ms) if ms else True,
       [oct(os.stat(p).st_mode)[-3:] for p in ms])
else:
    ok("bỏ qua (chỉ kiểm tra quyền trên POSIX)", True)

print("\n[5] LLM payload được ẩn danh trước khi gửi")
try:
    from app import llm
    txt = ("Liên hệ John <john.doe@acme-corp.com> từ 203.0.113.45, "
           "mở https://acme-login.example/verify ngay. Tài khoản acme.com")
    red = llm._redact(txt)
    ok("email bị che", "@" not in red.replace("<email>", ""), red[:120])
    ok("IP bị che", "203.0.113.45" not in red, red[:120])
    ok("URL bị che", "acme-login.example" not in red, red[:120])
    ok("nội dung vẫn còn để LLM đọc", "Liên hệ" in red and "ngay" in red, red[:120])
except Exception as e:
    ok("module llm kiểm tra được", False, e)

print("\n[6] File upload tạm luôn bị xoá sau analyze")
try:
    up = ROOT / "data" / "uploads"
    leftovers = [x.name for x in up.glob("*")] if up.exists() else []
    ok("không còn file upload tạm", not leftovers, leftovers[:5])
except Exception as e:
    ok("kiểm tra uploads được", False, e)

print("\n[7] Không có nội dung thư trong log/tệp tạm của hệ thống")
tmp = Path(os.getenv("TEMP") or "/tmp")
scratch = [x.name for x in tmp.glob("ms-pst-*")] + [x.name for x in tmp.glob("ms-mbox-*")]
ok("không còn thư mục tạm của parser", not scratch, scratch[:5])

print(f"\n{p}/{p + f} PASS  (leak audit)")
sys.exit(1 if f else 0)
