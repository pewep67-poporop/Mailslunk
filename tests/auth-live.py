"""M2 — verification suite for SPF / DKIM / DMARC (live DNS).

Run with a server on :8100 or directly:
    LIVE_DNS=1 python tests/auth-live.py
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["LIVE_DNS"] = "1"   # force: this suite needs the real DNS

from app.authcheck import check_auth, _org_domain, _public_suffix  # noqa: E402

p = f = 0


def ok(name, cond, extra=""):
    global p, f
    if cond:
        p += 1
        print("  PASS  " + name)
    else:
        f += 1
        print("  FAIL  " + name + ((" :: " + str(extra)[:300]) if extra else ""))


def eml(**kw):
    hdrs = []
    for k, v in kw.items():
        hdrs.append(f"{k}: {v}")
    return ("\r\n".join(hdrs) + "\r\n\r\nbody text\r\n").encode()


# ---------------------------------------------------------------- PSL / org domain
print("\n[1] Public Suffix / org domain")
ok("co.uk -> example.co.uk", _org_domain("mail.example.co.uk") == "example.co.uk", _org_domain("mail.example.co.uk"))
ok("com.au -> example.com.au", _org_domain("example.com.au") == "example.com.au", _org_domain("example.com.au"))
ok("gmail.com -> gmail.com", _org_domain("gmail.com") == "gmail.com")
ok("co.jp -> example.co.jp", _org_domain("a.example.co.jp") == "example.co.jp", _org_domain("a.example.co.jp"))
ok("plain domain", _org_domain("example.com") == "example.com")
ok("no dot", _org_domain("localhost") == "localhost")
ok("public suffix github.io", _org_domain("user.github.io") == "user.github.io", _org_domain("user.github.io"))

# ---------------------------------------------------------------- SPF (live DNS)
print("\n[2] SPF — DNS thật (pyspf)")
t0 = time.time()
r = check_auth(eml(**{
    "Return-Path": "<bounce@gmail.com>",
    "Received": "from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41]) by mx.local with ESMTP id a1; Mon, 10 Nov 2026 10:00:00 +0000",
    "From": "Alice <alice@gmail.com>",
    "To": "bob@example.org",
    "Subject": "hello",
}))
spf = r["spf"]
ok("SPF pass (gmail.com / IP của Google)", spf["result"] == "pass", (spf["result"], spf["reason"]))
ok("SPF client IP đúng", spf["clientIp"] == "209.85.220.41", spf["clientIp"])
ok("SPF HELO đúng", spf["helo"] == "mail-sor-f41.google.com", spf["helo"])
ok("SPF domain = MAIL FROM", spf["domain"] == "gmail.com", spf["domain"])
ok("SPF record được lấy từ DNS", "v=spf1" in (spf.get("record") or ""), spf.get("record"))
print("      (%.1fs)" % (time.time() - t0))

r2 = check_auth(eml(**{
    "Return-Path": "<bounce@github.com>",
    "Received": "from mail.github.com (mail.github.com [8.8.8.8]) by mx.local with ESMTP id a2; Mon, 10 Nov 2026 10:00:00 +0000",
    "From": "Bob <bob@github.com>",
    "To": "x@y.org",
}))
ok("SPF softfail/fail (IP không được phép)", r2["spf"]["result"] in ("softfail", "fail"),
   (r2["spf"]["result"], r2["spf"]["reason"]))

r3 = check_auth(eml(**{
    "Return-Path": "<bounce@nowhere-nospf-record.example>",
    "Received": "from mx.nowhere.example (mx.nowhere.example [8.8.4.4]) by mx.local with ESMTP id a3; Mon, 10 Nov 2026 10:00:00 +0000",
    "From": "N <n@nowhere-nospf-record.example>",
    "To": "x@y.org",
}))
ok("SPF none (domain không có bản ghi SPF)", r3["spf"]["result"] == "none",
   (r3["spf"]["result"], r3["spf"]["reason"]))

r4 = check_auth(eml(**{
    "Return-Path": "<bounce@gmail.com>",
    "From": "A <a@gmail.com>",
}))
ok("SPF không có client IP -> none", r4["spf"]["result"] == "none", r4["spf"]["result"])
r5 = check_auth(eml(**{
    "Return-Path": "",
    "Received": "from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41]) by mx.local with ESMTP id a5",
    "From": "A <a@gmail.com>",
}))
ok("SPF không có Return-Path -> none (không đoán MAIL FROM)", r5["spf"]["result"] == "none",
   (r5["spf"]["result"], r5["spf"]["reason"]))

# ---------------------------------------------------------------- DMARC (live DNS)
print("\n[3] DMARC — DNS thật")
r6 = check_auth(eml(**{
    "Return-Path": "<bounce@gmail.com>",
    "Received": "from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41]) by mx.local with ESMTP id a6",
    "From": "A <a@gmail.com>",
}))
ok("DMARC pass (gmail.com có policy, SPF khớp)", r6["dmarc"]["result"] == "pass",
   (r6["dmarc"]["result"], r6["dmarc"].get("policy"), r6["dmarc"].get("alignment")))
ok("DMARC policy lấy đúng", r6["dmarc"]["policy"] in ("reject", "quarantine", "none"), r6["dmarc"].get("policy"))
ok("DMARC record được lấy từ DNS", "v=DMARC1" in (r6["dmarc"].get("record") or ""), r6["dmarc"].get("record"))
ok("DMARC alignment spf = True", r6["dmarc"]["alignment"]["spf"] is True, r6["dmarc"]["alignment"])

r7 = check_auth(eml(**{
    "Return-Path": "<bounce@gmail.com>",
    "Received": "from mail-sor-f41.google.com (mail-sor-f64.google.com [209.85.220.41]) by mx.local with ESMTP id a7",
    "From": "A <a@google.com>",
}))
ok("DMARC fail (SPF pass nhưng không khớp From=google.com)",
   r7["dmarc"]["result"] == "fail" and r7["dmarc"]["alignment"]["spf"] is False,
   (r7["dmarc"]["result"], r7["dmarc"]["alignment"]))
ok("có finding dmarc_fail", any(x["type"] == "dmarc_fail" for x in r7["findings"]), r7["findings"])
ok("có finding spf_alignment_mismatch", any(x["type"] == "spf_alignment_mismatch" for x in r7["findings"]),
   [x["type"] for x in r7["findings"]])

r8 = check_auth(eml(**{
    "Return-Path": "<bounce@nowhere-nospf-record.example>",
    "Received": "from mx.nowhere.example (mx.nowhere.example [8.8.4.4]) by mx.local with ESMTP id a8",
    "From": "N <n@nowhere-nospf-record.example>",
}))
ok("DMARC none (không có policy)", r8["dmarc"]["result"] == "none",
   (r8["dmarc"]["result"], r8["dmarc"].get("reason")))

# ---------------------------------------------------------------- DKIM
print("\n[4] DKIM — chữ ký thật (khóa RSA tự sinh + DNS giả lập)")
import dkim  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
priv = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                         serialization.NoEncryption())
pub = key.public_key().public_bytes(serialization.Encoding.DER,
                                     serialization.PublicFormat.SubjectPublicKeyInfo)
import base64  # noqa: E402
pub_b64 = base64.b64encode(pub).decode()
key_txt = "v=DKIM1; k=rsa; p=" + pub_b64

BODY = (b"From: alice@example.com\r\nTo: bob@example.org\r\nSubject: signed test\r\n"
        b"\r\nHello signed world\r\n")
# dkimpy: sign(message, selector, domain, privkey) -> returns ONLY the signature
# header, so the signed message is header + original message.
sig1 = dkim.sign(BODY, b"sel1", b"example.com", priv, canonicalize=(b"relaxed", b"relaxed"))
signed = sig1 + BODY

# 4a: verify with the key served through our DNS layer
import app.authcheck as AC  # noqa: E402
orig_txt = AC._txt_records
AC._txt_records = lambda name: ([key_txt] if "sel1._domainkey.example.com" in name.lower() else orig_txt(name))
try:
    r9 = AC.check_auth(signed)
    ok("DKIM pass (chữ ký hợp lệ)", r9["dkim"]["result"] == "pass",
       (r9["dkim"]["result"], r9["dkim"].get("reason")))
    ok("DKIM domain/selector đúng", r9["dkim"].get("verifiedDomain") == "example.com"
       and r9["dkim"].get("verifiedSelector") == "sel1", r9["dkim"])
    ok("DMARC pass khi DKIM khớp From", r9["dmarc"]["result"] == "pass",
       (r9["dmarc"]["result"], r9["dmarc"]["alignment"]))
    ok("authSeen = True", r9["authSeen"] is True)
finally:
    AC._txt_records = orig_txt

# 4b: tampered body -> DKIM fail
tampered = signed.replace(b"Hello signed world", b"Hello TAMPERED world")
AC._txt_records = lambda name: ([key_txt] if "sel1._domainkey.example.com" in name.lower() else orig_txt(name))
try:
    r10 = AC.check_auth(tampered)
    ok("DKIM fail khi body bị sửa", r10["dkim"]["result"] == "fail", (r10["dkim"]["result"], r10["dkim"].get("reason")))
    ok("lý do body hash rõ ràng", "body" in (r10["dkim"].get("reason") or "").lower(), r10["dkim"].get("reason"))
    ok("có finding dkim_fail", any(x["type"] == "dkim_fail" for x in r10["findings"]), [x["type"] for x in r10["findings"]])
finally:
    AC._txt_records = orig_txt

# 4c: missing public key -> fail with clear reason
AC._txt_records = lambda name: ([] if "sel1._domainkey" in name.lower() else orig_txt(name))
try:
    r11 = AC.check_auth(signed)
    ok("DKIM fail khi thiếu khóa công khai", r11["dkim"]["result"] == "fail", r11["dkim"]["result"])
    ok("lý do 'public key not found'", "key" in (r11["dkim"].get("reason") or "").lower(), r11["dkim"].get("reason"))
finally:
    AC._txt_records = orig_txt

# 4d: no DKIM-Signature at all
r12 = check_auth(eml(**{"From": "a@b.com", "Subject": "no dkim"}))
ok("DKIM none khi không có chữ ký", r12["dkim"]["result"] == "none", r12["dkim"]["result"])
ok("có finding dkim_none", any(x["type"] == "dkim_none" for x in r12["findings"]), [x["type"] for x in r12["findings"]])

# 4e: two signatures — one valid, one broken -> overall pass, per-signature detail
sig2 = dkim.sign(BODY, b"sel2", b"example.com", priv, canonicalize=(b"relaxed", b"relaxed"))
both = sig1 + sig2 + BODY
AC._txt_records = lambda name: ([key_txt] if "sel1._domainkey.example.com" in name.lower()
                                 else ([] if "sel2._domainkey" in name.lower() else orig_txt(name)))
try:
    r13 = AC.check_auth(both)
    ok("2 chữ ký: kết quả từng chữ ký được báo", len(r13["dkim"]["signatures"]) == 2, r13["dkim"]["signatures"])
    ok("có ít nhất 1 chữ ký pass", any(s["result"] == "pass" for s in r13["dkim"]["signatures"]),
       r13["dkim"]["signatures"])
    ok("chữ ký hỏng được báo riêng", any(s["result"] == "fail" for s in r13["dkim"]["signatures"]),
       r13["dkim"]["signatures"])
finally:
    AC._txt_records = orig_txt

# ---------------------------------------------------------------- real DNS key
print("\n[4b] Lấy khóa DKIM thật từ Internet")
real_key = AC._txt_records("s1._domainkey.sendgrid.net")
ok("đọc được khóa DKIM thật qua DNS", bool(real_key) and "p=" in (real_key[0] if real_key else ""),
   (real_key[0][:60] if real_key else None))
ok("_dnsfunc trả về bản ghi TXT cho dkimpy",
   isinstance(AC._dnsfunc(b"s1._domainkey.sendgrid.net"), bytes))

# ---------------------------------------------------------------- upstream AR
print("\n[5] Authentication-Results của máy nhận (upstream)")
r14 = check_auth(eml(**{
    "From": "a@gmail.com",
    "Return-Path": "<bounce@gmail.com>",
    "Received": "from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41]) by mx.local with ESMTP id a14",
    "Authentication-Results": "mx.google.com; spf=pass (google.com: domain of x designates 209.85.220.41) smtp.mailfrom=x; dkim=pass header.i=@x; dmarc=pass (p=reject sp=reject) header.from=x",
}))
ok("upstream authserv-id đọc được", r14["upstream"]["authserv"] == "mx.google.com", r14["upstream"])
ok("upstream spf/dkim/dmarc đọc được",
   r14["upstream"]["spf"] == "pass" and r14["upstream"]["dkim"] == "pass" and r14["upstream"]["dmarc"] == "pass",
   r14["upstream"])
ok("headerFound = True", r14["headerFound"] is True)
ok("authservId đọc được", r14["authservId"] == "mx.google.com", r14["authservId"])

# ---------------------------------------------------------------- offline mode
print("\n[6] Chế độ offline (LIVE_DNS=0) — dùng cho PST lớn")
os.environ["LIVE_DNS"] = "0"
r15 = check_auth(eml(**{
    "From": "a@gmail.com",
    "Return-Path": "<bounce@gmail.com>",
    "Received": "from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41]) by mx.local with ESMTP id a15",
    "Authentication-Results": "mx.google.com; spf=pass; dkim=pass; dmarc=pass",
}))
ok("offline: spf not_run", r15["spf"]["result"] == "not_run", r15["spf"]["result"])
ok("offline: dkim not_run", r15["dkim"]["result"] == "not_run", r15["dkim"]["result"])
ok("offline: dmarc not_run", r15["dmarc"]["result"] == "not_run", r15["dmarc"]["result"])
ok("offline: upstream vẫn có (không cần DNS)", r15["upstream"]["spf"] == "pass", r15["upstream"])
ok("offline: authSeen vẫn True", r15["authSeen"] is True)
ok("offline: không có finding fail giả", not any(x["type"].endswith("_fail") for x in r15["findings"]),
   [x["type"] for x in r15["findings"]])
os.environ["LIVE_DNS"] = "1"

# ---------------------------------------------------------------- cache
print("\n[7] Cache DNS")
t0 = time.time()
for _ in range(5):
    check_auth(eml(**{
        "Return-Path": "<bounce@gmail.com>",
        "Received": "from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41]) by mx.local with ESMTP id a16",
        "From": "A <a@gmail.com>",
    }))
dt = time.time() - t0
ok("5 lần check SPF/DMARC cùng domain < 2s (có cache)", dt < 2.0, "%.2fs" % dt)

print(f"\n{p}/{p + f} PASS  (M2 live)")
sys.exit(1 if f else 0)
