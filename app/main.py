"""MailSleuth Python — FastAPI server (parallel to Node.js version).

Mirrors public contract of ../mailsleuth/server/index.js:
  /api/health, /api/register, /api/login, /api/me, /api/logout,
  /api/password, /api/recover, /api/profile*, /api/analyze,
  /api/cases, /api/dns, /api/ip, /api/map, /api/case/{id}/message/{idx},
  /api/report/{id}, /api/settings/map, /api/admin/logs, /api/admin/sessions
Static UI served from ../public (copy) on /.
"""
import os, errno, hashlib, time, secrets, json, uuid, re
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Request, Response, HTTPException, Depends, UploadFile, File
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse, PlainTextResponse
from fastapi.concurrency import run_in_threadpool
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from starlette.exceptions import HTTPException as StarletteHTTPException
import bcrypt

from . import auth as A
from .db import connect, init_db, log, kv_get, kv_set, data_dir, setup_tmpdir, tmp_dir
from .parsers import load_messages, extract_pst, ParseError, EXT_RE
from .enrichment import geo_lookup, confidence, classify_server, score
from .dns_real import lookup_domain, lookup_auth, normalize_domain, reverse_ptr as dns_reverse
from .report import render_report, render_csv
from .mapgen import build_map
from .mapglot import reverse as mapglot_reverse, last_error_of as mapglot_last_error
from .headers import analyze_headers
from .routing import analyze_routing
from .authcheck import check_auth
from .urls import analyze as analyze_urls
from .attachments import extract as extract_attachments, findings_for as attachment_findings
from .ioc import extract as ioc_extract, to_csv as ioc_csv, to_stix as ioc_stix
from . import siem
from . import bodies

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT / "public"
APP_PUBLIC = PUBLIC

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app):
    # startup: init DB schema + bootstrap admin (replaces deprecated on_event for FastAPI >= 0.120 / Py 3.14)
    # Stage multipart/readpst scratch on the roomiest drive FIRST: Starlette spills
    # uploads to %TEMP% after 1 MB, and a full OS drive otherwise kills the batch
    # with a masked "http_error".
    try:
        app.state.tmpdir = str(setup_tmpdir())
    except Exception:
        app.state.tmpdir = None
    init_db(); A.init_admin()
    # self-healing watchdog (see _watchdog_loop) - disabled with WATCHDOG_INTERVAL=0
    try:
        app.state.watchdog_stop = _start_watchdog()
    except Exception:
        app.state.watchdog_stop = None
    yield
    try:
        if getattr(app.state, "watchdog_stop", None):
            app.state.watchdog_stop.set()
    except Exception:
        pass

app = FastAPI(title="MailSleuth Python API", docs_url="/api/docs", lifespan=lifespan)

@app.exception_handler(StarletteHTTPException)
async def flat_http_error(request: Request, exc: StarletteHTTPException):
    """Always answer with a flat {"error": "<code>"} body.

    FastAPI would wrap HTTPException details as {"detail": {...}}, which the UI
    (and the Node contract) cannot read — the client would fall through to a
    generic message. Flattening keeps every error code machine-readable.
    """
    detail = exc.detail
    body = {}
    if isinstance(detail, dict):
        body = dict(detail)
        code = body.pop("error", None) or body.pop("code", None) or "http_error"
    elif isinstance(detail, list):
        code, body = "bad_request", {"detail": detail}
    else:
        code = "not_found" if exc.status_code == 404 else "http_error"
        body = {"detail": str(detail)}
        # FastAPI wraps ANY exception raised while reading the body into a bare
        # 400 "There was an error parsing the body" (fastapi/routing.py:284) and
        # parks the real one in __cause__. Surface it: a full disk must read as
        # "disk_full", not as a meaningless "http_error" the operator cannot act on.
        cause = exc.__cause__
        if isinstance(cause, OSError) and getattr(cause, "errno", None) in (
            errno.ENOSPC, getattr(errno, "EDQUOT", errno.ENOSPC)
        ):
            code = "disk_full"
            body["detail"] = f"{cause} (temp={tmp_dir()})"
        elif cause is not None and not str(detail):
            body["detail"] = f"{type(cause).__name__}: {cause}"
    body["error"] = code
    return JSONResponse(body, status_code=exc.status_code)

class SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp
app.add_middleware(SecurityHeaders)

# Simple in-memory rate limit (Node: express-rate-limit). SQLite sessions allow multi-worker boot,
# but counters stay per-process — use Redis if scaling workers.
_hits = {}
AVATAR_RATE_MAX = int(os.getenv("AVATAR_RATE_MAX", "20"))  # avatar uploads / IP / minute
def rate_check(key: str, max_n: int, window: int = 60) -> bool:
    now = time.time()
    arr = [t for t in _hits.get(key, []) if now - t < window]
    if len(arr) >= max_n: return False
    arr.append(now); _hits[key] = arr; return True
class RateLimit(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        p = request.url.path
        ip = request.client.host or "?"
        if p == "/api/login" and not rate_check(f"login:{ip}", 10): return JSONResponse({"error":"rate"}, status_code=429)
        if p == "/api/analyze" and not rate_check(f"an:{ip}", 40): return JSONResponse({"error":"rate"}, status_code=429)
        if p in ("/api/ip", "/api/dns", "/api/map") and not rate_check(f"tool:{ip}", 30): return JSONResponse({"error":"rate"}, status_code=429)
        if p == "/api/profile/avatar" and request.method == "POST" and not rate_check(f"av:{ip}", AVATAR_RATE_MAX):
            return JSONResponse({"error":"rate"}, status_code=429)
        return await call_next(request)
app.add_middleware(RateLimit)

def env_bool(k, d=False):
    return os.getenv(k, "1" if d else "0") not in ("0", "false", "False", "")

def now_iso():
    return datetime.now(timezone.utc).isoformat()

# ---------- helpers ----------
def get_session(request: Request) -> Optional[dict]:
    sid = request.cookies.get("sid") or ""
    return A.get_session(sid) if sid else None

def require_auth(request: Request) -> dict:
    s = get_session(request)
    if not s: raise HTTPException(401, detail={"error": "auth"})
    if request.method in ("POST", "PUT", "DELETE", "PATCH", "") and request.method != "GET":
        csrf = request.headers.get("x-csrf") or ""
        if s["csrf"] != csrf:
            raise HTTPException(403, detail={"error": "csrf"})
    return s

def require_admin(request: Request) -> dict:
    s = require_auth(request)
    if s["role"] != "admin": raise HTTPException(403, detail={"error": "forbidden"})
    return s

def find_user(name: str):
    con = connect()
    r = con.execute("SELECT * FROM users WHERE name=? COLLATE NOCASE", ((name or "").strip(),)).fetchone()
    con.close(); return r

# ---------- health ----------
def _health_deep() -> dict:
    """Component-level health: used by /api/health?deep=1 and the watchdog."""
    comp = {}
    degraded = []
    # 1. database
    try:
        con = connect()
        con.execute("SELECT COUNT(*) FROM users").fetchone()
        con.close()
        comp["db"] = "ok"
    except Exception as e:
        comp["db"] = f"error: {type(e).__name__}"
        degraded.append("db")
    # 2. data dir writable
    try:
        p = data_dir() / "uploads" / ".health"
        p.write_bytes(b"1")
        p.unlink()
        comp["storage"] = "ok"
    except Exception as e:
        comp["storage"] = f"error: {type(e).__name__}"
        degraded.append("storage")
    # 3. GeoLite2
    try:
        from .enrichment import _open
        comp["geoip"] = "ok" if _open() else "missing"
        if not _open():
            degraded.append("geoip")
    except Exception as e:
        comp["geoip"] = f"error: {type(e).__name__}"
        degraded.append("geoip")
    # 4. DNS resolver
    try:
        import dns.resolver
        dns.resolver.resolve("example.com", "A", lifetime=3)
        comp["dns"] = "ok"
    except Exception as e:
        comp["dns"] = f"error: {type(e).__name__}"
        degraded.append("dns")
    # 5. outbound breakers (reputation / LLM)
    try:
        from .breaker import snapshot
        comp["breakers"] = snapshot()
    except Exception:
        comp["breakers"] = {}
    # 6. optional ML model
    try:
        from . import ml
        comp["ml"] = ml.status()
        if comp["ml"].get("state") == "error":
            degraded.append("ml")
    except Exception:
        comp["ml"] = {"state": "absent"}
    return {"components": comp, "degraded": degraded}

@app.get("/api/health")
def health(deep: int = 0):
    from .enrichment import _open
    _open()
    out = {"ok": True, "geo": {"city": True, "asn": True, "country": True},
           "dnsResolvers": 1, "map": "osm", "mxAuto": False}
    if deep:
        d = _health_deep()
        out.update(d)
        out["ok"] = not d["degraded"]
    return out

# ---------- watchdog (self-healing) ----------
def _watchdog_loop(stop_evt, interval: int, threshold: int):
    """Periodically check the DB + storage; exit the process when it stays broken
    so systemd (Restart=always) brings a clean instance back."""
    fails = 0
    while not stop_evt.is_set():
        stop_evt.wait(interval)
        if stop_evt.is_set():
            return
        ok = True
        try:
            con = connect(); con.execute("SELECT 1").fetchone(); con.close()
        except Exception:
            ok = False
        if ok:
            try:
                p = data_dir() / "uploads" / ".watchdog"
                p.write_bytes(b"1"); p.unlink()
            except Exception:
                ok = False
        fails = 0 if ok else fails + 1
        if fails >= threshold:
            try:
                from .db import log
                log("system", "watchdog_exit", f"health checks failed {fails}x")
            except Exception:
                pass
            os._exit(1)   # systemd restarts us

def _start_watchdog():
    import threading
    interval = int(os.getenv("WATCHDOG_INTERVAL", "60") or 60)
    threshold = int(os.getenv("WATCHDOG_FAILS", "3") or 3)
    if interval <= 0:
        return None
    stop = threading.Event()
    t = threading.Thread(target=_watchdog_loop, args=(stop, interval, threshold), daemon=True)
    t.start()
    return stop

# ---------- auth ----------
@app.post("/api/register")
async def register(request: Request):
    b = await request.json()
    name = str(b.get("user") or ""); pw = str(b.get("pass") or "")
    if not A.username_ok(name): return JSONResponse({"error": "bad_user"}, status_code=400)
    if not A.password_ok(pw): return JSONResponse({"error": "weak"}, status_code=400)
    if find_user(name): return JSONResponse({"error": "exists"}, status_code=400)
    h = bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=12)).decode()
    con = connect()
    con.execute("INSERT INTO users(name,hash,role,created) VALUES(?,?,?,?)", (name, h, "analyst", now_iso()))
    uid = con.execute("SELECT id FROM users WHERE name=? COLLATE NOCASE", (name,)).fetchone()["id"]
    con.commit(); con.close()
    key = A.set_recovery(uid); log(name, "register"); return {"user": name, "recovery": key}

@app.post("/api/login")
async def login(request: Request):
    b = await request.json()
    u = find_user(str(b.get("user") or ""))
    pw = str(b.get("pass") or "")
    if not u or not bcrypt.checkpw(pw.encode(), str(u["hash"]).encode()):
        return JSONResponse({"error": "login"}, status_code=401)
    sid, csrf, exp = A.start_session(u["name"], u["role"])
    resp = JSONResponse({"user": u["name"], "role": u["role"], "csrf": csrf, "expiresAt": exp, "loginMs": 0})
    resp.set_cookie("sid", sid, httponly=True, samesite="strict", secure=os.getenv("COOKIE_SECURE","0")=="1", max_age=A.SESSION_TTL)
    log(u["name"], "login"); return resp

@app.get("/api/me")
async def me(request: Request):
    s = get_session(request)
    if not s: return JSONResponse({"error":"auth"}, status_code=401)
    return {"user": s["user"], "role": s["role"], "csrf": s["csrf"], "expiresAt": int(s["expires"]*1000), "loginMs": s.get("loginMs",0)}

@app.post("/api/logout")
async def logout(request: Request):
    sid = request.cookies.get("sid") or ""
    A.drop_session(sid, "logout")
    resp = JSONResponse({"ok": True}); resp.delete_cookie("sid"); return resp

@app.post("/api/password")
async def change_pw(request: Request):
    s = require_auth(request); b = await request.json()
    u = find_user(s["user"])
    if not bcrypt.checkpw(str(b.get("current") or "").encode(), str(u["hash"]).encode()):
        return JSONResponse({"error": "pass_bad"}, status_code=400)
    newp = str(b.get("new") or "")
    if not A.password_ok(newp): return JSONResponse({"error": "weak"}, status_code=400)
    h = bcrypt.hashpw(newp.encode(), bcrypt.gensalt(rounds=12)).decode()
    con = connect(); con.execute("UPDATE users SET hash=? WHERE name=?", (h, s["user"])); con.commit(); con.close()
    A.drop_all_sessions(s["user"]); log(s["user"], "password_change"); return {"ok": True}

@app.post("/api/recover")
async def recover(request: Request):
    b = await request.json()
    u = find_user(str(b.get("user") or ""))
    if not u or not bcrypt.checkpw(A.norm_key(str(b.get("key") or "")).encode(), str(u["recovery"]).encode()):
        return JSONResponse({"error": "recover"}, status_code=400)
    newp = str(b.get("new") or "")
    if not A.password_ok(newp): return JSONResponse({"error": "weak"}, status_code=400)
    h = bcrypt.hashpw(newp.encode(), bcrypt.gensalt(rounds=12)).decode()
    con = connect(); con.execute("UPDATE users SET hash=? WHERE name=?", (h, u["name"])); con.commit(); con.close()
    A.drop_all_sessions(u["name"]); key = A.set_recovery(u["id"]); return {"recovery": key}

# ---------- profile (minimal) ----------
@app.get("/api/profile")
async def profile(request: Request):
    s = require_auth(request); u = find_user(s["user"])
    return {"user": s["user"], "role": s["role"], "created": u["created"] if u else None,
            "hasAvatar": bool(u and u["avatar"]),
            "avatarMime": (u["avatar_mime"] if u else None),
            "avatarUpdated": (u["avatar_updated"] if u else None)}
@app.get("/api/profile/avatar")
async def avatar(request: Request):
    s = require_auth(request); u = find_user(s["user"])
    if u and u["avatar"]:
        return Response(content=bytes(u["avatar"]), media_type=u["avatar_mime"] or "image/png",
                        headers={"Cache-Control": "private, max-age=300"})
    return JSONResponse({"error": "not_found"}, status_code=404)
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_JPG_MAGIC = b"\xff\xd8\xff"
@app.post("/api/profile/avatar")
async def avatar_up(request: Request, avatar: UploadFile | None = File(None)):
    s = require_auth(request)
    if avatar is None: return JSONResponse({"error": "bad_avatar"}, status_code=400)
    data = await avatar.read()
    if not data: return JSONResponse({"error": "bad_avatar"}, status_code=400)
    if len(data) > 2*1024*1024: return JSONResponse({"error": "avatar_too_large"}, status_code=413)
    # trust magic bytes, not the client-declared content-type / file name
    if data.startswith(_PNG_MAGIC): mime = "image/png"
    elif data.startswith(_JPG_MAGIC): mime = "image/jpeg"
    else: return JSONResponse({"error": "bad_avatar"}, status_code=400)
    stamp = now_iso()
    con = connect()
    con.execute("UPDATE users SET avatar=?, avatar_mime=?, avatar_updated=? WHERE name=?",
                (data, mime, stamp, s["user"]))
    con.commit(); con.close(); log(s["user"], "avatar", f"{len(data)} bytes {mime}")
    return {"ok": True, "avatarUpdated": stamp}

# ---------- analyze ----------
PST_AUTH_MAX = int(os.getenv("PST_AUTH_MAX", "50"))          # messages per PST that get live SPF/DKIM/DMARC
PST_FILE_MAX = int(os.getenv("PST_FILE_MAX", str(500 * 1024 * 1024)))  # Node multer cap
MSG_FILE_MAX = 25 * 1024 * 1024


def _forensic_core(fname: str, raw: bytes, do_auth: bool = True, user: str = "") -> dict:
    """M1–M6 for ONE blob (a single EML, an MBOX, or one PST-extracted EML)."""
    msgs = load_messages(fname, raw)
    # Keep the bytes of every parsed message so the body preview can be stored
    # (MBOX carries one blob with many messages -> parsers keep them apart).
    for m in msgs:
        m.setdefault("_raw", raw)
        m.setdefault("_name", fname)
    ips = list(dict.fromkeys([ip for m in msgs for ip in (m.get("originIPs") or [])]))
    sc, verdict = score(msgs)
    # --- P1 forensics: headers (M1), routing (M3), real SPF/DKIM/DMARC (M2) ---
    hdr = analyze_headers(raw)
    rt = analyze_routing(raw)
    auth = check_auth(raw, live=do_auth)
    # --- P2 threats: phishing URLs (M4), attachments (M5), IOC (M6) ---
    urls = analyze_urls(raw, user)
    atts = extract_attachments(fname, raw, quarantine=True, user=user)
    att_f = attachment_findings(atts)
    findings = (hdr["checks"] + rt["anomalies"] + auth["findings"]
                + urls["findings"] + att_f)
    penalty = sum(int(w.get("weight") or 0) for w in findings)
    sc = max(0, min(100, sc - penalty))
    if sc < 50: verdict = "malicious_or_phishing"
    elif sc < 85: verdict = "suspicious"
    if any(a["verdict"] == "malicious" for a in atts): verdict = "malicious_or_phishing"
    return {"msgs": msgs, "ips": ips, "score": sc, "verdict": verdict,
            "hdr": hdr, "rt": rt, "auth": auth, "urls": urls["urls"],
            "atts": atts, "findings": findings, "raw": raw}


def _enrich(msgs: list, ips: list) -> tuple:
    """Domain DNS + IP intel once per file/case (never per PST message)."""
    domains = [normalize_domain((m.get("from") or "")) for m in msgs]
    domains = list(dict.fromkeys([d for d in domains if d]))[:5]
    dns_map = {}
    if os.getenv("LIVE_DNS", "1") != "0":
        for d in domains:
            try: dns_map[d] = lookup_auth(d)
            except Exception: dns_map[d] = {"auth": {}, "records": {}}
    ip_info = []
    for ip in ips[:20]:
        ptr = dns_reverse(ip); geo = geo_lookup(ip)
        names = ptr.get("names") or []
        ip_info.append({"ip": ip, "geo": geo, "ptr": names,
                        "confidence": confidence(geo, names),
                        "server": classify_server(names, geo, []),
                        "assessment": {"verdict": "unverified", "reasons": [f"PTR: {', '.join(names)}" if names else "no PTR record"]}})
    return dns_map, ip_info


def feature_source(fname: str, raw: bytes) -> dict:
    """Result-shaped dict for the ML feature extractor — WITHOUT side effects
    (no DB write, no evidence copy, no quarantine). Used by
    tools/build_features.py to turn a corpus into training samples.
    Auth checks run offline (no DNS) so the feature distribution matches the
    server's offline mode.
    """
    ext = (fname or "").lower().rsplit(".", 1)[-1] if "." in (fname or "") else ""
    msgs = load_messages(fname, raw)
    hdr = analyze_headers(raw)
    rt = analyze_routing(raw)
    auth = check_auth(raw, live=False)
    urls = analyze_urls(raw, "")
    atts = extract_attachments(fname, raw, quarantine=False, user="")
    att_f = attachment_findings(atts)
    findings = (hdr["checks"] + rt["anomalies"] + auth["findings"]
                + urls["findings"] + att_f)
    return {"format": ext, "count": len(msgs), "score": 0, "verdict": "clean",
            "headerAnalysis": {"checks": hdr["checks"], "receivedCount": hdr["receivedCount"]},
            "routing": {"hops": rt["hops"], "anomalies": rt["anomalies"],
                        "totalDelayMs": rt["totalDelayMs"]},
            "auth": auth, "urls": urls["urls"], "attachments": atts,
            "findings": findings}


def _analyze_one(fname: str, raw: bytes, user: str, src_path: str = None):
    """M1→M7 pipeline for ONE file. Sync by design — executed via run_in_threadpool
    so slow DNS / parsing never blocks the event loop (large datasets on Linux/VMs
    used to freeze the whole server). Returns (result, None) or (None, error).

    PST/OST: readpst extracts every message to EML, then each message runs the
    same M1–M6 core. Findings/attachments/URLs/IPs are aggregated; the worst
    message supplies the file-level header/routing/auth view.

    ``src_path`` (optional): the upload was staged on disk — PST/OST is then
    parsed straight from the file (no 500 MB copy in RAM).
    """
    low = (fname or "").lower()
    ext = low.rsplit(".", 1)[-1] if "." in low else ""
    if not EXT_RE.search(fname or ""):
        return None, {"file": fname, "error": "file"}
    is_pst = ext in ("pst", "ost")
    size = len(raw) if raw is not None else (os.path.getsize(src_path) if src_path and os.path.exists(src_path) else 0)
    if size > (PST_FILE_MAX if is_pst else MSG_FILE_MAX):
        return None, {"file": fname, "error": "too_large"}
    if raw is None and src_path and os.path.exists(src_path) and not is_pst:
        with open(src_path, "rb") as fh:
            raw = fh.read()
    if raw is None and not is_pst:
        return None, {"file": fname, "error": "parse"}
    if raw is not None:
        sha = hashlib.sha256(raw).hexdigest()
    else:
        # PST: hash the staged file in chunks (never load 500 MB into RAM)
        h = hashlib.sha256()
        try:
            with open(src_path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    h.update(chunk)
            sha = h.hexdigest()
        except OSError:
            return None, {"file": fname, "error": "parse"}
    truncated = False

    if is_pst:
        try:
            items, truncated = extract_pst(fname, raw, path=src_path)
        except ParseError as e:
            return None, {"file": fname, "error": e.code}
        except Exception:
            return None, {"file": fname, "error": "parse"}
        chunks = []
        for idx, (name, data) in enumerate(items):
            try:
                chunks.append(_forensic_core(name, data, do_auth=idx < PST_AUTH_MAX, user=user))
            except ParseError as e:
                return None, {"file": fname, "error": e.code}
            except Exception:
                return None, {"file": fname, "error": "parse"}
        if not chunks:
            return None, {"file": fname, "error": "empty"}
    else:
        try:
            chunks = [_forensic_core(fname, raw, do_auth=True, user=user)]
        except ParseError as e:
            return None, {"file": fname, "error": e.code}
        except Exception:
            return None, {"file": fname, "error": "parse"}

    findings, atts, urls, messages, ips = [], [], [], [], []
    msgs_all, seen_urls, seen_ips = [], set(), set()
    body_items = []
    chunk_raws = []
    for idx, ch in enumerate(chunks):
        msgs_all.extend(ch["msgs"])
        chunk_raws.append(ch.get("raw"))
        av = {k: ch["auth"].get(k) for k in
              ("spf", "dkim", "dmarc", "authSeen", "clientIp", "fromDomain", "envDomain")}
        # PST: one message per chunk. EML/MBOX: keep every parsed message (same
        # file-level score), so the message list still reflects the whole upload.
        for m in (ch["msgs"][:1] if is_pst else (ch["msgs"] or [{}])):
            msg_index = len(messages)
            messages.append({"subject": m.get("subject", ""), "from": m.get("from", ""),
                             "fromName": m.get("fromName", ""), "date": m.get("date", ""),
                             "to": [x.strip() for x in re.split(r",", (m.get("to") or "")) if x.strip()],
                             "replyTo": m.get("replyTo", ""),
                             "returnPath": m.get("returnPath", ""),
                             "messageId": m.get("message_id", ""),
                             "score": ch["score"], "verdict": ch["verdict"],
                             "originIPs": m.get("originIPs") or [], "auth": av})
            raw_m = m.get("_raw")
            if raw_m:
                body_items.append((msg_index, m.get("_name") or fname, raw_m))
        room = 2000 - len(findings)
        for f in ch["findings"][:max(0, room)]:
            f = dict(f); f["m"] = idx; findings.append(f)
        room = 2000 - len(atts)
        for a in ch["atts"][:max(0, room)]:
            a = dict(a); a["m"] = idx; atts.append(a)
        for u in ch["urls"]:
            key = (u.get("url") or "").lower()
            if key and key not in seen_urls:
                seen_urls.add(key); urls.append(u)
        for ip in ch["ips"]:
            if ip not in seen_ips and len(ips) < 20:
                seen_ips.add(ip); ips.append(ip)

    # Python score runs 100→0 (lower is worse), unlike Node's 0→100 risk score.
    worst = min(chunks, key=lambda c: (c["score"], c["verdict"] == "clean"))
    sc, verdict = worst["score"], worst["verdict"]
    if any(c["verdict"] == "malicious_or_phishing" for c in chunks) or \
       any(a.get("verdict") == "malicious" for a in atts):
        verdict = "malicious_or_phishing"
    auth = worst["auth"]
    hdr, rt = worst["hdr"], worst["rt"]
    auth_seen = all(ch["auth"].get("authSeen") for ch in chunks)
    dns_map, ip_info = _enrich(msgs_all, ips)

    # --- M10 trained classifier + M11 LLM (both ADVISORY: they may only raise
    #     the suspicion level, never lower a rule verdict) ---
    feature_src = {
        "format": ext, "count": len(messages), "score": sc, "verdict": verdict,
        "headerAnalysis": {"checks": (worst["hdr"]["checks"]), "receivedCount": worst["hdr"]["receivedCount"]},
        "routing": {"hops": worst["rt"]["hops"], "anomalies": worst["rt"]["anomalies"],
                    "totalDelayMs": worst["rt"]["totalDelayMs"]},
        "auth": worst["auth"], "urls": urls, "attachments": atts, "findings": findings,
    }
    ml_out = {}
    try:
        from . import ml as _ml
        ml_out = _ml.score_result(feature_src)
    except Exception:
        ml_out = {}
    if ml_out:
        top = ", ".join(t.get("feature", "") for t in (ml_out.get("topFactors") or [])[:3])
        findings.append({"id": "ML-001", "sev": 2 if ml_out.get("mlVerdict") in ("suspicious", "phishing") else 0,
                         "severity": "medium", "type": "ml_phishing",
                         "evidence": f"ML {ml_out.get('mlScore')}% (model {ml_out.get('modelVersion')}) — top: {top}",
                         "weight": 5 if ml_out.get("mlVerdict") in ("suspicious", "phishing") else 0})
        if verdict == "clean" and ml_out.get("mlVerdict") in ("suspicious", "phishing"):
            verdict = "suspicious"
            sc = max(0, sc - 5)

    llm_out = {}
    try:
        from . import llm as _llm
        if _llm.enabled():
            worst_raw = chunk_raws[0] if chunk_raws else None
            if worst_raw:
                text = worst_raw.decode("utf-8", "ignore")
                llm_out = _llm.assess(feature_src, text, user)
    except Exception:
        llm_out = {}
    if llm_out:
        ev = "; ".join(str(e.get("quote") or "")[:80] for e in (llm_out.get("evidence") or [])[:2])
        findings.append({"id": "LLM-001", "sev": 2, "severity": "medium", "type": "llm_suspicious",
                         "evidence": f"LLM: {llm_out.get('verdict')} ({int(float(llm_out.get('confidence') or 0)*100)}%) — {llm_out.get('intent','')[:120]} {ev}".strip(),
                         "weight": 3})
        if verdict == "clean" and llm_out.get("verdict") in ("suspicious", "phishing", "malware"):
            verdict = "suspicious"
            sc = max(0, sc - 3)
    # release the extracted message bytes (memory)
    try:
        del chunk_raws
    except Exception:
        pass

    case_id = uuid.uuid4().hex[:12]
    ev_path = data_dir() / "evidence" / f"{case_id}.bin"
    if src_path and os.path.exists(src_path):
        # streaming copy: never holds a second full copy in RAM
        import shutil as _sh
        with open(src_path, "rb") as src, open(ev_path, "wb") as dst:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                dst.write(chunk)
    else:
        ev_path.write_bytes(raw)
    try: os.chmod(ev_path, 0o444)
    except Exception: pass
    # M8: store one body preview per message (DATA_DIR/messages/<case_id>/) so
    # the UI can open any message without bloating the case row.
    try:
        for meta in bodies.save_bodies(case_id, body_items):
            i = meta.get("index")
            if isinstance(i, int) and 0 <= i < len(messages):
                messages[i]["body"] = {k: meta.get(k) for k in
                                       ("hasText", "hasHtml", "truncated", "omitted",
                                        "textBytes", "htmlBytes")}
    except Exception:
        pass
    result = {"format": ext, "count": len(messages), "truncated": truncated,
              "authSeen": auth_seen, "verdict": verdict, "score": sc,
              "custody": {"caseId": case_id, "original": fname, "sha256": sha, "utc": now_iso()},
              "messages": messages,
              "findings": findings, "attachments": atts, "originIPs": ips,
              "urls": urls,
              "headerAnalysis": {"checks": hdr["checks"], "receivedCount": hdr["receivedCount"],
                                 "headers": hdr["headers"], "fromDomain": hdr["fromDomain"],
                                 "returnPathDomain": hdr["returnPathDomain"], "replyToDomain": hdr["replyToDomain"]},
              "routing": {"hops": rt["hops"], "anomalies": rt["anomalies"], "totalDelayMs": rt["totalDelayMs"], "hopCount": rt["hopCount"]},
              "auth": {k: auth.get(k) for k in ("spf", "dkim", "dmarc", "alignment", "overall",
                                               "authSeen", "clientIp", "fromDomain", "envDomain",
                                               "envAddr", "fromAddr", "replyTo", "headerFound",
                                               "authservId", "raw", "upstream", "dkimSignatures")},
              "dns": dns_map, "ipInfo": ip_info}
    if ml_out:
        result["ml"] = ml_out
    if llm_out:
        result["llm"] = llm_out
    result["ioc"] = ioc_extract(result)
    con = connect()
    con.execute("INSERT INTO cases(id,ts,user,file,sha256,result) VALUES(?,?,?,?,?,?)",
                (case_id, now_iso(), user, fname, sha, json.dumps(result, ensure_ascii=False)))
    con.commit(); con.close(); log(user, "analyze", fname)
    # M7: opt-in SIEM push (Wazuh syslog / Splunk HEC / Elastic _bulk) — never fatal, tokens never logged
    push = {"events": 0, "wazuh": 0, "splunk": 0, "elastic": 0, "errors": []}
    try: push = siem.emit_case(result, user)
    except Exception as e: push["errors"].append(type(e).__name__)
    if push["events"]: log(user, "siem_push", f"events={push['events']} wazuh={push['wazuh']} splunk={push['splunk']} elastic={push['elastic']} errors={len(push['errors'])}")
    return result, None

@app.post("/api/analyze")
async def analyze(request: Request, files: list[UploadFile] | None = File(None)):
    s = require_auth(request)
    if not files: return JSONResponse({"error": "file"}, status_code=400)
    results = []; errors = []
    up_dir = data_dir() / "uploads"
    up_dir.mkdir(parents=True, exist_ok=True)
    for f in files:
        # Stream the upload to disk: a 500 MB PST must never be held in RAM.
        tmp_path = up_dir / f"{uuid.uuid4().hex}.bin"
        try:
            size = 0
            with open(tmp_path, "wb") as out:
                while True:
                    chunk = await f.read(1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    out.write(chunk)
            result, err = await run_in_threadpool(_analyze_one, f.filename, None, s["user"], str(tmp_path))
            if err: errors.append(err)
            else: results.append(result)
        finally:
            # the upload staging file is a trace -> always removed
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    return {"results": results, "errors": errors}

@app.get("/api/cases")
async def cases(request: Request, q: str = "", limit: int = 100):
    s = require_auth(request)
    con = connect()
    if s["role"] == "admin":
        rows = con.execute("SELECT id,ts,user,file,sha256 FROM cases WHERE file LIKE ? OR user LIKE ? OR id LIKE ? ORDER BY ts DESC LIMIT ?",
                           (f"%{q}%", f"%{q}%", f"%{q}%", limit)).fetchall()
    else:
        rows = con.execute("SELECT id,ts,user,file,sha256 FROM cases WHERE user=? AND (file LIKE ? OR id LIKE ?) ORDER BY ts DESC LIMIT ?",
                           (s["user"], f"%{q}%", f"%{q}%", limit)).fetchall()
    con.close(); return {"cases": [dict(r) for r in rows]}

# ---------- IOC export (JSON / CSV / STIX 2.1) ----------
def _load_case(case_id: str):
    con = connect(); r = con.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone(); con.close()
    if not r: return None
    return dict(r), json.loads(r["result"] or "{}")

@app.get("/api/case/{case_id}/message/{idx}")
async def case_message(case_id: str, idx: int, request: Request):
    """Body preview of one message (M8) — text + sanitised HTML."""
    s = require_auth(request)
    row = _load_case(case_id)
    if not row: return JSONResponse({"error": "not_found"}, status_code=404)
    meta, result = row
    if s["role"] != "admin" and meta.get("user") != s["user"]:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    msgs = result.get("messages") or []
    if idx < 0 or idx >= len(msgs):
        return JSONResponse({"error": "not_found"}, status_code=404)
    body = bodies.read_body(case_id, idx)
    if not body:
        # Fallback (Node parity): the body files are missing (e.g. the DB was
        # copied without DATA_DIR/messages) -> re-derive from the forensic copy.
        ev = data_dir() / "evidence" / f"{case_id}.bin"
        try:
            if ev.exists():
                body = bodies.rebuild_body(case_id, idx, ev.read_bytes(), result.get("format") or "eml")
                if body:
                    m = dict(msgs[idx])
                    m["body"] = {k: body.get(k) for k in
                                 ("hasText", "hasHtml", "truncated", "omitted",
                                  "textBytes", "htmlBytes")}
                    msgs[idx] = m
                    result["messages"] = msgs
                    con = connect()
                    con.execute("UPDATE cases SET result=? WHERE id=?",
                                (json.dumps(result, ensure_ascii=False), case_id))
                    con.commit(); con.close()
        except Exception:
            body = None
    if not body: return JSONResponse({"error": "body_unavailable"}, status_code=404)
    return {"index": idx, **body}

@app.get("/api/ioc/{case_id}.csv")
async def ioc_csv_ep(case_id: str, request: Request, defang: str = "1"):
    require_auth(request)
    row = _load_case(case_id)
    if not row: return JSONResponse({"error": "not_found"}, status_code=404)
    data = ioc_csv(row[1].get("ioc", {}).get("iocs", []), row[0], defang=(defang != "0"))
    return PlainTextResponse(data, media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="{case_id}-ioc.csv"'})

@app.get("/api/ioc/{case_id}")
async def ioc_get(case_id: str, request: Request, format: str = ""):
    require_auth(request)
    row = _load_case(case_id)
    if not row: return JSONResponse({"error": "not_found"}, status_code=404)
    ioc = row[1].get("ioc", {})
    if format.lower() == "stix":
        stix = ioc_stix(ioc.get("iocs", []), row[0])
        return Response(content=json.dumps(stix, indent=2), media_type="application/stix+json",
                        headers={"Content-Disposition": f'attachment; filename="{case_id}-stix.json"'})
    return {"caseId": case_id, **ioc}

# ---------- SIEM export (CEF / ECS / syslog / HEC) ----------
@app.get("/api/export/{case_id}")
async def export_case(case_id: str, request: Request, format: str = "cef"):
    s = require_auth(request)
    row = _load_case(case_id)
    if not row: return JSONResponse({"error": "not_found"}, status_code=404)
    r, result = row
    events = siem.events_from_result(result, s["user"])
    fm = (format or "cef").lower()
    if fm == "cef":
        body, mt, ext = siem.to_cef(events), "text/plain; charset=utf-8", "cef"
    elif fm == "syslog":
        body, mt, ext = siem.to_syslog(events), "text/plain; charset=utf-8", "syslog"
    elif fm == "ecs":
        body, mt, ext = siem.to_ecs(events, result, s["user"]), "application/x-ndjson", "ecs.ndjson"
    elif fm == "elastic":
        body, mt, ext = siem.to_bulk(events, result, s["user"]), "application/x-ndjson", "bulk.ndjson"
    elif fm == "splunk":
        body, mt, ext = siem.to_hec(events, result, s["user"]), "application/json", "hec.json"
    elif fm == "stix":
        stix = ioc_stix(result.get("ioc", {}).get("iocs", []), r)
        return Response(content=json.dumps(stix, indent=2), media_type="application/stix+json",
                        headers={"Content-Disposition": f'attachment; filename="{case_id}-stix.json"'})
    else:
        return JSONResponse({"error": "bad_format"}, status_code=400)
    return Response(content=body, media_type=mt,
                    headers={"Content-Disposition": f'attachment; filename="{case_id}-{ext}"'})

# ---------- dns / ip / map ----------
@app.post("/api/dns")
async def dns(request: Request):
    s = require_auth(request); b = await request.json()
    domain = b.get("domain") or ""
    dtype = str(b.get("type") or "all").lower()
    sel = b.get("selector")
    if dtype == "all":
        recs = {}
        for k in ("a","aaaa","mx","txt","ns","soa"):
            src = lookup_domain(domain, k)
            recs[k] = (src.get("records") or {}).get(k, [])
        return {"source": "native", "domain": domain, "type": "all", "records": recs, "errors": [], "resolver": []}
    out = lookup_domain(domain, dtype, sel)
    if isinstance(out, dict) and out.get("error") == "bad_domain":
        return JSONResponse({"error": "bad_domain"}, status_code=400)
    if isinstance(out, dict) and out.get("error") == "bad_type":
        return JSONResponse({"error": "bad_type"}, status_code=400)
    if isinstance(out, dict) and out.get("error") == "selector":
        return JSONResponse({"error": "selector"}, status_code=400)
    return out

@app.post("/api/ip")
async def ip_lookup(request: Request):
    s = require_auth(request); b = await request.json()
    ip = str(b.get("ip") or "").strip()
    from .enrichment import geo_lookup
    import ipaddress as ipmod
    try: ipmod.ip_address(ip)
    except Exception: return JSONResponse({"error": "bad_ip"}, status_code=400)
    ptr = dns_reverse(ip); geo = geo_lookup(ip)
    return {"source": "native", "ip": ip, "at": now_iso(), "geo": geo, "ptr": {"names": ptr.get("names") or [], "errors": ptr.get("errors") or []},
            "confidence": confidence(geo, ptr.get("names") or []),
            "server": classify_server(ptr.get("names") or [], geo, []),
            "geoStatus": {"city": True, "asn": True, "country": True}}

@app.get("/api/map")
async def map_img(request: Request, ips: str = ""):
    s = require_auth(request)
    vals = [x.strip() for x in (ips or "").split(",") if x.strip()][:15]
    if not vals: return JSONResponse({"error": "ips"}, status_code=400)
    geos = [geo_lookup(v) for v in vals]
    blob = build_map(vals, geos)
    if not blob: return JSONResponse({"error": "no_location"}, status_code=404)
    return Response(content=blob, media_type="image/png")

# ---------- report / map settings / admin ----------
@app.get("/api/report/{case_id}.csv")
async def report_csv(case_id: str, request: Request, lang: str = "en"):
    s = require_auth(request)
    con = connect(); r = con.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone(); con.close()
    if not r: return JSONResponse({"error": "not_found"}, status_code=404)
    result = json.loads(r["result"] or "{}")
    return PlainTextResponse(render_csv(dict(r), result, lang=lang), media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="{case_id}.csv"'})

@app.get("/api/report/{case_id}")
async def report(case_id: str, request: Request, lang: str = "en", format: str = ""):
    s = require_auth(request)
    con = connect(); r = con.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone(); con.close()
    if not r: return JSONResponse({"error": "not_found"}, status_code=404)
    result = json.loads(r["result"] or "{}")
    if format.lower() == "json":
        row_d = dict(r)
        row_d.setdefault("result", "{}")
        j = json.loads(row_d["result"] or "{}")
        j.setdefault("custody", {})
        j["custody"].setdefault("caseId", row_d["id"])
        j["caseMeta"] = {"id": row_d["id"], "ts": row_d["ts"], "user": row_d["user"],
                         "file": row_d["file"], "sha256": row_d["sha256"]}
        return JSONResponse(j)
    if format.lower() == "csv":
        return PlainTextResponse(render_csv(dict(r), result, lang=lang), media_type="text/csv; charset=utf-8",
                                 headers={"Content-Disposition": f'attachment; filename="{case_id}.csv"'})
    sc = require_auth(request)
    vals = [x["ip"] for x in (result.get("ipInfo") or [])][:15]
    b64 = ""
    if vals:
        geos = [geo_lookup(v) for v in vals]
        blob = build_map(vals, geos)
        if blob:
            import base64
            b64 = base64.b64encode(blob).decode()
        # Reverse-geocode each located point (MapGlot) -> legend addresses.
        key = map_key_for(sc["user"]); mlang = lang if lang in ("en",) else "en"
        for x, g in zip(result.get("ipInfo") or [], geos):
            loc = g.get("location") or {}
            x["mapAddr"] = ""
            if loc.get("latitude") is not None and key:
                rg = mapglot_reverse(loc["latitude"], loc["longitude"], key, mlang)
                if rg: x["mapAddr"] = rg.get("address") or rg.get("display") or ""
    html = render_report(dict(r), result, lang=lang, integrity=True, map_base64=b64)
    return HTMLResponse(html)

def map_key_for(user: str) -> str:
    u = re.sub(r"[^A-Za-z0-9._-]", "", user or "")[:32].lower()
    return kv_get(f"mapglot_key:{u}") or kv_get("mapglot_key") or os.getenv("MAPGLOT_API_KEY","").strip()

def map_info(user: str):
    u = re.sub(r"[^A-Za-z0-9._-]", "", user or "")[:32].lower()
    own = kv_get(f"mapglot_key:{u}")
    source = "user" if own else "server" if kv_get("mapglot_key") else "env" if os.getenv("MAPGLOT_API_KEY") else None
    mk = map_key_for(user)
    return {"hasKey": bool(mk), "source": source, "error": mapglot_last_error(mk) if mk else None}

@app.get("/api/settings/map")
async def map_get(request: Request):
    s = require_auth(request); return map_info(s["user"])

@app.post("/api/settings/map")
async def map_post(request: Request):
    s = require_auth(request); b = await request.json()
    key = str(b.get("key") or "").strip()
    u = re.sub(r"[^A-Za-z0-9._-]", "", s["user"] or "")[:32].lower()
    kv_set(f"mapglot_key:{u}", key)
    return map_info(s["user"])

# ---------- settings: reputation / LLM keys (per-user, never echoed) ----------
_REP_KEYS = ("abusech", "vt", "sb")

def _rep_info(user: str) -> dict:
    from . import reputation
    out = {"enabled": reputation.enabled(), "keys": {}}
    for name in _REP_KEYS:
        try:
            from .db import kv_get
            v = kv_get(f"reputation.{name}:{user}")
        except Exception:
            v = None
        out["keys"][name] = {"hasKey": bool(v)}
    return out

@app.get("/api/settings/reputation")
async def rep_get(request: Request):
    s = require_auth(request); return _rep_info(s["user"])

@app.post("/api/settings/reputation")
async def rep_post(request: Request):
    s = require_auth(request); b = await request.json()
    u = re.sub(r"[^A-Za-z0-9._-]", "", s["user"] or "")[:32].lower()
    for name in _REP_KEYS:
        if name in b:
            key = str(b.get(name) or "").strip()[:200]
            kv_set(f"reputation.{name}:{u}", key)
    log(s["user"], "settings_reputation", ",".join(n for n in _REP_KEYS if n in b))
    return _rep_info(s["user"])

@app.get("/api/admin/logs")
async def admin_logs(request: Request):
    require_admin(request)
    con = connect(); rows = con.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 200").fetchall(); con.close()
    return [dict(r) for r in rows]

@app.get("/api/admin/sessions")
async def admin_sessions(request: Request):
    require_admin(request)
    con = connect(); rows = con.execute("SELECT * FROM session_signatures ORDER BY rowid DESC LIMIT 50").fetchall(); con.close()
    return [dict(r) for r in rows]

# --- static UI (same files as Node public/) ---
if APP_PUBLIC.exists():
    app.mount("/", StaticFiles(directory=str(APP_PUBLIC), html=True), name="static")
