"""MailSleuth Python — FastAPI server.

Offline-first email forensics: EML / MSG / MBOX / TXT / Maildir. PST/OST is
handled by an external tool (readpst, Outlook export) and imported as EML.

Security model
--------------
* Session cookie is HttpOnly/SameSite=Strict; every mutating request needs the
  per-session CSRF token. The role is re-read from the database on every request,
  so a stale cookie cannot keep an old privilege.
* Normal users: bcrypt password + one-time recovery key + random hex32 id.
* Administrators: PBKDF2-HMAC-SHA256 verifier derived offline from
  password + SHA-256(username|CCCD); only the verifier and the CCCD-derived salt
  are stored. The CCCD itself is never stored.
* Every case read is checked against the owner (admins may read all). Every
  admin endpoint calls require_admin and refuses self-demotion/self-disable.
"""
import base64
import errno
import hashlib
import ipaddress
import json
import os
import re
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import bcrypt
from fastapi import (Depends, FastAPI, File, Form, HTTPException, Request,
                     Response, UploadFile)
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import (FileResponse, HTMLResponse, JSONResponse,
                               PlainTextResponse, StreamingResponse)
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest

from . import auth as A
from . import bodies
from . import graph as entity_graph
from . import urlintel
from .attachments import extract as extract_attachments, findings_for as attachment_findings
from .authcheck import check_auth
from .db import (connect, data_dir, init_db, kv_get, kv_set, log, setup_tmpdir,
                 tmp_dir)
from .dns_local import lookup_auth, lookup_domain, normalize_domain, reverse_ptr as dns_reverse
from .enrichment import classify_server, confidence, geo_lookup, score
from .headers import analyze_headers
from .ioc import extract as ioc_extract, to_csv as ioc_csv, to_stix as ioc_stix
from .mapgen import build_map
from .parsers import (EXT_RE, ParseError, detect_client, load_messages,
                      parse_mbox_bytes, sniff_format)
from .report import (case_signature, render_csv, render_pdf, render_report,
                     stats_rows, url_groups)
from .routing import analyze_routing
from .urls import analyze as analyze_urls

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT / "public"
APP_PUBLIC = PUBLIC

MSG_FILE_MAX = int(os.getenv("MSG_FILE_MAX", str(80 * 1024 * 1024)))
MAX_MESSAGES_PER_FILE = int(os.getenv("MAX_MESSAGES_PER_FILE", "2000"))
LIVE_DNS = False  # forensic mode: no live DNS, snapshot only (P3)
LLM_ALLOW_REMOTE = False


@asynccontextmanager
async def lifespan(app):
    try:
        app.state.tmpdir = str(setup_tmpdir())
    except Exception:
        app.state.tmpdir = None
    init_db()
    A.init_admin()
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
    """Always answer with a flat {"error": "<code>"} body."""
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
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return resp


app.add_middleware(SecurityHeaders)

_hits = {}
AVATAR_RATE_MAX = int(os.getenv("AVATAR_RATE_MAX", "20"))


def rate_check(key: str, max_n: int, window: int = 60) -> bool:
    now = time.time()
    arr = [t for t in _hits.get(key, []) if now - t < window]
    if len(arr) >= max_n:
        return False
    arr.append(now)
    _hits[key] = arr
    return True


class RateLimit(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        p = request.url.path
        ip = request.client.host if request.client else "?"
        limits = {
            "/api/login": (10, f"login:{ip}"),
            "/api/register": (5, f"reg:{ip}"),
            "/api/recover": (5, f"rec:{ip}"),
            "/api/analyze": (40, f"an:{ip}"),
            "/api/analyze/stream": (80, f"ans:{ip}"),
            "/api/urls/import": (30, f"ui:{ip}"),
            "/api/ip": (30, f"tool:{ip}"),
            "/api/dns": (30, f"tool:{ip}"),
        }
        if p in limits:
            n, key = limits[p]
            if not rate_check(key, n):
                return JSONResponse({"error": "rate"}, status_code=429)
        if p == "/api/profile/avatar" and request.method == "POST" and not rate_check(f"av:{ip}", AVATAR_RATE_MAX):
            return JSONResponse({"error": "rate"}, status_code=429)
        return await call_next(request)


app.add_middleware(RateLimit)


def env_bool(k, d=False):
    return os.getenv(k, "1" if d else "0") not in ("0", "false", "False", "")


def now_iso():
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# auth helpers
# ---------------------------------------------------------------------------
def get_session(request: Request) -> Optional[dict]:
    sid = request.cookies.get("sid") or ""
    return A.get_session(sid) if sid else None


def _user_by_name(name: str):
    con = connect()
    r = con.execute("SELECT * FROM users WHERE name=? COLLATE NOCASE", ((name or "").strip(),)).fetchone()
    con.close()
    return r


def _user_by_uid(uid: str):
    con = connect()
    r = con.execute("SELECT * FROM users WHERE uid=?", ((uid or "").strip().lower(),)).fetchone()
    con.close()
    return r


def require_auth(request: Request) -> dict:
    s = get_session(request)
    if not s:
        raise HTTPException(401, detail={"error": "auth"})
    u = _user_by_name(s["user"])
    if not u or int(u["disabled"] or 0):
        A.drop_session(request.cookies.get("sid") or "", "disabled_or_missing")
        raise HTTPException(401, detail={"error": "auth"})
    s["role"] = u["role"] or "analyst"
    s["uid"] = u["uid"] or ""
    if request.method in ("POST", "PUT", "DELETE", "PATCH") and s.get("csrf") != (request.headers.get("x-csrf") or ""):
        raise HTTPException(403, detail={"error": "csrf"})
    return s


def require_admin(request: Request) -> dict:
    s = require_auth(request)
    if s["role"] != "admin":
        raise HTTPException(403, detail={"error": "forbidden"})
    return s


def _can_access_case(s: dict, row: dict) -> bool:
    if s["role"] == "admin":
        return True
    # uid is immutable across renames; fall back to the name only for rows
    # created before the uid migration.
    if row.get("uid"):
        return row.get("uid") == s.get("uid")
    return row.get("user") == s["user"]


def _load_case(case_id: str):
    con = connect()
    r = con.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    con.close()
    if not r:
        return None
    try:
        result = json.loads(r["result"] or "{}")
    except Exception:
        result = {}
    return dict(r), result


def _case_for(s: dict, case_id: str):
    row = _load_case(case_id)
    if not row:
        raise HTTPException(404, detail={"error": "not_found"})
    if not _can_access_case(s, row[0]):
        raise HTTPException(403, detail={"error": "forbidden"})
    return row


# ---------------------------------------------------------------------------
# health / watchdog
# ---------------------------------------------------------------------------
def _health_deep() -> dict:
    comp = {}
    degraded = []
    try:
        con = connect()
        con.execute("SELECT COUNT(*) FROM users").fetchone()
        con.close()
        comp["db"] = "ok"
    except Exception as e:
        comp["db"] = f"error: {type(e).__name__}"
        degraded.append("db")
    try:
        p = data_dir() / "uploads" / ".health"
        p.write_bytes(b"1")
        p.unlink()
        comp["storage"] = "ok"
    except Exception as e:
        comp["storage"] = f"error: {type(e).__name__}"
        degraded.append("storage")
    try:
        from .enrichment import _open
        comp["geoip"] = "ok" if _open() else "missing"
        if not _open():
            degraded.append("geoip")
    except Exception as e:
        comp["geoip"] = f"error: {type(e).__name__}"
        degraded.append("geoip")
    comp["dns"] = "snapshot-only"
    try:
        from .breaker import snapshot
        comp["breakers"] = snapshot()
    except Exception:
        comp["breakers"] = {}
    comp["ml"] = {"state": "removed"}
    return {"components": comp, "degraded": degraded}


@app.get("/api/health")
def health(deep: int = 0):
    from .enrichment import _open
    _open()
    out = {"ok": True, "geo": {"city": True, "asn": True, "country": True},
           "dnsResolvers": 0, "map": "local-schematic", "mxAuto": False,
           "offline": not LIVE_DNS}
    if deep:
        d = _health_deep()
        out.update(d)
        out["ok"] = not d["degraded"]
    return out


def _watchdog_loop(stop_evt, interval: int, threshold: int):
    fails = 0
    while not stop_evt.is_set():
        stop_evt.wait(interval)
        if stop_evt.is_set():
            return
        ok = True
        try:
            con = connect()
            con.execute("SELECT 1").fetchone()
            con.close()
        except Exception:
            ok = False
        if ok:
            try:
                p = data_dir() / "uploads" / ".watchdog"
                p.write_bytes(b"1")
                p.unlink()
            except Exception:
                ok = False
        fails = 0 if ok else fails + 1
        if fails >= threshold:
            try:
                log("system", "watchdog_exit", f"health checks failed {fails}x")
            except Exception:
                pass
            os._exit(1)


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


# ---------------------------------------------------------------------------
# auth endpoints
# ---------------------------------------------------------------------------
@app.post("/api/register")
async def register(request: Request):
    b = await request.json()
    name = str(b.get("user") or "").strip()
    pw = str(b.get("pass") or "")
    phone = A.norm_phone(str(b.get("phone") or ""))
    if not A.username_ok(name):
        return JSONResponse({"error": "bad_user"}, status_code=400)
    if not A.password_ok(pw):
        return JSONResponse({"error": "weak"}, status_code=400)
    if phone and not A.phone_ok(phone):
        return JSONResponse({"error": "bad_phone"}, status_code=400)
    if A.find_user_by_login(name):
        return JSONResponse({"error": "exists"}, status_code=400)
    if phone:
        con = connect()
        dup = con.execute("SELECT 1 FROM users WHERE phone=?", (phone,)).fetchone()
        con.close()
        if dup:
            return JSONResponse({"error": "phone_exists"}, status_code=400)
    uid = A.new_uid()
    h = bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode()
    con = connect()
    con.execute("INSERT INTO users(name,hash,role,created,uid,phone) VALUES(?,?,?,?,?,?)",
                (name, h, "analyst", now_iso(), uid, phone or None))
    row = con.execute("SELECT id FROM users WHERE uid=?", (uid,)).fetchone()
    con.commit()
    con.close()
    key = A.set_recovery(row["id"])
    log(name, "register", f"uid={uid}")
    return {"user": name, "uid": uid, "phone": phone or None, "recovery": key}


@app.post("/api/login")
async def login(request: Request):
    b = await request.json()
    ident = str(b.get("user") or "").strip()
    pw = str(b.get("pass") or "")
    u = A.find_user_by_login(ident)
    if not u:
        try:
            bcrypt.checkpw(pw.encode("utf-8"), b"$2b$12$" + b"x" * 53)
        except Exception:
            pass
        return JSONResponse({"error": "login"}, status_code=401)
    if int(u["disabled"] or 0) or not A.verify_password(u, pw):
        return JSONResponse({"error": "login"}, status_code=401)
    con = connect()
    con.execute("UPDATE users SET last_login=? WHERE id=?", (now_iso(), u["id"]))
    con.commit()
    con.close()
    sid, csrf, exp = A.start_session(u["name"], u["role"], uid=u["uid"] or "")
    resp = JSONResponse({"user": u["name"], "uid": u["uid"], "phone": u["phone"] or "",
                         "role": u["role"], "csrf": csrf, "expiresAt": exp, "loginMs": 0})
    resp.set_cookie("sid", sid, httponly=True, samesite="strict",
                    secure=os.getenv("COOKIE_SECURE", "0") == "1", max_age=A.SESSION_TTL)
    log(u["name"], "login")
    return resp


@app.get("/api/me")
async def me(request: Request):
    s = get_session(request)
    if not s:
        return JSONResponse({"error": "auth"}, status_code=401)
    u = _user_by_name(s["user"])
    if not u or int(u["disabled"] or 0):
        A.drop_session(request.cookies.get("sid") or "", "disabled_or_missing")
        return JSONResponse({"error": "auth"}, status_code=401)
    return {"user": u["name"], "uid": u["uid"], "phone": u["phone"] or "",
            "role": u["role"], "csrf": s["csrf"],
            "expiresAt": int(s["expires"] * 1000), "loginMs": s.get("loginMs", 0)}


@app.post("/api/logout")
async def logout(request: Request):
    require_auth(request)  # also enforces CSRF on this mutating request
    sid = request.cookies.get("sid") or ""
    A.drop_session(sid, "logout")
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("sid")
    return resp


@app.post("/api/password")
async def change_pw(request: Request):
    s = require_auth(request)
    b = await request.json()
    u = _user_by_name(s["user"])
    if not u or not A.verify_password(u, str(b.get("current") or "")):
        return JSONResponse({"error": "pass_bad"}, status_code=400)
    newp = str(b.get("new") or "")
    if not A.password_ok(newp):
        return JSONResponse({"error": "weak"}, status_code=400)
    con = connect()
    if (u["role"] or "") == "admin" and u["admin_kdf"]:
        try:
            blob = json.loads(u["admin_kdf"])
            blob = A.admin_rekey(blob, newp)
            con.execute("UPDATE users SET admin_kdf=? WHERE id=?",
                        (json.dumps(blob), u["id"]))
        except Exception:
            con.close()
            return JSONResponse({"error": "weak"}, status_code=400)
    else:
        h = bcrypt.hashpw(newp.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode()
        con.execute("UPDATE users SET hash=? WHERE id=?", (h, u["id"]))
    con.commit()
    con.close()
    A.drop_all_sessions(s["user"])
    log(s["user"], "password_change")
    return {"ok": True, "relogin": True}


@app.post("/api/recover")
async def recover(request: Request):
    b = await request.json()
    ident = str(b.get("user") or b.get("identifier") or "").strip()
    key = A.norm_key(str(b.get("key") or ""))
    newp = str(b.get("new") or "")
    if not A.password_ok(newp):
        return JSONResponse({"error": "weak"}, status_code=400)
    u = A.find_user_by_login(ident)
    if not u or (u["role"] or "") == "admin" or not u["recovery"]:
        return JSONResponse({"error": "recover"}, status_code=400)
    try:
        ok = bcrypt.checkpw(key.encode("utf-8"), str(u["recovery"]).encode("ascii"))
    except Exception:
        ok = False
    if not ok:
        return JSONResponse({"error": "recover"}, status_code=400)
    h = bcrypt.hashpw(newp.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode()
    con = connect()
    con.execute("UPDATE users SET hash=? WHERE id=?", (h, u["id"]))
    con.commit()
    con.close()
    A.drop_all_sessions(u["name"])
    fresh = A.set_recovery(u["id"])
    log(u["name"], "recover")
    return {"user": u["name"], "recovery": fresh}


# ---------------------------------------------------------------------------
# profile
# ---------------------------------------------------------------------------
@app.get("/api/profile")
async def profile(request: Request):
    s = require_auth(request)
    u = _user_by_name(s["user"])
    return {"user": s["user"], "uid": u["uid"] if u else "", "phone": u["phone"] if u else "",
            "role": s["role"], "created": u["created"] if u else None,
            "lastLogin": u["last_login"] if u else None,
            "hasAvatar": bool(u and u["avatar"]),
            "avatarMime": (u["avatar_mime"] if u else None),
            "avatarUpdated": (u["avatar_updated"] if u else None)}


@app.get("/api/profile/avatar")
async def avatar(request: Request):
    s = require_auth(request)
    u = _user_by_name(s["user"])
    if u and u["avatar"]:
        return Response(content=bytes(u["avatar"]), media_type=u["avatar_mime"] or "image/png",
                        headers={"Cache-Control": "private, max-age=300"})
    return JSONResponse({"error": "not_found"}, status_code=404)


_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_JPG_MAGIC = b"\xff\xd8\xff"


@app.post("/api/profile/avatar")
async def avatar_up(request: Request, avatar: UploadFile | None = File(None)):
    s = require_auth(request)
    if avatar is None:
        return JSONResponse({"error": "bad_avatar"}, status_code=400)
    data = await avatar.read()
    if not data:
        return JSONResponse({"error": "bad_avatar"}, status_code=400)
    if len(data) > 2 * 1024 * 1024:
        return JSONResponse({"error": "avatar_too_large"}, status_code=413)
    if data.startswith(_PNG_MAGIC):
        mime = "image/png"
    elif data.startswith(_JPG_MAGIC):
        mime = "image/jpeg"
    else:
        return JSONResponse({"error": "bad_avatar"}, status_code=400)
    stamp = now_iso()
    con = connect()
    con.execute("UPDATE users SET avatar=?, avatar_mime=?, avatar_updated=? WHERE name=?",
                (data, mime, stamp, s["user"]))
    con.commit()
    con.close()
    log(s["user"], "avatar", f"{len(data)} bytes {mime}")
    return {"ok": True, "avatarUpdated": stamp}


@app.post("/api/profile/rename")
async def rename(request: Request):
    """Rename with the one-time token issued by an administrator."""
    s = require_auth(request)
    b = await request.json()
    token = re.sub(r"[^0-9a-f]", "", str(b.get("token") or ""), flags=re.I).lower()
    new_name = str(b.get("new") or "").strip()
    if not A.username_ok(new_name):
        return JSONResponse({"error": "bad_user"}, status_code=400)
    u = _user_by_name(s["user"])
    if not u or not u["rename_token"] or not u["rename_exp"]:
        return JSONResponse({"error": "rename_token"}, status_code=400)
    try:
        exp = datetime.fromisoformat(str(u["rename_exp"]).replace("Z", "+00:00"))
        if exp < datetime.now(timezone.utc):
            return JSONResponse({"error": "rename_expired"}, status_code=400)
    except Exception:
        return JSONResponse({"error": "rename_token"}, status_code=400)
    if not secrets.compare_digest(hashlib.sha256(token.encode()).hexdigest(), str(u["rename_token"])):
        return JSONResponse({"error": "rename_token"}, status_code=400)
    if not A.verify_password(u, str(b.get("pass") or "")):
        return JSONResponse({"error": "pass_bad"}, status_code=400)
    if A.find_user_by_login(new_name):
        return JSONResponse({"error": "exists"}, status_code=400)
    con = connect()
    con.execute("UPDATE users SET name=?, rename_token=NULL, rename_exp=NULL WHERE id=?",
                (new_name, u["id"]))
    # URL imports and per-account settings follow the account name. Cases are
    # intentionally NOT rewritten: they are owned by uid and keep the analyst
    # name that was recorded (and signed) at analysis time.
    con.execute("UPDATE url_imports SET user=? WHERE user=?", (new_name, s["user"]))
    suffix = ":" + s["user"]
    for r in con.execute("SELECT k FROM kv").fetchall():
        k = r["k"]
        if k.endswith(suffix):
            nk = k[:-len(suffix)] + ":" + new_name
            con.execute("DELETE FROM kv WHERE k=?", (nk,))
            con.execute("UPDATE kv SET k=? WHERE k=?", (nk, k))
    con.commit()
    con.close()
    A.drop_all_sessions(s["user"])
    log(s["user"], "rename", f"-> {new_name}")
    return {"ok": True, "user": new_name}


# ---------------------------------------------------------------------------
# analysis pipeline
# ---------------------------------------------------------------------------
def _forensic_core(fname: str, raw: bytes, do_auth: bool = False, user: str = "") -> dict:
    """M1–M6 for ONE message blob."""
    msgs = load_messages(fname, raw)
    for m in msgs:
        m.setdefault("_raw", raw)
        m.setdefault("_name", fname)
    ips = list(dict.fromkeys([ip for m in msgs for ip in (m.get("originIPs") or [])]))
    sc, verdict = score(msgs)
    hdr = analyze_headers(raw)
    rt = analyze_routing(raw)
    auth = check_auth(raw, live=do_auth)
    urls = analyze_urls(raw, user)
    atts = extract_attachments(fname, raw, quarantine=True, user=user)
    att_f = attachment_findings(atts)
    findings = (hdr["checks"] + rt["anomalies"] + auth["findings"]
                + urls["findings"] + att_f)
    penalty = sum(int(w.get("weight") or 0) for w in findings)
    sc = max(0, min(100, sc - penalty))
    if sc < 50:
        verdict = "malicious_or_phishing"
    elif sc < 85:
        verdict = "suspicious"
    if any(a["verdict"] == "malicious" for a in atts):
        verdict = "malicious_or_phishing"
    return {"msgs": msgs, "ips": ips, "score": sc, "verdict": verdict,
            "hdr": hdr, "rt": rt, "auth": auth, "urls": urls["urls"],
            "atts": atts, "findings": findings, "raw": raw}


def _enrich(msgs: list, ips: list) -> tuple:
    """Domain DNS + IP intel once per file/case. Live DNS is opt-in."""
    domains = [normalize_domain((m.get("from") or "")) for m in msgs]
    domains = list(dict.fromkeys([d for d in domains if d]))[:5]
    dns_map = {}
    # DNS lịch sử: chỉ đọc snapshot do người dùng cung cấp (P3). Không query live.
    for d in domains:
        try:
            dns_map[d] = lookup_auth(d)
        except Exception:
            dns_map[d] = {"auth": {}, "records": {}, "source": "unavailable"}
    ip_info = []
    for ip in ips[:20]:
        try:
            ptr = dns_reverse(ip)
        except Exception:
            ptr = {"names": [], "errors": []}
        geo = geo_lookup(ip)
        names = ptr.get("names") or []
        ip_info.append({"ip": ip, "geo": geo, "ptr": names,
                        "confidence": confidence(geo, names),
                        "server": classify_server(names, geo, []),
                        "assessment": {"verdict": "unverified",
                                       "reasons": [f"PTR: {', '.join(names)}" if names else "no PTR record"]}})
    return dns_map, ip_info


def _platform_for(platform: str, fmt: str, fname: str, msgs: list) -> str:
    p = (platform or "auto").strip().lower()
    if p in ("windows", "linux"):
        return p
    low = (fname or "").lower().replace("\\", "/")
    if fmt in ("msg",) or low.endswith(".msg"):
        return "windows"
    if fmt == "mbox" or "/cur/" in low or "/new/" in low:
        return "linux"
    if msgs:
        c = detect_client(msgs[0].get("_name") or fname, msgs[0].get("_raw") or b"").get("key")
        if c in ("thunderbird", "apple", "maildir"):
            return "linux"
    return "windows"


def _analyze_one(fname: str, raw: bytes, user: str, src_path: str = None,
                 platform: str = "auto", lang: str = "en", uid: str = ""):
    """M1→M7 for one uploaded file. Returns (result, error)."""
    size = len(raw) if raw is not None else (os.path.getsize(src_path) if src_path and os.path.exists(src_path) else 0)
    if size > MSG_FILE_MAX:
        return None, {"file": fname, "error": "too_large"}
    if raw is None and src_path and os.path.exists(src_path):
        with open(src_path, "rb") as fh:
            raw = fh.read()
    if raw is None:
        return None, {"file": fname, "error": "parse"}
    fmt = sniff_format(fname, raw)
    if not fmt:
        return None, {"file": fname, "error": "file"}
    sha = hashlib.sha256(raw).hexdigest()
    truncated = False

    try:
        if fmt == "mbox":
            items = parse_mbox_bytes(raw)
            if not items:
                return None, {"file": fname, "error": "empty"}
            if len(items) > MAX_MESSAGES_PER_FILE:
                items = items[:MAX_MESSAGES_PER_FILE]
                truncated = True
            chunks = []
            for idx, item in enumerate(items):
                mraw = item.get("_raw") or b""
                chunks.append(_forensic_core(f"{fname}#{idx + 1}.eml", mraw,
                                             do_auth=False, user=user))
        else:
            chunks = [_forensic_core(fname, raw, do_auth=False, user=user)]
    except ParseError as e:
        return None, {"file": fname, "error": e.code}
    except Exception:
        return None, {"file": fname, "error": "parse"}

    findings, atts, urls, messages, ips = [], [], [], [], []
    msgs_all, seen_urls, seen_ips = [], set(), set()
    body_items = []
    for idx, ch in enumerate(chunks):
        msgs_all.extend(ch["msgs"])
        av = {k: ch["auth"].get(k) for k in
              ("spf", "dkim", "dmarc", "authSeen", "clientIp", "fromDomain", "envDomain")}
        for m in (ch["msgs"] or [{}]):
            msg_index = len(messages)
            mraw = m.get("_raw") or b""
            client = detect_client(m.get("_name") or fname, mraw)
            messages.append({"subject": m.get("subject", ""), "from": m.get("from", ""),
                             "fromName": m.get("fromName", ""), "date": m.get("date", ""),
                             "to": [x.strip() for x in re.split(r"[,;]", (m.get("to") or "")) if x.strip()],
                             "cc": [x.strip() for x in re.split(r"[,;]", (m.get("cc") or "")) if x.strip()],
                             "replyTo": m.get("replyTo", ""),
                             "returnPath": m.get("returnPath", ""),
                             "messageId": m.get("message_id", ""),
                             "score": ch["score"], "verdict": ch["verdict"],
                             "originIPs": m.get("originIPs") or [], "auth": av,
                             "client": client, "index": msg_index})
            if mraw:
                body_items.append((msg_index, m.get("_name") or fname, mraw))
        room = 3000 - len(findings)
        for f in ch["findings"][:max(0, room)]:
            f = dict(f)
            f["m"] = idx
            findings.append(f)
        room = 3000 - len(atts)
        for a in ch["atts"][:max(0, room)]:
            a = dict(a)
            a["m"] = idx
            atts.append(a)
        for u in ch["urls"]:
            key = (u.get("url") or "").lower()
            if key and key not in seen_urls:
                seen_urls.add(key)
                urls.append(u)
        for ip in ch["ips"]:
            if ip not in seen_ips and len(ips) < 20:
                seen_ips.add(ip)
                ips.append(ip)

    worst = min(chunks, key=lambda c: (c["score"], c["verdict"] == "clean"))
    sc, verdict = worst["score"], worst["verdict"]
    if any(c["verdict"] == "malicious_or_phishing" for c in chunks) or \
       any(a.get("verdict") == "malicious" for a in atts):
        verdict = "malicious_or_phishing"
    auth = worst["auth"]
    hdr, rt = worst["hdr"], worst["rt"]
    auth_seen = all(ch["auth"].get("authSeen") for ch in chunks)
    dns_map, ip_info = _enrich(msgs_all, ips)
    plat = _platform_for(platform, fmt, fname, msgs_all)

    feature_src = {
        "format": fmt, "count": len(messages), "score": sc, "verdict": verdict,
        "headerAnalysis": {"checks": worst["hdr"]["checks"], "receivedCount": worst["hdr"]["receivedCount"]},
        "routing": {"hops": worst["rt"]["hops"], "anomalies": worst["rt"]["anomalies"],
                    "totalDelayMs": worst["rt"]["totalDelayMs"]},
        "auth": worst["auth"], "urls": urls, "attachments": atts, "findings": findings,
    }
    # ML/LLM bị gỡ: verdict chỉ từ evidence rule-based (xem TIEN_DO_BUILD.md).
    case_id = uuid.uuid4().hex[:12]
    ev_path = data_dir() / "evidence" / f"{case_id}.bin"
    if src_path and os.path.exists(src_path):
        import shutil as _sh
        with open(src_path, "rb") as src, open(ev_path, "wb") as dst:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                dst.write(chunk)
    else:
        ev_path.write_bytes(raw)
    try:
        os.chmod(ev_path, 0o444)
    except Exception:
        pass
    try:
        for meta in bodies.save_bodies(case_id, body_items):
            i = meta.get("index")
            if isinstance(i, int) and 0 <= i < len(messages):
                messages[i]["body"] = {k: meta.get(k) for k in
                                       ("hasText", "hasHtml", "truncated", "omitted",
                                        "textBytes", "htmlBytes")}
    except Exception:
        pass
    ts = now_iso()
    result = {"format": fmt, "count": len(messages), "truncated": truncated,
              "authSeen": auth_seen, "verdict": verdict, "score": sc,
              "platform": plat, "lang": lang,
              "client": (messages[0].get("client") if messages else {"key": "generic", "label": "RFC 822 / EML"}),
              "custody": {"caseId": case_id, "original": fname, "sha256": sha, "utc": ts},
              "messages": messages,
              "findings": findings, "attachments": atts, "originIPs": ips,
              "urls": urls,
              "headerAnalysis": {"checks": hdr["checks"], "receivedCount": hdr["receivedCount"],
                                 "headers": hdr["headers"], "fromDomain": hdr["fromDomain"],
                                 "returnPathDomain": hdr["returnPathDomain"], "replyToDomain": hdr["replyToDomain"]},
              "routing": {"hops": rt["hops"], "anomalies": rt["anomalies"],
                          "totalDelayMs": rt["totalDelayMs"], "hopCount": rt["hopCount"]},
              "auth": {k: auth.get(k) for k in ("spf", "dkim", "dmarc", "alignment", "overall",
                                                "authSeen", "clientIp", "fromDomain", "envDomain",
                                                "envAddr", "fromAddr", "replyTo", "headerFound",
                                                "authservId", "raw", "upstream", "dkimSignatures")},
              "dns": dns_map, "ipInfo": ip_info, "offline": not LIVE_DNS}
    result["ioc"] = ioc_extract(result)
    try:
        from .relations import build as build_relations
        result["relations"] = build_relations(result)
    except Exception:
        result["relations"] = {"relations": [], "count": 0, "byKind": {}}
    try:
        result["graph"] = entity_graph.summary(result)
    except Exception:
        result["graph"] = {"nodes": 0, "edges": 0, "byKind": {}, "truncated": False}
    row = {"id": case_id, "ts": ts, "user": user, "file": fname, "sha256": sha}
    sig = case_signature(row, result)
    result["signature"] = {"sha256": sig, "at": ts, "alg": "SHA-256"}
    con = connect()
    con.execute("INSERT INTO cases(id,ts,user,file,sha256,result,sig,platform,lang,uid) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (case_id, ts, user, fname, sha, json.dumps(result, ensure_ascii=False), sig, plat, lang, uid))
    con.commit()
    con.close()
    log(user, "analyze", fname)
    # SIEM bị gỡ hoàn toàn: không đẩy sự kiện ra ngoài.
    return result, None


def _nd(o) -> str:
    return json.dumps(o, ensure_ascii=False, separators=(",", ":")) + "\n"


@app.post("/api/analyze/stream")
async def analyze_stream(request: Request, file: UploadFile = File(...),
                         platform: str = Form("auto"), lang: str = Form("en")):
    """NDJSON progress stream for ONE file: stage events, then the result.

    The client uploads files sequentially, so a crash stops exactly at the
    failing file and the next request can resume from the following one.
    """
    s = require_auth(request)
    fname = file.filename or "upload.eml"
    up_dir = data_dir() / "uploads"
    up_dir.mkdir(parents=True, exist_ok=True)
    tmp_path = up_dir / f"{uuid.uuid4().hex}.bin"

    # FastAPI closes the UploadFile as soon as the endpoint returns, so the
    # upload is staged before the streaming response starts.
    size = 0
    try:
        with open(tmp_path, "wb") as out:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MSG_FILE_MAX:
                    return JSONResponse({"error": "too_large"}, status_code=413)
                out.write(chunk)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        return JSONResponse({"error": "upload"}, status_code=400)

    async def gen():
        try:
            yield _nd({"type": "stage", "stage": "receive", "file": fname,
                       "bytes": size, "pct": 8})
            yield _nd({"type": "stage", "stage": "parse", "file": fname,
                       "bytes": size, "pct": 25})
            try:
                result, err = await run_in_threadpool(_analyze_one, fname, None,
                                                      s["user"], str(tmp_path),
                                                      platform, lang, s.get("uid", ""))
            except Exception as e:
                result, err = None, {"file": fname, "error": "parse",
                                     "detail": f"{type(e).__name__}: {e}"}
            if err:
                yield _nd({"type": "error", **err, "pct": 100})
            else:
                yield _nd({"type": "result", "result": result, "pct": 100})
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    return StreamingResponse(gen(), media_type="application/x-ndjson",
                             headers={"Cache-Control": "no-store",
                                      "X-Accel-Buffering": "no"})


@app.post("/api/analyze")
async def analyze(request: Request, files: list[UploadFile] | None = File(None),
                  platform: str = Form("auto"), lang: str = Form("en")):
    s = require_auth(request)
    if not files:
        return JSONResponse({"error": "file"}, status_code=400)
    results = []
    errors = []
    up_dir = data_dir() / "uploads"
    up_dir.mkdir(parents=True, exist_ok=True)
    for f in files:
        tmp_path = up_dir / f"{uuid.uuid4().hex}.bin"
        try:
            with open(tmp_path, "wb") as out:
                while True:
                    chunk = await f.read(1024 * 1024)
                    if not chunk:
                        break
                    out.write(chunk)
            result, err = await run_in_threadpool(_analyze_one, f.filename, None,
                                                  s["user"], str(tmp_path), platform, lang,
                                                  s.get("uid", ""))
            if err:
                errors.append(err)
            else:
                results.append(result)
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    return {"results": results, "errors": errors}


def feature_source(fname: str, raw: bytes) -> dict:
    """Result-shaped dict for the ML feature extractor (no side effects)."""
    fmt = sniff_format(fname, raw) or "eml"
    msgs = load_messages(fname, raw)
    hdr = analyze_headers(raw)
    rt = analyze_routing(raw)
    auth = check_auth(raw, live=False)
    urls = analyze_urls(raw, "")
    atts = extract_attachments(fname, raw, quarantine=False, user="")
    att_f = attachment_findings(atts)
    findings = (hdr["checks"] + rt["anomalies"] + auth["findings"]
                + urls["findings"] + att_f)
    return {"format": fmt, "count": len(msgs), "score": 0, "verdict": "clean",
            "headerAnalysis": {"checks": hdr["checks"], "receivedCount": hdr["receivedCount"]},
            "routing": {"hops": rt["hops"], "anomalies": rt["anomalies"],
                        "totalDelayMs": rt["totalDelayMs"]},
            "auth": auth, "urls": urls["urls"], "attachments": atts,
            "findings": findings}


# ---------------------------------------------------------------------------
# cases / message detail
# ---------------------------------------------------------------------------
@app.get("/api/cases")
async def cases(request: Request, q: str = "", limit: int = 100):
    s = require_auth(request)
    limit = max(1, min(int(limit or 100), 500))
    con = connect()
    fields = """id, ts, user, file, sha256, sig, platform, lang,
        CASE WHEN json_valid(result) THEN json_extract(result,'$.format') END AS format,
        CASE WHEN json_valid(result) THEN json_extract(result,'$.count') END AS count,
        CASE WHEN json_valid(result) THEN json_extract(result,'$.score') END AS score,
        CASE WHEN json_valid(result) THEN json_extract(result,'$.verdict') END AS verdict"""
    if s["role"] == "admin":
        rows = con.execute(f"SELECT {fields} FROM cases WHERE file LIKE ? OR user LIKE ? OR id LIKE ? ORDER BY ts DESC LIMIT ?",
                           (f"%{q}%", f"%{q}%", f"%{q}%", limit)).fetchall()
    else:
        rows = con.execute(f"SELECT {fields} FROM cases WHERE (uid=? OR (uid IS NULL AND user=?)) "
                           "AND (file LIKE ? OR id LIKE ?) ORDER BY ts DESC LIMIT ?",
                           (s.get("uid", ""), s["user"], f"%{q}%", f"%{q}%", limit)).fetchall()
    con.close()
    return {"cases": [dict(r) for r in rows]}


@app.get("/api/case/{case_id}/message/{idx}")
async def case_message(case_id: str, idx: int, request: Request):
    """Headers + text/HTML body of one message (evidence-preserving)."""
    s = require_auth(request)
    meta, result = _case_for(s, case_id)
    msgs = result.get("messages") or []
    if idx < 0 or idx >= len(msgs):
        return JSONResponse({"error": "not_found"}, status_code=404)
    body = bodies.read_body(case_id, idx)
    if not body:
        ev = data_dir() / "evidence" / f"{case_id}.bin"
        try:
            if ev.exists():
                body = bodies.rebuild_body(case_id, idx, ev.read_bytes(),
                                           result.get("format") or "eml")
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
                    con.commit()
                    con.close()
        except Exception:
            body = None
    if not body:
        return JSONResponse({"error": "body_unavailable"}, status_code=404)
    return {"index": idx, "meta": msgs[idx], **body}


@app.get("/api/case/{case_id}/graph")
async def case_graph(case_id: str, request: Request, lang: str = "en"):
    s = require_auth(request)
    _, result = _case_for(s, case_id)
    g = entity_graph.build(result)
    return {"graph": g, "summary": entity_graph.summary(result), "lang": lang}


@app.get("/api/case/{case_id}/relations")
async def case_relations(case_id: str, request: Request, csv_out: int = 0):
    s = require_auth(request)
    _, result = _case_for(s, case_id)
    rel = result.get("relations") or {"relations": [], "count": 0, "byKind": {}}
    if csv_out:
        from .relations import to_csv
        return PlainTextResponse(to_csv(rel.get("relations") or [], case_id),
                                 media_type="text/csv; charset=utf-8",
                                 headers={"Content-Disposition": f'attachment; filename="{case_id}-relations.csv"'})
    return {"caseId": case_id, **rel}


@app.get("/api/case/{case_id}/graph.svg")
async def case_graph_svg(case_id: str, request: Request, lang: str = "en"):
    s = require_auth(request)
    _, result = _case_for(s, case_id)
    svg = entity_graph.to_svg(entity_graph.build(result), lang)
    return Response(content=svg, media_type="image/svg+xml",
                    headers={"Content-Disposition": f'inline; filename="{case_id}-graph.svg"'})


@app.get("/api/case/{case_id}/urls")
async def case_urls(case_id: str, request: Request, lang: str = "en"):
    s = require_auth(request)
    _, result = _case_for(s, case_id)
    groups = url_groups(result, lang)
    return {"caseId": case_id, "groups": groups,
            "summary": {"total": sum(len(g["urls"]) for g in groups),
                        "groups": len(groups)}}


@app.get("/api/case/{case_id}/urls.csv")
async def case_urls_csv(case_id: str, request: Request, lang: str = "en"):
    s = require_auth(request)
    row, result = _case_for(s, case_id)
    data = render_csv(row, result, lang=lang, kind="urls")
    return PlainTextResponse(data, media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="{case_id}-urls.csv"'})


# ---------------------------------------------------------------------------
# IOC exports (local only)
# ---------------------------------------------------------------------------
@app.get("/api/ioc/{case_id}.csv")
async def ioc_csv_ep(case_id: str, request: Request, defang: str = "1"):
    s = require_auth(request)
    row, _ = _case_for(s, case_id)
    data = ioc_csv(row.get("ioc", {}).get("iocs", []), row, defang=(defang != "0"))
    return PlainTextResponse(data, media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="{case_id}-ioc.csv"'})


@app.get("/api/ioc/{case_id}")
async def ioc_get(case_id: str, request: Request, format: str = ""):
    s = require_auth(request)
    row, result = _case_for(s, case_id)
    ioc = result.get("ioc", {})
    if format.lower() == "stix":
        stix = ioc_stix(ioc.get("iocs", []), row)
        return Response(content=json.dumps(stix, indent=2), media_type="application/stix+json",
                        headers={"Content-Disposition": f'attachment; filename="{case_id}-stix.json"'})
    return {"caseId": case_id, **ioc}


# ---------------------------------------------------------------------------
# URL import / re-analysis (offline local rules)
# ---------------------------------------------------------------------------
@app.post("/api/urls/import")
async def urls_import(request: Request, files: list[UploadFile] | None = File(None),
                      case_id: str = Form("")):
    s = require_auth(request)
    if not files:
        return JSONResponse({"error": "file"}, status_code=400)
    all_entries = []
    sources = []
    h = hashlib.sha256()
    for f in files:
        data = await f.read()
        h.update(data)
        try:
            entries = urlintel.parse_upload(f.filename or "", data)
        except ValueError:
            return JSONResponse({"error": "file_too_large"}, status_code=413)
        sources.append(f.filename or "")
        all_entries.extend(entries)
    # Deduplicate by URL, keep the first imported verdict.
    seen = {}
    for e in all_entries:
        u = (e.get("url") or "").strip()
        if u and u not in seen:
            seen[u] = e
    analyzed = urlintel.analyze_entries(list(seen.values()))
    summary = urlintel.summary(analyzed)
    import_id = uuid.uuid4().hex[:12]
    ts = now_iso()
    con = connect()
    con.execute("INSERT INTO url_imports(id,ts,user,case_id,source,sha256,summary,entries) VALUES(?,?,?,?,?,?,?,?)",
                (import_id, ts, s["user"], case_id or "", ", ".join(sources)[:500], h.hexdigest(),
                 json.dumps(summary, ensure_ascii=False), json.dumps(analyzed, ensure_ascii=False)))
    con.commit()
    con.close()
    merged = 0
    if case_id:
        try:
            row, result = _case_for(s, case_id)
            by_url = {(u.get("url") or "").lower(): u for u in (result.get("urls") or [])}
            for e in analyzed:
                cur = by_url.get(e["url"].lower())
                if cur:
                    cur["imported"] = {"verdict": e.get("verdict"), "risk": e.get("risk"),
                                       "source": e.get("source"), "reasons": e.get("reasons")}
                    cur["risk"] = max(int(cur.get("risk") or 0), int(e.get("risk") or 0))
                    if e.get("verdict") == "malicious":
                        cur["verdict"] = "malicious"
                    elif e.get("verdict") == "suspicious" and cur.get("verdict") == "clean":
                        cur["verdict"] = "suspicious"
                    cur["reasons"] = list(dict.fromkeys((cur.get("reasons") or []) + (e.get("reasons") or [])))[:12]
                    merged += 1
                else:
                    result.setdefault("urls", []).append({
                        "url": e["url"], "host": e.get("host"), "risk": e.get("risk"),
                        "verdict": e.get("verdict"), "reasons": e.get("reasons") or [],
                        "m": None, "target": "imported", "source": e.get("source") or "import",
                    })
            result.setdefault("urlImports", []).append({"id": import_id, "ts": ts, "count": len(analyzed),
                                                        "summary": summary, "merged": merged})
            row2 = dict(row)
            row2["sha256"] = row.get("sha256")
            sig = case_signature(row2, result)
            result["signature"] = {"sha256": sig, "at": now_iso(), "alg": "SHA-256"}
            con = connect()
            con.execute("UPDATE cases SET result=?, sig=? WHERE id=?",
                        (json.dumps(result, ensure_ascii=False), sig, case_id))
            con.commit()
            con.close()
            log(s["user"], "url_import", f"{case_id} {len(analyzed)} urls")
        except HTTPException:
            pass
    return {"id": import_id, "ts": ts, "caseId": case_id or None, "summary": summary,
            "entries": analyzed, "merged": merged, "sources": sources}


@app.get("/api/urlintel/{import_id}.csv")
async def urlintel_csv(import_id: str, request: Request, lang: str = "en"):
    s = require_auth(request)
    con = connect()
    r = con.execute("SELECT * FROM url_imports WHERE id=?", (import_id,)).fetchone()
    con.close()
    if not r:
        return JSONResponse({"error": "not_found"}, status_code=404)
    if s["role"] != "admin" and r["user"] != s["user"]:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    data = urlintel.to_csv(json.loads(r["entries"] or "[]"), lang)
    return PlainTextResponse(data, media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="{import_id}-urls.csv"'})


@app.get("/api/urlintel/{import_id}")
async def urlintel_get(import_id: str, request: Request):
    s = require_auth(request)
    con = connect()
    r = con.execute("SELECT * FROM url_imports WHERE id=?", (import_id,)).fetchone()
    con.close()
    if not r:
        return JSONResponse({"error": "not_found"}, status_code=404)
    if s["role"] != "admin" and r["user"] != s["user"]:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    return {"id": r["id"], "ts": r["ts"], "user": r["user"], "caseId": r["case_id"],
            "source": r["source"], "sha256": r["sha256"],
            "summary": json.loads(r["summary"] or "{}"),
            "entries": json.loads(r["entries"] or "[]")}


# ---------------------------------------------------------------------------
# DNS / IP / local map
# ---------------------------------------------------------------------------
@app.post("/api/dns")
async def dns(request: Request):
    require_auth(request)
    b = await request.json()
    domain = b.get("domain") or ""
    dtype = str(b.get("type") or "all").lower()
    sel = b.get("selector")
    if dtype == "all":
        recs = {}
        for k in ("a", "aaaa", "mx", "txt", "ns", "soa"):
            src = lookup_domain(domain, k)
            recs[k] = (src.get("records") or {}).get(k, [])
        return {"source": "native", "domain": domain, "type": "all", "records": recs,
                "errors": [], "resolver": []}
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
    require_auth(request)
    b = await request.json()
    ip = str(b.get("ip") or "").strip()
    try:
        ipaddress.ip_address(ip)
    except Exception:
        return JSONResponse({"error": "bad_ip"}, status_code=400)
    ptr = dns_reverse(ip)
    geo = geo_lookup(ip)
    return {"source": "native", "ip": ip, "at": now_iso(), "geo": geo,
            "ptr": {"names": ptr.get("names") or [], "errors": ptr.get("errors") or []},
            "confidence": confidence(geo, ptr.get("names") or []),
            "server": classify_server(ptr.get("names") or [], geo, []),
            "geoStatus": {"city": True, "asn": True, "country": True}}


@app.get("/api/map")
async def map_img(request: Request, ips: str = ""):
    require_auth(request)
    vals = [x.strip() for x in (ips or "").split(",") if x.strip()][:15]
    if not vals:
        return JSONResponse({"error": "ips"}, status_code=400)
    geos = [geo_lookup(v) for v in vals]
    blob = build_map(vals, geos)
    if not blob:
        return JSONResponse({"error": "no_location"}, status_code=404)
    return Response(content=blob, media_type="image/png")


@app.get("/api/settings/map")
async def map_get(request: Request):
    require_auth(request)
    return {"mode": "local", "hasKey": False, "source": "local",
            "error": None, "tileSource": "schematic", "offline": True}


@app.post("/api/settings/map")
async def map_post(request: Request):
    require_auth(request)
    return {"mode": "local", "hasKey": False, "source": "local",
            "error": None, "tileSource": "schematic", "offline": True}


# ---------------------------------------------------------------------------
# static UI
# ---------------------------------------------------------------------------
if APP_PUBLIC.exists():
    app.mount("/", StaticFiles(directory=str(APP_PUBLIC), html=True), name="static")
