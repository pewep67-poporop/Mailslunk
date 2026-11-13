"""Auth — port of server/auth.js (bcrypt + in-memory sessions + CSRF)."""
import os, re, secrets, hashlib, time, threading
import bcrypt
from .db import connect, log

SESSION_TTL = 8 * 3600  # 8h, same as Node
_sessions = {}
_lock = threading.Lock()

def sha256(v: str) -> str:
    return hashlib.sha256(str(v).encode()).hexdigest()

def norm_key(k: str) -> str:
    return re.sub(r"[^0-9a-f]", "", k or "", flags=re.I).upper()

def group_key(k: str) -> str:
    return "-".join(k[i:i+4] for i in range(0, len(k), 4))

def new_recovery_key() -> str:
    return group_key(secrets.token_hex(12).upper())

def username_ok(name: str) -> bool:
    return bool(name) and bool(re.match(r"^(?=.*[A-Za-z0-9])[A-Za-z0-9._-]{3,32}$", name))

def password_ok(p: str) -> bool:
    return isinstance(p, str) and len(p) >= 10 and len(p.encode("utf-8")) <= 72

def find_user(name: str):
    name = (name or "").strip()
    if not name: return None
    con = connect()
    r = con.execute("SELECT * FROM users WHERE name=? COLLATE NOCASE", (name,)).fetchone()
    con.close(); return r

def set_recovery(user_id: int) -> str:
    key = new_recovery_key()
    h = bcrypt.hashpw(norm_key(key).encode(), bcrypt.gensalt(rounds=10)).decode()
    con = connect(); con.execute("UPDATE users SET recovery=? WHERE id=?", (h, user_id)); con.commit(); con.close()
    return key

def init_admin():
    con = connect()
    r = con.execute("SELECT id FROM users WHERE name='admin' COLLATE NOCASE").fetchone()
    con.close()
    from datetime import datetime, timezone
    if r: return
    pw = os.getenv("ADMIN_PASS", "")
    if not pw:
        print("First run: login admin / <ADMIN_PASS env>")
        pw = "ChangeMe-Admin-123456"
    h = bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=12)).decode()
    con = connect()
    con.execute("INSERT OR IGNORE INTO users(name,hash,role,created) VALUES(?,?,?,?)",
                ("admin", h, "admin", datetime.now(timezone.utc).isoformat()))
    con.commit(); con.close()
    key = set_recovery(1)
    print(f"First run: login admin / {pw}")
    print(f"RECOVERY KEY for admin (save it, shown once): {key}")

def start_session(user: str, role: str, login_ms: int = 0):
    sid = secrets.token_hex(32); csrf = secrets.token_hex(16)
    now = time.time()
    exp = now + SESSION_TTL
    with _lock:
        _sessions[sid] = {"user": user, "role": role, "csrf": csrf,
                          "started": now, "expires": exp, "loginMs": login_ms, "ended": None}
    try:
        con = connect()
        con.execute("INSERT INTO sessions(sid,user,role,csrf,started,expires,login_ms,ended) VALUES(?,?,?,?,?,?,?,?)",
                    (sid, user, role, csrf, now, exp, login_ms, None))
        con.commit(); con.close()
    except Exception: pass
    return sid, csrf, int(exp * 1000)

def drop_session(sid: str, reason: str = "logout"):
    with _lock:
        s = _sessions.get(sid)
        if not s:
            try:
                con = connect(); r = con.execute("SELECT * FROM sessions WHERE sid=?", (sid,)).fetchone()
                if r: s = {"user": r["user"], "role": r["role"], "started": r["started"], "expires": r["expires"]}
                con.close()
            except Exception: s = None
        if not s or s.get("ended"): return
        s["ended"] = time.time()
    log(s["user"], "session_end", reason, int(s["ended"] - s["started"]))
    with _lock:
        _sessions.pop(sid, None)
    try:
        con = connect(); con.execute("DELETE FROM sessions WHERE sid=?", (sid,)); con.commit(); con.close()
    except Exception: pass

def get_session(sid: str):
    with _lock:
        s = _sessions.get(sid)
        if s:
            if time.time() > s["expires"]:
                _sessions.pop(sid, None)
                try:
                    con = connect(); con.execute("DELETE FROM sessions WHERE sid=?", (sid,)); con.commit(); con.close()
                except Exception: pass
                return None
            return s
    try:
        con = connect(); r = con.execute("SELECT * FROM sessions WHERE sid=?", (sid,)).fetchone()
        con.close()
        if not r: return None
        if time.time() > r["expires"]:
            con = connect(); con.execute("DELETE FROM sessions WHERE sid=?", (sid,)); con.commit(); con.close()
            return None
        s = {"user": r["user"], "role": r["role"], "csrf": r["csrf"], "started": r["started"],
             "expires": r["expires"], "loginMs": r["login_ms"], "ended": None}
        with _lock: _sessions[sid] = s
        return s
    except Exception:
        return None

def drop_all_sessions(username: str):
    with _lock:
        for sid in [k for k, v in _sessions.items() if v["user"] == username]:
            _sessions.pop(sid, None)
    try:
        con = connect(); con.execute("DELETE FROM sessions WHERE user=?", (username,)); con.commit(); con.close()
    except Exception: pass
