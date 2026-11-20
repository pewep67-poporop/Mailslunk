"""Authentication and credentials.

Design notes
------------
* Normal users: bcrypt password + a one-time recovery key (only its bcrypt
  hash is stored). Every account also gets a random hex32 public id.
* Administrators: an offline script derives a high-entropy key from
  ``password + SHA-256(username|CCCD)`` with PBKDF2-HMAC-SHA256 (600k rounds).
  Only the salt (a hash of the CCCD, never the CCCD itself) and a verifier are
  stored. At login the admin types the password; the server re-derives and
  compares. The generated key can be kept offline as a recovery secret.
* No secret is ever printed by the server or written to the audit log.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time

import bcrypt

from .db import connect, log

SESSION_TTL = 8 * 3600
_sessions = {}
_lock = threading.Lock()

ADMIN_KDF_ITER = 600_000
ADMIN_KDF_VERSION = 1
ADMIN_KEY_PREFIX = "MSK1-"


def sha256(v) -> str:
    if isinstance(v, bytes):
        return hashlib.sha256(v).hexdigest()
    return hashlib.sha256(str(v).encode("utf-8")).hexdigest()


def norm_key(k: str) -> str:
    return re.sub(r"[^0-9a-f]", "", k or "", flags=re.I).upper()


def group_key(k: str) -> str:
    return "-".join(k[i:i + 4] for i in range(0, len(k), 4))


def new_recovery_key() -> str:
    return group_key(secrets.token_hex(12).upper())


def new_uid() -> str:
    """Public account id: 32 random hex characters (never sequential)."""
    return secrets.token_hex(16)


def username_ok(name: str) -> bool:
    return bool(name) and bool(re.match(r"^(?=.*[A-Za-z0-9])[A-Za-z0-9._-]{3,32}$", name))


def password_ok(p: str) -> bool:
    return isinstance(p, str) and len(p) >= 10 and len(p.encode("utf-8")) <= 72


def norm_phone(p: str) -> str:
    """Normalise a Vietnamese/international phone number to digits.

    +84 912 345 678 -> 0912345678, 84912345678 -> 0912345678.
    """
    d = re.sub(r"\D", "", p or "")
    if d.startswith("84") and len(d) >= 11:
        d = "0" + d[2:]
    return d


def phone_ok(p: str) -> bool:
    d = norm_phone(p)
    return 8 <= len(d) <= 15 and d.isdigit()


def find_user(name: str):
    """Look up by username, hex32 uid or phone (kept for existing callers)."""
    return find_user_by_login(name)


def find_user_by_login(identifier: str):
    ident = (identifier or "").strip()
    if not ident:
        return None
    con = connect()
    # Exact username / hex32 id first; only then a normalised phone number.
    r = con.execute(
        "SELECT * FROM users WHERE name=? COLLATE NOCASE OR uid=?",
        (ident, ident.lower()),
    ).fetchone()
    if r is None and re.search(r"\d", ident):
        phone = norm_phone(ident)
        if phone:
            r = con.execute(
                "SELECT * FROM users WHERE phone<>'' AND phone=?",
                (phone,),
            ).fetchone()
    con.close()
    return r


def set_recovery(user_id: int) -> str:
    key = new_recovery_key()
    h = bcrypt.hashpw(norm_key(key).encode(), bcrypt.gensalt(rounds=10)).decode()
    con = connect()
    con.execute("UPDATE users SET recovery=? WHERE id=?", (h, user_id))
    con.commit(); con.close()
    return key


# ---------------------------------------------------------------------------
# Administrator credential (PBKDF2-HMAC-SHA256, CCCD-derived salt)
# ---------------------------------------------------------------------------
def admin_salt(username: str, cccd: str) -> bytes:
    raw = "mailsleuth-admin-v1|%s|%s" % ((username or "").strip().lower(),
                                          re.sub(r"\D", "", cccd or ""))
    return hashlib.sha256(raw.encode("utf-8")).digest()


def _admin_verifier(key: bytes) -> bytes:
    return hashlib.sha256(b"mailsleuth-admin-verifier-v1|" + key).digest()


def admin_derive(password: str, salt: bytes, iterations: int = ADMIN_KDF_ITER) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                               int(iterations), dklen=48)


def admin_blob(username: str, password: str, cccd: str,
               iterations: int = ADMIN_KDF_ITER) -> tuple:
    """-> (blob_dict, key_string). The key string is the offline recovery key."""
    if not password or len(password) < 10:
        raise ValueError("admin password must be at least 10 characters")
    if not re.fullmatch(r"\d{9,12}", re.sub(r"\D", "", cccd or "")):
        raise ValueError("CCCD must contain 9-12 digits")
    salt = admin_salt(username, cccd)
    key = admin_derive(password, salt, iterations)
    blob = {
        "v": ADMIN_KDF_VERSION,
        "kdf": "pbkdf2-sha256",
        "iter": int(iterations),
        "salt": base64.b64encode(salt).decode("ascii"),
        "verifier": base64.b64encode(_admin_verifier(key)).decode("ascii"),
    }
    key_str = ADMIN_KEY_PREFIX + base64.urlsafe_b64encode(key).decode("ascii").rstrip("=")
    return blob, key_str


def admin_rekey(blob: dict, new_password: str) -> dict:
    """Change the admin password without needing the CCCD again."""
    if not password_ok(new_password):
        raise ValueError("weak password")
    salt = base64.b64decode(blob["salt"])
    key = admin_derive(new_password, salt, int(blob.get("iter") or ADMIN_KDF_ITER))
    out = dict(blob)
    out["verifier"] = base64.b64encode(_admin_verifier(key)).decode("ascii")
    return out


def admin_verify(blob_json: str, password: str) -> bool:
    try:
        blob = json.loads(blob_json or "{}")
        expected = base64.b64decode(blob["verifier"])
    except Exception:
        return False
    supplied = (password or "").strip()
    try:
        if supplied.startswith(ADMIN_KEY_PREFIX):
            pad = "=" * (-len(supplied[len(ADMIN_KEY_PREFIX):]) % 4)
            key = base64.urlsafe_b64decode(supplied[len(ADMIN_KEY_PREFIX):] + pad)
        else:
            salt = base64.b64decode(blob["salt"])
            key = admin_derive(supplied, salt, int(blob.get("iter") or ADMIN_KDF_ITER))
    except Exception:
        return False
    return hmac.compare_digest(_admin_verifier(key), expected)


def admin_enrolled(row) -> bool:
    try:
        return bool(row and row["admin_kdf"])
    except Exception:
        return False


def verify_password(row, password: str) -> bool:
    if row is None:
        return False
    if (row["role"] or "") == "admin" and admin_enrolled(row):
        return admin_verify(row["admin_kdf"], password)
    try:
        return bcrypt.checkpw((password or "").encode("utf-8"), str(row["hash"]).encode("ascii"))
    except Exception:
        return False


def init_admin():
    """Create the admin row without ever printing a secret.

    A fresh install is intentionally not usable until the operator runs
    ``python tools/admin_keygen.py`` (or sets ADMIN_PASS for a legacy/dev
    bootstrap). This removes the old hard-coded fallback password.
    """
    con = connect()
    r = con.execute("SELECT id, uid FROM users WHERE name='admin' COLLATE NOCASE").fetchone()
    if r:
        con.close()
        return
    from datetime import datetime, timezone
    pw = os.getenv("ADMIN_PASS", "")
    if pw:
        h = bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode()
        note = "legacy ADMIN_PASS bootstrap"
    else:
        # Random, unknown password: login is impossible until keygen runs.
        h = bcrypt.hashpw(secrets.token_hex(32).encode(), bcrypt.gensalt(rounds=12)).decode()
        note = "locked until tools/admin_keygen.py"
    con.execute(
        "INSERT OR IGNORE INTO users(name,hash,role,created,uid) VALUES(?,?,?,?,?)",
        ("admin", h, "admin", datetime.now(timezone.utc).isoformat(), new_uid()),
    )
    con.commit(); con.close()
    print("Admin account initialised (%s). Run: python tools/admin_keygen.py --user admin --cccd <CCCD> --password <password> --write-db" % note)


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------
def start_session(user: str, role: str, login_ms: int = 0, uid: str = ""):
    sid = secrets.token_hex(32)
    csrf = secrets.token_hex(16)
    now = time.time()
    exp = now + SESSION_TTL
    with _lock:
        _sessions[sid] = {"user": user, "role": role, "csrf": csrf, "uid": uid,
                          "started": now, "expires": exp, "loginMs": login_ms, "ended": None}
    try:
        con = connect()
        con.execute(
            "INSERT INTO sessions(sid,user,role,csrf,started,expires,login_ms,ended,uid) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (sid, user, role, csrf, now, exp, login_ms, None, uid),
        )
        con.commit(); con.close()
    except Exception:
        pass
    return sid, csrf, int(exp * 1000)


def drop_session(sid: str, reason: str = "logout"):
    with _lock:
        s = _sessions.get(sid)
        if not s:
            try:
                con = connect()
                r = con.execute("SELECT * FROM sessions WHERE sid=?", (sid,)).fetchone()
                if r:
                    s = {"user": r["user"], "role": r["role"],
                         "started": r["started"], "expires": r["expires"]}
                con.close()
            except Exception:
                s = None
        if not s or s.get("ended"):
            return
        s["ended"] = time.time()
    log(s["user"], "session_end", reason, int(s["ended"] - s["started"]))
    with _lock:
        _sessions.pop(sid, None)
    try:
        con = connect()
        con.execute("DELETE FROM sessions WHERE sid=?", (sid,))
        con.commit(); con.close()
    except Exception:
        pass


def get_session(sid: str):
    if not sid:
        return None
    with _lock:
        s = _sessions.get(sid)
        if s:
            if time.time() > s["expires"]:
                _sessions.pop(sid, None)
                try:
                    con = connect()
                    con.execute("DELETE FROM sessions WHERE sid=?", (sid,))
                    con.commit(); con.close()
                except Exception:
                    pass
                return None
            return s
    try:
        con = connect()
        r = con.execute("SELECT * FROM sessions WHERE sid=?", (sid,)).fetchone()
        con.close()
        if not r:
            return None
        if time.time() > r["expires"]:
            con = connect()
            con.execute("DELETE FROM sessions WHERE sid=?", (sid,))
            con.commit(); con.close()
            return None
        s = {"user": r["user"], "role": r["role"], "csrf": r["csrf"],
             "started": r["started"], "expires": r["expires"],
             "loginMs": r["login_ms"], "ended": None,
             "uid": (r["uid"] if "uid" in r.keys() else "") or ""}
        with _lock:
            _sessions[sid] = s
        return s
    except Exception:
        return None


def drop_all_sessions(username: str):
    with _lock:
        for sid in [k for k, v in _sessions.items() if v["user"] == username]:
            _sessions.pop(sid, None)
    try:
        con = connect()
        con.execute("DELETE FROM sessions WHERE user=?", (username,))
        con.commit(); con.close()
    except Exception:
        pass
