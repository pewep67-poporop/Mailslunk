"""SQLite storage — users, audit, cases, kv, sessions.

The schema is migrated in place: older databases keep working while new
columns (hex32 user id, phone, admin KDF blob, case signature) are added.
"""
import os, secrets, shutil, sqlite3, tempfile, threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def data_dir() -> Path:
    p = os.getenv("DATA_DIR", str(ROOT / "data"))
    d = Path(p)
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    for sub in ("uploads", "evidence", "messages", "tmp", "reports"):
        (d / sub).mkdir(parents=True, exist_ok=True, mode=0o700)
    return d


def tmp_dir() -> Path:
    """Scratch dir for multipart staging and temporary extracts."""
    p = os.getenv("MS_TMPDIR")
    d = Path(p) if p else data_dir() / "tmp"
    try:
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError:
        d = Path(tempfile.gettempdir())
    return d


def setup_tmpdir() -> Path:
    """Point tempfile at the roomiest drive, not blindly at %TEMP%."""
    forced = os.getenv("MS_TMPDIR")
    if forced:
        chosen = Path(forced)
    else:
        sys_tmp = Path(tempfile.gettempdir())
        mine = data_dir() / "tmp"

        def free(p: Path) -> int:
            try:
                return shutil.disk_usage(p).free
            except OSError:
                return -1

        chosen = mine if free(mine) >= free(sys_tmp) else sys_tmp
    try:
        chosen.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError:
        chosen = Path(tempfile.gettempdir())
    tempfile.tempdir = str(chosen)
    return chosen


def db_path() -> Path:
    return data_dir() / "app.db"


_lock = threading.Lock()


def connect():
    con = sqlite3.connect(str(db_path()), check_same_thread=False, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    return con


def _add_column(con, table: str, name: str, decl: str):
    cols = {r["name"] for r in con.execute(f"PRAGMA table_info({table})")}
    if name not in cols:
        con.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")


def init_db():
    con = connect()
    con.executescript("""
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, name TEXT UNIQUE, hash TEXT, role TEXT,
  recovery TEXT, created TEXT, avatar BLOB, avatar_mime TEXT, avatar_updated TEXT);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ts TEXT, user TEXT, action TEXT, detail TEXT, ms INTEGER);
CREATE TABLE IF NOT EXISTS cases(id TEXT PRIMARY KEY, ts TEXT, user TEXT, file TEXT, sha256 TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS session_signatures(
  sid_hash TEXT PRIMARY KEY, user TEXT, role TEXT, started INTEGER, ended INTEGER,
  reason TEXT, prev_hash TEXT, sha256 TEXT, ts TEXT);
CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS sessions(sid TEXT PRIMARY KEY, user TEXT, role TEXT, csrf TEXT, started REAL, expires REAL, login_ms INTEGER, ended REAL);
CREATE TABLE IF NOT EXISTS url_imports(
  id TEXT PRIMARY KEY, ts TEXT, user TEXT, case_id TEXT, source TEXT,
  sha256 TEXT, summary TEXT, entries TEXT);
""")
    # users: hex32 public id, phone login, admin KDF, one-time rename token
    for name, decl in [
        ("recovery", "TEXT"), ("created", "TEXT"), ("avatar", "BLOB"),
        ("avatar_mime", "TEXT"), ("avatar_updated", "TEXT"),
        ("uid", "TEXT"), ("phone", "TEXT"), ("admin_kdf", "TEXT"),
        ("rename_token", "TEXT"), ("rename_exp", "TEXT"),
        ("disabled", "INTEGER DEFAULT 0"),
        ("last_login", "TEXT"),
    ]:
        _add_column(con, "users", name, decl)
    # cases: detached SHA-256 signature + source platform + owner uid.
    # Ownership follows the immutable uid, so renaming an account never
    # rewrites (and never invalidates) an existing signed case.
    for name, decl in [("sig", "TEXT"), ("platform", "TEXT"), ("lang", "TEXT"),
                       ("uid", "TEXT")]:
        _add_column(con, "cases", name, decl)
    # sessions: carry the public id so /api/me can expose it without a lookup
    _add_column(con, "sessions", "uid", "TEXT")
    # Backfill hex32 ids for accounts created before this migration.
    rows = con.execute("SELECT id FROM users WHERE uid IS NULL OR uid=''").fetchall()
    for r in rows:
        con.execute("UPDATE users SET uid=? WHERE id=?", (secrets.token_hex(16), r["id"]))
    con.execute("CREATE UNIQUE INDEX IF NOT EXISTS users_uid ON users(uid)")
    con.execute("CREATE UNIQUE INDEX IF NOT EXISTS users_phone ON users(phone) WHERE phone IS NOT NULL AND phone<>''")
    # Attach legacy cases to the account uid that still owns that name.
    con.execute("UPDATE cases SET uid=(SELECT u.uid FROM users u "
                "WHERE u.name=cases.user COLLATE NOCASE) "
                "WHERE uid IS NULL OR uid=''")
    con.execute("CREATE INDEX IF NOT EXISTS cases_uid ON cases(uid)")
    try:
        con.execute("CREATE UNIQUE INDEX IF NOT EXISTS users_name_nocase ON users(name COLLATE NOCASE)")
    except Exception:
        pass
    con.commit(); con.close()


def log(user: str, action: str, detail: str = "", ms=None):
    con = connect()
    from datetime import datetime, timezone
    con.execute("INSERT INTO audit(ts,user,action,detail,ms) VALUES(?,?,?,?,?)",
                (datetime.now(timezone.utc).isoformat(), user, action, detail, ms))
    con.commit(); con.close()


def kv_get(k: str) -> str:
    con = connect()
    r = con.execute("SELECT v FROM kv WHERE k=?", (k,)).fetchone()
    con.close()
    return (r["v"] if r else "") or ""


def kv_set(k: str, v: str):
    con = connect()
    con.execute("INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, v))
    con.commit(); con.close()
