"""SQLite storage — mirror server/db.js schema (users, audit, cases, kv)."""
import os, sqlite3, threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def data_dir() -> Path:
    p = os.getenv("DATA_DIR", str(ROOT / "data"))
    d = Path(p)
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    for sub in ("uploads", "evidence", "messages"):
        (d / sub).mkdir(parents=True, exist_ok=True, mode=0o700)
    return d

def db_path() -> Path:
    return data_dir() / "app.db"

_lock = threading.Lock()

def connect():
    con = sqlite3.connect(str(db_path()), check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    return con

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
""")
    cols = {r["name"] for r in con.execute("PRAGMA table_info(users)")}
    for name, decl in [("recovery","TEXT"),("created","TEXT"),("avatar","BLOB"),
                       ("avatar_mime","TEXT"),("avatar_updated","TEXT")]:
        if name not in cols:
            con.execute(f"ALTER TABLE users ADD COLUMN {name} {decl}")
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
