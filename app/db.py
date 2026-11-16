"""SQLite storage — mirror server/db.js schema (users, audit, cases, kv)."""
import os, shutil, sqlite3, tempfile, threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def data_dir() -> Path:
    p = os.getenv("DATA_DIR", str(ROOT / "data"))
    d = Path(p)
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    for sub in ("uploads", "evidence", "messages", "tmp"):
        (d / sub).mkdir(parents=True, exist_ok=True, mode=0o700)
    return d

def tmp_dir() -> Path:
    """Scratch dir for multipart staging + readpst output.

    Override with MS_TMPDIR; otherwise DATA_DIR/tmp (created by data_dir()).
    """
    p = os.getenv("MS_TMPDIR")
    d = Path(p) if p else data_dir() / "tmp"
    try:
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError:
        d = Path(tempfile.gettempdir())
    return d

def setup_tmpdir() -> Path:
    """Point tempfile at the roomiest drive, NOT blindly at %TEMP%.

    Starlette spools every uploaded file into a SpooledTemporaryFile that rolls
    over to disk after 1 MB — i.e. into %TEMP%. When that drive is full the
    write raises ENOSPC *while FastAPI is parsing the body*, FastAPI wraps it
    into a generic 400 "There was an error parsing the body", and the UI ends up
    showing a meaningless "http_error" for files that were never analyzed.

    Picking the roomiest of (MS_TMPDIR | DATA_DIR/tmp, %TEMP%) keeps a full OS
    drive from killing the whole batch. Call once at startup.
    """
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
