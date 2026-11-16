"""Parsers — EML/MBOX/TXT via stdlib email; PST/OST via an external extractor.

PST/OST is never parsed in-process. Either libpst's ``readpst`` (Linux/Docker)
or the bundled Python extractor ``tools/pst_extract.py`` (pypff, runs in WSL)
writes one .eml per message into a private temp dir; the normal per-message
pipeline then runs on each .eml. Errors bubble up as :class:`ParseError` with
the same stable codes as the Node server (``readpst_missing`` / ``pst_timeout``
/ ``readpst_failed`` / ``format_mismatch`` / ``empty``).
"""
import email, json, re, mailbox, io, os, shutil, subprocess, sys, tempfile
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, parsedate_to_datetime
import ipaddress as ipmod

EXT_RE = re.compile(r"\.(eml|msg|mbox|pst|ost|emlx|mht|mhtml|txt)$", re.I)
BIG = {".pst", ".ost"}
PST_MAGIC = b"!BDN"
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class ParseError(Exception):
    """Stable error code consumed by /api/analyze (mirrors Node error strings)."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _pst_int(name: str, default: int) -> int:
    try:
        return max(1, int(os.getenv(name, str(default))))
    except Exception:
        return default


def _wsl_path(p: str) -> str:
    """C:\\path -> /mnt/c/path for a Linux subprocess launched through WSL."""
    m = re.match(r"^([A-Za-z]):[\\/](.*)$", p or "")
    if m:
        return "/mnt/%s/%s" % (m.group(1).lower(), m.group(2).replace("\\", "/"))
    return (p or "").replace("\\", "/")


def _python_extractor() -> list:
    """Command prefix for the bundled pypff extractor (WSL on Windows, native on Linux)."""
    tool = os.getenv("PST_PYEXTRACT") or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "tools", "pst_extract.py")
    if not os.path.isfile(tool):
        return None
    if os.name != "nt":
        return [sys.executable or "python3", tool]
    wsl = shutil.which("wsl.exe") or shutil.which("wsl")
    if not wsl:
        return None
    return [wsl, "-e", "python3", _wsl_path(tool)]


def extract_pst(fname: str, raw: bytes = None, path: str = None):
    """Extract a PST/OST container to a list of (name, eml_bytes).

    Returns ``(messages, truncated)``. Raises ParseError on every failure so the
    API can answer with a machine-readable code instead of a stack trace.
    Caps are env-tunable: PST_MAX_MSGS (1000), PST_MAX_BYTES (200 MB),
    PST_TIMEOUT (300 s).

    ``path`` lets the caller hand over a file on disk: a 500 MB PST is then
    never loaded into RAM (readpst reads the file itself).
    """
    ext = os.path.splitext(fname or "")[1].lower()
    if ext not in BIG:
        raise ParseError("format_mismatch")
    src_path = None
    if path:
        if not os.path.exists(path):
            raise ParseError("format_mismatch")
        with open(path, "rb") as fh:
            head = fh.read(4)
        if head != PST_MAGIC:
            raise ParseError("format_mismatch")
        src_path = path
    else:
        if not raw:
            raise ParseError("empty")
        if not raw.startswith(PST_MAGIC):
            raise ParseError("format_mismatch")
    if not raw and not src_path:
        raise ParseError("empty")

    exe = shutil.which("readpst")
    pycmd = None if exe else _python_extractor()
    if not exe and not pycmd:
        raise ParseError("readpst_missing")

    max_msgs = _pst_int("PST_MAX_MSGS", 1000)
    max_bytes = _pst_int("PST_MAX_BYTES", 200 * 1024 * 1024)
    timeout = _pst_int("PST_TIMEOUT", 300)

    tmp = tempfile.mkdtemp(prefix="ms-pst-")
    try:
        if src_path is None:
            src_path = os.path.join(tmp, "input" + (ext or ".pst"))
            with open(src_path, "wb") as fh:
                fh.write(raw)
        out = os.path.join(tmp, "out")
        os.makedirs(out)
        # Convert paths only when the extractor really runs inside WSL; a
        # native/custom extractor (PST_PYEXTRACT) gets plain local paths.
        uses_wsl = bool(pycmd) and "wsl" in os.path.basename(pycmd[0]).lower()
        if exe:
            # Fixed argv, no shell (Node parity). A .cmd/.bat stub on Windows
            # still needs cmd.exe to be executable.
            cmd = [exe, "-r", "-e", "-q", "-o", out, src_path]
            if os.name == "nt" and exe.lower().endswith((".cmd", ".bat")):
                cmd = ["cmd", "/c"] + cmd
        elif uses_wsl:
            cmd = pycmd + [_wsl_path(src_path), _wsl_path(out),
                           "--max-msgs", str(max_msgs), "--max-bytes", str(max_bytes)]
        else:
            cmd = pycmd + [src_path, out, "--max-msgs", str(max_msgs),
                           "--max-bytes", str(max_bytes)]
        try:
            # stdin=DEVNULL: an encrypted PST must fail fast instead of hanging
            # forever on a password prompt that can never be answered.
            # Capture the extractor's one-line JSON summary so its cap (true
            # message count / truncated flag) reaches the case result.
            proc = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise ParseError("pst_timeout")
        except FileNotFoundError:
            raise ParseError("readpst_missing")
        except OSError:
            raise ParseError("readpst_failed")
        summary = None
        if not exe:
            try:
                lines = [ln for ln in (proc.stdout or b"").decode("utf-8", "replace").splitlines()
                         if ln.strip()]
                summary = json.loads(lines[-1]) if lines else None
            except Exception:
                summary = None
        if proc.returncode != 0:
            code = (summary or {}).get("error")
            if code in ("bad_signature", "input_unreadable"):
                raise ParseError("format_mismatch")
            if code == "wsl_unavailable":
                raise ParseError("readpst_missing")
            raise ParseError("readpst_failed")

        paths = []
        for root, _dirs, files in os.walk(out):
            for name in files:
                if name.lower().endswith(".eml"):
                    paths.append(os.path.join(root, name))
        paths.sort()

        msgs, total, truncated = [], 0, False
        if not exe:
            if summary and summary.get("error"):
                raise ParseError("readpst_failed")
            truncated = bool((summary or {}).get("truncated"))
        for fpath in paths:
            try:
                with open(fpath, "rb") as fh:
                    data = fh.read()
            except OSError:
                continue
            if len(msgs) >= max_msgs:
                truncated = True
                break
            if msgs and total + len(data) > max_bytes:
                truncated = True
                break
            if len(data) > max_bytes:
                truncated = True
            total += len(data)
            msgs.append((os.path.basename(fpath), data))
        if not msgs:
            raise ParseError("empty")
        return msgs, truncated
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

def is_private(ip: str) -> bool:
    try:
        a = ipmod.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
    except Exception:
        return True

def extract_ips(headers_text: str):
    ips = []
    for h in re.findall(r"(?im)^Received:.*", headers_text or ""):
        for ip in _IP_RE.findall(h):
            if is_private(ip): continue
            if ip not in ips: ips.append(ip)
    return ips

def parse_eml_bytes(raw: bytes) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    headers = "\n".join(f"{k}: {v}" for k, v in msg.items())
    origin = extract_ips(headers)
    return {
        "from": str(msg.get("From", "")), "to": str(msg.get("To", "")),
        "subject": str(msg.get("Subject", "")), "date": str(msg.get("Date", "")),
        "message_id": str(msg.get("Message-ID", "")), "originIPs": origin,
        "replyTo": str(msg.get("Reply-To", "")), "returnPath": str(msg.get("Return-Path", "")),
        "body": msg.get_payload(decode=True)[:4096].decode("utf-8", "ignore") if msg.get_payload(decode=True) else "",
    }

def iter_mbox_messages(raw: bytes):
    """Yield email.message objects from raw MBOX bytes.

    mailbox.mbox needs a real path (it does not accept a file-like object), so
    the upload is staged in a private temp file and deleted when iteration ends.
    """
    fd, path = tempfile.mkstemp(prefix="ms-mbox-", suffix=".mbox")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw)
        mbox = mailbox.mbox(path, create=False)
        try:
            for m in mbox:
                yield m
        finally:
            mbox.close()
    finally:
        try: os.unlink(path)
        except OSError: pass


def parse_mbox_bytes(raw: bytes) -> list:
    out = []
    for m in iter_mbox_messages(raw):
        headers = "\n".join(f"{k}: {v}" for k, v in m.items())
        try:
            msg_raw = m.as_bytes()
        except Exception:
            msg_raw = raw
        out.append({"from": str(m.get("From","")), "subject": str(m.get("Subject","")),
                    "date": str(m.get("Date","")), "originIPs": extract_ips(headers),
                    "_raw": msg_raw})
    return out

def parse_text_bytes(raw: bytes) -> dict:
    return parse_eml_bytes(raw)

def load_messages(name: str, raw: bytes) -> list:
    low = name.lower()
    if low.endswith(".mbox"): return parse_mbox_bytes(raw)
    if low.endswith(".msg"):
        import io as _io
        import extract_msg
        with _io.BytesIO(raw) as f:
            m = extract_msg.MessageMessage(f)
            headers = "\n".join(str(v) for v in m.header.values()) if hasattr(m, "header") else ""
            return [{"from": str(m.sender or ""), "subject": str(m.subject or ""),
                     "originIPs": extract_ips(headers)}]
    if low.endswith(".txt"): return [parse_text_bytes(raw)]
    return [parse_eml_bytes(raw)]
