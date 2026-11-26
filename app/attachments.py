"""M5 - Malware Attachment Analysis.

Walks MIME parts of the raw evidence (EML/MBOX, basic .msg support), hashes every
attachment, compares declared MIME against magic bytes, measures entropy, checks
archives (zip bomb / nesting), Office VBA macros (oletools), PDF active content,
double extensions and the EICAR test string. Findings ids are prefixed A-.
Threat/content scan (local, offline-safe): heuristics + optional yara-python/local
YARA rules + optional local external tools (YARA CLI, ClamAV, sandbox endpoint)
with strict time/size limits. Reputation (VT hash-lookup / MalwareBazaar) is
stubbed for the key-management phase.
"""
import io, re, math, hashlib, zipfile
from email import policy
from email.parser import BytesParser

MAGIC = [(b"MZ", "exe/dll"), (b"\x7fELF", "elf"), (b"PK\x03\x04", "zip/office"),
         (b"%PDF", "pdf"), (b"\xd0\xcf\x11\xe0", "ole"), (b"Rar!", "rar"),
         (b"7z\xbc\xaf", "7z"), (b"\x1f\x8b", "gzip"), (b"\x89PNG", "png"),
         (b"\xff\xd8\xff", "jpeg"), (b"GIF8", "gif"), (b"RIFF", "riff/avi"),
         (b"%!PS", "postscript"), (b"BM", "bmp")]
EXEC_MAGIC = {"exe/dll", "elf"}
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
DOUBLE_EXT = re.compile(r"(?i)\.(jpe?g|png|gif|pdf|docx?|txt|xls|xlsx)\.(exe|scr|bat|cmd|com|js|vbs|ps1|jar|lnk|hta|pif)$")
OFFICE_EXT = (".doc", ".xls", ".ppt", ".docm", ".xlsm", ".pptm", ".dot", ".xla")
MEDIA_DECL = ("image/", "audio/", "video/")
MAX_ATT = 200
MAX_INLINE = 25 * 1024 * 1024

# Offline/local content scan (heuristics + optional yara-python/CLI/ClamAV/sandbox)
THREAT_SCAN = None
try:
    from . import threatscan as THREAT_SCAN
except Exception:
    THREAT_SCAN = None


def entropy(data: bytes) -> float:
    if not data: return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c)


def magic_of(data: bytes) -> str:
    for sig, name in MAGIC:
        if data[:len(sig)] == sig: return name
    return "unknown"


def _verdict(name, magic, ent, raw_decl, data):
    """-> (verdict, reasons, weight, sev)"""
    reasons = []
    weights = []
    low = (name or "").lower()
    if EICAR in data:
        reasons.append("EICAR antivirus test string detected"); weights.append(30)
    if magic in EXEC_MAGIC:
        reasons.append(f"executable payload ({magic})"); weights.append(30)
    if raw_decl and raw_decl.startswith(MEDIA_DECL) and magic in (EXEC_MAGIC | {"zip/office", "ole"}):
        reasons.append(f"declared {raw_decl} but real content is {magic}"); weights.append(30)
    if DOUBLE_EXT.search(low):
        reasons.append("double file extension"); weights.append(10)
    if low.endswith(OFFICE_EXT) and magic == "ole":
        if _scan_macros(data):
            reasons.append("VBA macro code found in Office file"); weights.append(20)
        if low.endswith((".docm", ".xlsm", ".pptm")):
            reasons.append("macro-enabled Office format"); weights.append(10)
    if low.endswith(".pdf") or magic == "pdf":
        acts = _pdf_actions(data)
        if acts: reasons.append("PDF active content: " + ", ".join(acts)); weights.append(15)
    if low.endswith((".zip", ".rar", ".7z")) or magic in ("zip/office", "rar", "7z"):
        bomb = _zip_check(data)
        if bomb: reasons.append(bomb); weights.append(20)
    if not reasons:
        return "clean", [], 0, 0
    w = max(weights)
    sev = 3 if w >= 20 else 2
    return ("malicious" if w >= 30 else "suspicious"), reasons[:6], w, sev


def _scan_macros(data: bytes) -> bool:
    try:
        from oletools.olevba import VBA_Parser
        vp = VBA_Parser(io.BytesIO(data))
        try:
            return bool(vp.detect_vba_macros())
        finally:
            try: vp.close()
            except Exception: pass
    except Exception:
        return False


def _pdf_actions(data: bytes) -> list:
    acts = []
    for kw, label in ((b"/JavaScript", "JavaScript"), (b"/OpenAction", "OpenAction"),
                      (b"/Launch", "Launch"), (b"/EmbeddedFile", "embedded file")):
        if kw in data[:2 * 1024 * 1024]: acts.append(label)
    return acts


def _zip_check(data: bytes):
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            infos = z.infolist()
            if not infos: return None
            raw_sum = sum(i.file_size for i in infos)
            comp_sum = sum(i.compress_size for i in infos) or 1
            depth = 0
            for i in infos:
                if i.filename.lower().endswith((".zip", ".rar", ".7z")):
                    depth += 1
            if comp_sum and raw_sum / max(comp_sum, 1) > 500 and raw_sum > 1024 * 1024:
                return f"archive bomb: {raw_sum // 1024}KB expands from {comp_sum // 1024}KB (ratio {raw_sum // comp_sum}x)"
            if depth >= 3:
                return f"nested archives x{depth}"
            if raw_sum > 1024 * 1024 * 1024:
                return f"uncompressed size {raw_sum // 1024 // 1024}MB"
    except Exception:
        pass
    return None


def _iter_eml(raw: bytes):
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    for part in msg.walk():
        if part.get_content_maintype() == "multipart": continue
        fn = part.get_filename()
        if not fn and part.get_content_disposition() != "attachment": continue
        try: data = part.get_payload(decode=True) or b""
        except Exception: data = b""
        yield fn or "(unnamed)", part.get_content_type(), data


def _iter_mbox(raw: bytes):
    from .parsers import iter_mbox_messages
    for m in iter_mbox_messages(raw):
        try:
            for fn, ct, data in _iter_eml(m.as_bytes()):
                yield fn, ct, data
        except Exception:
            continue


def extract(name: str, raw: bytes, quarantine: bool = True, user: str = "") -> list:
    """-> [{id, name, size, mime, magic, entropy, sha256, md5, sha1, verdict, reasons, weight, sev}]"""
    low = (name or "").lower()
    if low.endswith(".mbox"): gen = _iter_mbox(raw)
    elif low.endswith(".msg"):
        gen = _iter_msg(raw)
    else: gen = _iter_eml(raw)

    # Reputation bị gỡ: không gửi hash ra dịch vụ ngoài.
    out = []
    for i, (fn, decl, data) in enumerate(gen):
        if i >= MAX_ATT: break
        if len(data) > MAX_INLINE: data = data[:MAX_INLINE]
        magic = magic_of(data)
        sha = hashlib.sha256(data).hexdigest()
        verdict, reasons, weight, sev = _verdict(fn, magic, entropy(data), decl or "", data)
        a = {"id": f"A-{i+1:03d}", "name": fn[:200], "size": len(data), "mime": decl or "",
             "magic": magic, "entropy": round(entropy(data), 2), "sha256": sha,
             "md5": hashlib.md5(data).hexdigest(), "sha1": hashlib.sha1(data).hexdigest(),
             "verdict": verdict, "reasons": reasons, "weight": weight, "sev": sev}
        # Offline/local threat scan (heuristics + optional YARA/ClamAV/sandbox)
        scan = {"findings": [], "matches": [], "engines": []}
        if THREAT_SCAN is not None:
            try:
                scan = THREAT_SCAN.scan_attachment(fn, data, sha) or scan
            except Exception:
                scan = {"findings": [], "matches": [], "engines": []}
        if scan.get("engines"):
            a["scanEngines"] = scan.get("engines") or []
        if scan.get("matches"):
            a["scanMatches"] = scan.get("matches") or []
        for sf in (scan.get("findings") or []):
            reason = str(sf.get("reason") or "").strip()
            if reason and reason not in a["reasons"]:
                a["reasons"].append(reason)
            a["weight"] = max(int(a.get("weight") or 0), int(sf.get("weight") or 0))
            a["sev"] = max(int(a.get("sev") or 0), int(sf.get("sev") or 0))
            v = str(sf.get("verdict") or "")
            if v == "malicious" or a["sev"] >= 3:
                a["verdict"] = "malicious"
            elif v == "suspicious" and a.get("verdict") != "malicious":
                a["verdict"] = "suspicious"
            elif a["reasons"] and a.get("verdict") == "clean":
                a["verdict"] = "suspicious" if a["sev"] >= 2 else "clean"
        out.append(a)
        if quarantine and a.get("verdict") != "clean":
            _quarantine(sha, fn, data)
    return out


def _iter_msg(raw: bytes):
    try:
        import extract_msg
        m = extract_msg.MessageMessage(io.BytesIO(raw))
        for att in (m.attachments or []):
            fn = getattr(att, "longFilename", None) or getattr(att, "shortFilename", None) or "(unnamed)"
            data = getattr(att, "data", b"") or b""
            yield str(fn), getattr(att, "contentMimeType", "") or "", data
    except Exception:
        return


def _quarantine(sha: str, fn: str, data: bytes):
    try:
        from .db import data_dir
        q = data_dir() / "quarantine"
        q.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", fn)[:80]
        p = q / f"{sha[:16]}_{safe}"
        if not p.exists():
            p.write_bytes(data)
        try:
            import os; os.chmod(p, 0o444)
        except Exception: pass
    except Exception:
        pass


def findings_for(attachments: list) -> list:
    """Convert attachment verdicts into findings (A-xxx, UI i18n keys)."""
    out = []
    for a in attachments:
        if a["verdict"] == "clean": continue
        sev = 3 if a["verdict"] == "malicious" else 2
        ftype = "dangerous_attachment" if sev == 3 else "suspicious_attachment"
        out.append({"id": a["id"], "sev": sev,
                    "severity": {0: "info", 1: "low", 2: "medium", 3: "high"}[sev],
                    "type": ftype,
                    "evidence": f"{a['name']} ({a['size']} B, {a['magic']}) — " + "; ".join(a["reasons"]),
                    "weight": a["weight"]})
    return out
