"""Library-backed attachment scanning (offline, deterministic, no network).

Every finding records the library/fact that produced it. No reputation feed,
no YARA CLI/ClamAV/sandbox HTTP, no ad-hoc brand or behavioural scoring.
"""
from __future__ import annotations

import io
import os
import re
import zipfile
from pathlib import Path

try:
    from ..analysis import rules
except ImportError:  # chạy trực tiếp từ project root
    from analysis import rules

MAX_SCAN_BYTES = int(os.getenv("THREATSCAN_MAX_BYTES", str(25 * 1024 * 1024)) or 25 * 1024 * 1024)


def enabled() -> bool:
    return os.getenv("THREATSCAN_ENABLED", "1").strip().lower() not in ("0", "false", "no", "off")


def _finding(reason, sev, verdict, weight, source):
    return {"reason": reason, "sev": sev, "verdict": verdict,
            "weight": weight, "source": source}


def _ole(data: bytes, out: list, matches: list, engines: set):
    try:
        import olefile
        if not olefile.isOleFile(io.BytesIO(data)):
            return
        engines.add("olefile")
        with olefile.OleFileIO(io.BytesIO(data)) as ole:
            streams = ["/".join(s) for s in ole.listdir()]
        matches.append({"engine": "olefile", "rule": "OLE/CFB container",
                        "description": f"{len(streams)} streams", "severity": "info"})
        out.append(_finding("OLE/CFB compound container", 1, "suspicious", 5, "olefile"))
    except Exception:
        pass
    try:
        from oletools.olevba import VBA_Parser
        vp = VBA_Parser(io.BytesIO(data))
        try:
            if vp.detect_vba_macros():
                engines.add("olevba")
                out.append(_finding("VBA macro code detected by olevba", 2, "suspicious", 20, "olevba"))
        finally:
            try:
                vp.close()
            except Exception:
                pass
    except Exception:
        pass
    try:
        from oletools.mraptor import MacroRaptor
        mr = MacroRaptor(data)
        if getattr(mr, "is_suspicious", False):
            engines.add("mraptor")
            out.append(_finding("MacroRaptor flags suspicious macro pattern", 2, "suspicious", 15, "mraptor"))
    except Exception:
        pass


def _encrypted_office(data: bytes, out: list, engines: set):
    try:
        import msoffcrypto
        f = msoffcrypto.OfficeFile(io.BytesIO(data))
        if f.is_encrypted():
            engines.add("msoffcrypto")
            out.append(_finding("encrypted Office document (content not inspectable)", 1, "suspicious", 5, "msoffcrypto"))
    except Exception:
        pass


def _pe(data: bytes, out: list, matches: list, engines: set):
    try:
        import pefile
        pe = pefile.PE(data=data, fast_load=True)
        engines.add("pefile")
        matches.append({"engine": "pefile", "rule": "PE executable",
                        "description": f"{len(pe.sections)} sections", "severity": "high"})
        out.append(_finding("PE executable payload (parsed by pefile)", 3, "malicious", 30, "pefile"))
    except Exception:
        pass


def _archive(data: bytes, name: str, out: list, engines: set):
    if not zipfile.is_zipfile(io.BytesIO(data)):
        return
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            infos = z.infolist()
            engines.add("zipfile")
            bad = [i.filename for i in infos
                   if i.filename.startswith(("/", "\\")) or ".." in i.filename.replace("\\", "/").split("/")]
            if bad:
                out.append(_finding("archive path traversal names", 3, "malicious", 25, "zipfile"))
            raw = sum(i.file_size for i in infos)
            comp = sum(i.compress_size for i in infos) or 1
            if raw > 1024 * 1024 and raw / comp > 500:
                out.append(_finding(f"archive bomb ratio {raw // comp}x ({raw // 1024}KB)", 3, "malicious", 25, "zipfile"))
            depth = sum(1 for i in infos if i.filename.lower().endswith((".zip", ".rar", ".7z")))
            if depth >= 3:
                out.append(_finding(f"nested archives x{depth}", 2, "suspicious", 12, "zipfile"))
    except Exception:
        pass


def _image(data: bytes, name: str, out: list, engines: set):
    low = name.lower()
    try:
        from PIL import Image
        with Image.open(io.BytesIO(data)) as img:
            fmt = (img.format or "").lower()
        engines.add("Pillow")
        declared = Path(low).suffix.lstrip(".")
        if declared and fmt and declared not in (fmt, "jpeg" if fmt == "jpg" else fmt):
            out.append(_finding(f"declared extension .{declared} but image format is {fmt}",
                                2, "suspicious", 10, "Pillow"))
    except Exception:
        pass


def _html(data: bytes, name: str, out: list, engines: set):
    head = data[:2048].lower()
    if not (name.lower().endswith((".html", ".htm", ".svg")) or
            b"<html" in head or b"<!doctype html" in head or b"<form" in head):
        return
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(data[:512 * 1024], "html.parser")
        tags = {t.name.lower() for t in soup.find_all(True)}
        active = set(rules.content_rules().get("html_active_tags", [])) & tags
        if active:
            engines.add("BeautifulSoup")
            out.append(_finding("active HTML tags: " + ", ".join(sorted(active)), 2, "suspicious", 12, "BeautifulSoup"))
        forms = [f.get("action", "") for f in soup.find_all("form")]
        remote = [a for a in forms if str(a).lower().startswith(("http://", "https://", "//"))]
        if remote:
            out.append(_finding(f"HTML form posts to remote action ({len(remote)})", 3, "malicious", 20, "BeautifulSoup"))
    except Exception:
        pass


def _xml(data: bytes, out: list, engines: set):
    if not re.search(rb"<\?xml|<![Dd][Oo][Cc][Tt][Yy][Pp][Ee]", data[:4096]):
        return
    try:
        from defusedxml import ElementTree as DET
        DET.fromstring(data[:512 * 1024])
    except Exception as e:
        engines.add("defusedxml")
        out.append(_finding(f"unsafe/undeclared XML entity blocked: {type(e).__name__}",
                            2, "suspicious", 12, "defusedxml"))


def _raw_keys(data: bytes, name: str, out: list):
    cfg = rules.content_rules()
    low = name.lower()
    sample = data[:MAX_SCAN_BYTES]
    if low.endswith(".pdf") or sample[:16].startswith(b"%PDF"):
        hits = [k for k in cfg.get("pdf_keys", []) if k.encode() in sample.lower()]
        if len(hits) >= 2:
            out.append(_finding("PDF active/embedded keys: " + ", ".join(hits[:5]),
                                2, "suspicious", 12, "rules/pdf_keys"))
    if low.endswith(".rtf") or sample[:8].startswith(b"{\\rtf"):
        text = sample[:300000].decode("latin-1", "ignore").lower()
        hits = [k for k in cfg.get("rtf_tokens", []) if k in text]
        if hits:
            out.append(_finding("RTF embedded-object markers: " + ", ".join(hits[:5]),
                                2, "suspicious", 12, "rules/rtf_tokens"))


def scan_attachment(name: str, data: bytes, sha256: str = "") -> dict:
    """-> {findings, matches, engines}; always degrades safely."""
    if not enabled() or not data:
        return {"findings": [], "matches": [], "engines": []}
    data = data[:MAX_SCAN_BYTES]
    out, matches, engines = [], [], set()

    _ole(data, out, matches, engines)
    _encrypted_office(data, out, engines)
    _pe(data, out, matches, engines)
    _archive(data, name, out, engines)
    _image(data, name, out, engines)
    _html(data, name, out, engines)
    _xml(data, out, engines)
    _raw_keys(data, name, out)

    seen = set()
    uniq = []
    for f in out:
        key = (f["source"], f["reason"])
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    return {"findings": uniq, "matches": matches[:50], "engines": sorted(engines)}
