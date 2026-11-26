"""Offline/local malicious-content scanning (M4a).

Default layer (2): pure-Python heuristics + optional yara-python with local rules.
Enhanced layer (1): optional local external tools/sandbox adapters (YARA CLI,
ClamAV clamscan/clamdscan, local sandbox HTTP endpoint) with strict timeout/size
limits. No Internet egress: sandbox endpoints must resolve to localhost/private.

All scanners degrade gracefully and never raise into the analysis pipeline.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse

MAX_SCAN_BYTES = int(os.getenv("THREATSCAN_MAX_BYTES", str(25 * 1024 * 1024)) or 25 * 1024 * 1024)
TIMEOUT = float(os.getenv("THREATSCAN_TIMEOUT", "15") or 15)

_SCRIPT_EXT = (".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".ps1", ".psm1", ".bat", ".cmd",
               ".hta", ".scr", ".lnk", ".chm", ".sct", ".inf", ".reg")
_TEXTY = (".txt", ".csv", ".json", ".xml", ".html", ".htm", ".svg", ".eml", ".md", ".rtf")

_SCRIPT_PATTERNS = [
    ("powershell_encoded", re.compile(rb"(?i)powershell[\s\S]{0,60}-(enc|encodedcommand)\b")),
    ("frombase64string", re.compile(rb"(?i)frombase64string")),
    ("invoke_expression", re.compile(rb"(?i)\b(iex|invoke-expression)\b")),
    ("download_cradle", re.compile(rb"(?i)(invoke-webrequest|iwr|wget|curl|downloadstring|downloadfile|bitsadmin\s+/transfer|certutil\s+-urlcache)")),
    ("lolbin_exec", re.compile(rb"(?i)\b(mshta|rundll32|regsvr32|wmic|cscript|wscript)\b[^\r\n]{0,80}\b(http|\\\\|\.hta|\.js|\.vbs|scrobj|javascript:)")),
    ("shell_spawn", re.compile(rb"(?i)\b(cmd\.exe|/bin/(ba)?sh|powershell\.exe)\b")),
    ("credential_prompt", re.compile(rb"(?i)(password|passwort|mot de passe|mat khau).{0,40}(enter|input|verify|confirm|re-?enter)")),
    ("macro_autoexec", re.compile(rb"(?i)\b(autoopen|document_open|workbook_open|auto_exec|autoclose)\b")),
]

_HTML_ACTIVE = [
    ("html_form_action", re.compile(rb"(?is)<form\b[^>]*\baction\s*=\s*['\"]?(?:https?:|//|data:|javascript:)", re.I)),
    ("html_script", re.compile(rb"(?is)<script\b", re.I)),
    ("html_iframe", re.compile(rb"(?is)<iframe\b", re.I)),
    ("html_meta_refresh", re.compile(rb"(?is)<meta\b[^>]*http-equiv\s*=\s*['\"]?refresh", re.I)),
    ("html_object_embed", re.compile(rb"(?is)<(object|embed)\b", re.I)),
]

_PDF_RISK = [(b"/JavaScript", "pdf_javascript"), (b"/JS", "pdf_js"), (b"/OpenAction", "pdf_openaction"),
             (b"/AA", "pdf_additional_action"), (b"/Launch", "pdf_launch"),
             (b"/EmbeddedFile", "pdf_embedded_file"), (b"/RichMedia", "pdf_richmedia"),
             (b"/URI", "pdf_uri"), (b"/XFA", "pdf_xfa")]

_RTF_RISK = [("\\objdata", "rtf_objdata"), ("\\objocx", "rtf_objocx"),
             ("\\objupdate", "rtf_objupdate"), ("equation.3", "rtf_equation_editor"),
             ("\\objhtml", "rtf_objhtml"), ("\\objlink", "rtf_objlink")]


def enabled() -> bool:
    v = os.getenv("THREATSCAN_ENABLED", "1").strip().lower()
    return v not in ("0", "false", "no", "off")


def _is_private_host(host: str) -> bool:
    host = (host or "").strip().lower().strip("[]")
    if host in ("localhost",):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private or ip.is_link_local
    except Exception:
        try:
            infos = socket.getaddrinfo(host, None)
            ips = [i[4][0] for i in infos]
            if not ips:
                return False
            return all(_is_private_host(x) for x in ips)
        except Exception:
            return False


def _safe_sandbox_url(url: str) -> str | None:
    if not url:
        return None
    try:
        p = urlparse(url)
        if p.scheme not in ("http", "https"):
            return None
        if not _is_private_host(p.hostname or ""):
            return None
        return url
    except Exception:
        return None


def _rules_dir() -> Path:
    env = os.getenv("YARA_RULES_DIR", "").strip()
    if env:
        return Path(env)
    return Path(__file__).resolve().parents[1] / "rules" / "yara"


def _add(find, reason, sev=2, verdict="suspicious", weight=10, source="local"):
    find.append({"reason": reason, "sev": sev, "verdict": verdict, "weight": weight, "source": source})


def _python_heuristics(name: str, data: bytes) -> list:
    low = (name or "").lower()
    out = []
    sample = data[:MAX_SCAN_BYTES]
    head = sample[:4096]

    # script-ish by extension or shebang
    if low.endswith(_SCRIPT_EXT):
        _add(out, f"script/executable container type ({Path(low).suffix})", 2, "suspicious", 10)
    if head.startswith(b"#!") and (b"sh" in head[:40] or b"python" in head[:40] or b"perl" in head[:40]):
        _add(out, "script shebang present", 2, "suspicious", 8)

    is_texty = low.endswith(_TEXTY) or low.endswith(_SCRIPT_EXT) or b"\x00" not in sample[:2048]
    if is_texty:
        for rid, rx in _SCRIPT_PATTERNS:
            if rx.search(sample):
                sev = 3 if rid in ("download_cradle", "lolbin_exec") else 2
                verdict = "malicious" if sev == 3 else "suspicious"
                _add(out, f"content indicator: {rid}", sev, verdict, 18 if sev == 3 else 10)

    # HTML active content in attachment
    if low.endswith((".html", ".htm", ".svg")) or b"<html" in sample[:4096].lower() or b"<!doctype html" in sample[:4096].lower():
        hits = [rid for rid, rx in _HTML_ACTIVE if rx.search(sample[:200000])]
        if hits:
            sev = 3 if "html_form_action" in hits and ("html_script" in hits or "html_iframe" in hits or "html_meta_refresh" in hits) else 2
            verdict = "malicious" if sev == 3 else "suspicious"
            _add(out, "active HTML content: " + ", ".join(hits[:5]), sev, verdict, 20 if sev == 3 else 10)

    # PDF active content density
    if low.endswith(".pdf") or head.startswith(b"%PDF"):
        hits = [label for sig, label in _PDF_RISK if sig in sample]
        if len(hits) >= 2:
            sev = 3 if ("pdf_javascript" in hits or "pdf_js" in hits or "pdf_launch" in hits) and ("pdf_openaction" in hits or "pdf_additional_action" in hits) else 2
            verdict = "malicious" if sev == 3 else "suspicious"
            _add(out, "PDF active/embedded features: " + ", ".join(hits[:6]), sev, verdict, 18 if sev == 3 else 10)
        elif hits:
            _add(out, "PDF feature: " + ", ".join(hits[:4]), 1, "suspicious", 5)

    # RTF exploit markers
    if low.endswith(".rtf") or head.startswith(b"{\\rtf"):
        text = sample[:300000].decode("latin-1", "ignore").lower()
        hits = [label for token, label in _RTF_RISK if token in text]
        if "rtf_objdata" in hits and ("rtf_equation_editor" in hits or "rtf_objocx" in hits):
            _add(out, "RTF embedded-object exploit markers: " + ", ".join(hits[:5]), 3, "malicious", 25)
        elif hits:
            _add(out, "RTF embedded-object markers: " + ", ".join(hits[:5]), 2, "suspicious", 12)

    # LNK by header
    if head.startswith(b"L\x00\x00\x00\x01\x14\x02\x00") or low.endswith(".lnk"):
        _add(out, "Windows shortcut (LNK) container", 2, "suspicious", 10)
    # ISO/IMG/UDF hints
    if low.endswith((".iso", ".img", ".vhd", ".vhdx")):
        _add(out, f"disk image container ({Path(low).suffix})", 2, "suspicious", 8)

    # high-risk compound extensions
    if re.search(r"(?i)\.(doc|xls|ppt|pdf|jpg|png|txt)\.(exe|scr|js|vbs|bat|cmd|ps1|hta|lnk|jar)$", low):
        _add(out, "double extension masquerading executable/script", 3, "malicious", 22)

    # very high printable ratio with long base64-like run in script context
    if is_texty:
        b64runs = re.findall(rb"[A-Za-z0-9+/]{120,}={0,2}", sample)
        if b64runs and (low.endswith(_SCRIPT_EXT) or any(rx.search(sample) for _, rx in _SCRIPT_PATTERNS[:3])):
            _add(out, f"large base64 blob in script context ({len(b64runs)} run(s))", 2, "suspicious", 12)

    return out


def _yara_python(name: str, data: bytes) -> tuple[list, list]:
    findings = []
    matches = []
    try:
        import yara  # type: ignore
    except Exception:
        return findings, matches
    rdir = _rules_dir()
    rule_files = []
    if rdir.is_dir():
        for p in sorted(rdir.glob("*.yar")) + sorted(rdir.glob("*.yara")):
            rule_files.append(str(p))
    if not rule_files:
        return findings, matches
    try:
        filemap = {f"r{i}": p for i, p in enumerate(rule_files)}
        rules = yara.compile(filepaths=filemap)
        res = rules.match(data=data, timeout=max(1, int(TIMEOUT)))
        for m in res:
            meta = getattr(m, "meta", {}) or {}
            sev_s = str(meta.get("severity", "medium")).lower()
            sev = 3 if sev_s in ("high", "critical", "malicious") else 2 if sev_s in ("medium", "suspicious") else 1
            verdict = str(meta.get("verdict", "suspicious" if sev < 3 else "malicious")).lower()
            verdict = verdict if verdict in ("malicious", "suspicious", "clean") else ("malicious" if sev >= 3 else "suspicious")
            desc = meta.get("description") or getattr(m, "rule", "yara_match")
            rule = getattr(m, "rule", "rule")
            matches.append({"engine": "yara-python", "rule": rule, "description": str(desc)[:200], "severity": sev_s})
            _add(findings, f"YARA match: {rule} - {str(desc)[:140]}", sev, verdict, 20 if sev >= 3 else 10, source="yara-python")
    except Exception as e:
        findings.append({"reason": f"yara-python error: {type(e).__name__}", "sev": 1, "verdict": "clean", "weight": 0, "source": "yara-python", "info": True})
    return findings, matches


def _run_cli(cmd, data: bytes, timeout: float):
    try:
        p = subprocess.run(cmd, input=data, capture_output=True, timeout=timeout, check=False)
        out = (p.stdout or b"") + b"\n" + (p.stderr or b"")
        return p.returncode, out.decode("utf-8", "replace")[:4000]
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except Exception as e:
        return 127, f"{type(e).__name__}: {e}"


def _yara_cli(data: bytes) -> tuple[list, list]:
    findings, matches = [], []
    exe = os.getenv("YARA_CLI", "").strip() or shutil.which("yara") or shutil.which("yara64") or ""
    rdir = _rules_dir()
    if not exe or not rdir.is_dir():
        return findings, matches
    tpath = None
    try:
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(data[:MAX_SCAN_BYTES])
            tpath = tf.name
        for rf in sorted(list(rdir.glob("*.yar")) + list(rdir.glob("*.yara")))[:50]:
            rc, out = _run_cli([exe, "-w", str(rf), tpath], b"", min(TIMEOUT, 20))
            if rc == 0 and out.strip():
                for line in out.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    rule = line.split()[0]
                    matches.append({"engine": "yara-cli", "rule": rule, "description": str(rf.name), "severity": "medium"})
                    _add(findings, f"YARA CLI match: {rule} ({rf.name})", 2, "suspicious", 10, source="yara-cli")
            elif rc == 124:
                _add(findings, f"YARA CLI timeout ({rf.name})", 1, "clean", 0, source="yara-cli")
                break
    except Exception:
        pass
    finally:
        if tpath:
            try:
                os.unlink(tpath)
            except Exception:
                pass
    return findings, matches


def _clamav_cli(name: str, data: bytes) -> tuple[list, list]:
    findings, matches = [], []
    exe = os.getenv("CLAMSCAN_CLI", "").strip()
    if not exe:
        exe = shutil.which("clamdscan") or shutil.which("clamscan") or ""
    if not exe:
        return findings, matches
    tpath = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(name or "file").suffix[:10]) as tf:
            tf.write(data[:MAX_SCAN_BYTES])
            tpath = tf.name
        cmd = [exe, "--no-summary"]
        if os.path.basename(exe).lower().startswith("clamscan"):
            cmd += ["--infected"]
        cmd += [tpath]
        rc, out = _run_cli(cmd, b"", max(5, int(TIMEOUT)))
        if rc == 1 or "FOUND" in out:
            sig = ""
            for line in out.splitlines():
                if "FOUND" in line:
                    sig = line.replace("FOUND", "").strip().strip(": ")
                    break
            sig = sig or "signature"
            matches.append({"engine": "clamav", "rule": sig, "description": "ClamAV detection", "severity": "high"})
            _add(findings, f"ClamAV detection: {sig}", 3, "malicious", 30, source="clamav")
        elif rc == 124:
            _add(findings, "ClamAV scan timeout", 1, "clean", 0, source="clamav")
    except Exception:
        pass
    finally:
        if tpath:
            try:
                os.unlink(tpath)
            except Exception:
                pass
    return findings, matches


def _sandbox_local(name: str, data: bytes, sha256: str) -> tuple[list, list]:
    """Optional local sandbox submit hook (localhost/private only). Best-effort, bounded."""
    findings, matches = [], []
    url = _safe_sandbox_url(os.getenv("SANDBOX_URL", "").strip())
    if not url:
        return findings, matches
    try:
        import urllib.request
        payload = json.dumps({"filename": name, "sha256": sha256, "size": len(data)}).encode("utf-8")
        endpoint = url.rstrip("/") + "/api/scan" if not url.rstrip("/").endswith("/api/scan") else url
        req = urllib.request.Request(endpoint, data=payload, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=min(TIMEOUT, 10)) as resp:
            body = resp.read(65536).decode("utf-8", "replace")
        try:
            j = json.loads(body)
        except Exception:
            j = {}
        verdict = str(j.get("verdict") or "").lower()
        score = j.get("score")
        if verdict in ("malicious", "suspicious") or (isinstance(score, (int, float)) and score >= 50):
            sev = 3 if verdict == "malicious" or (isinstance(score, (int, float)) and score >= 80) else 2
            v = "malicious" if sev == 3 else "suspicious"
            desc = j.get("summary") or j.get("signature") or "sandbox verdict"
            matches.append({"engine": "sandbox", "rule": str(desc)[:120], "description": "Local sandbox", "severity": "high" if sev == 3 else "medium"})
            _add(findings, f"Local sandbox: {v} - {str(desc)[:140]}", sev, v, 25 if sev == 3 else 12, source="sandbox")
    except Exception:
        pass
    return findings, matches


def scan_attachment(name: str, data: bytes, sha256: str = "") -> dict:
    """Return {findings:[{reason,sev,verdict,weight,source}], matches:[...], engines:[...]}"""
    if not enabled() or not data:
        return {"findings": [], "matches": [], "engines": []}
    data = data[:MAX_SCAN_BYTES]
    engines = []
    findings = []
    matches = []

    f = _python_heuristics(name, data)
    if f:
        engines.append("heuristics")
        findings.extend(f)

    fy, my = _yara_python(name, data)
    if fy or my:
        engines.append("yara-python")
    findings.extend([x for x in fy if not x.get("info")])
    matches.extend(my)

    fyc, myc = _yara_cli(data)
    if fyc or myc:
        engines.append("yara-cli")
    findings.extend([x for x in fyc if x.get("weight", 0) >= 0])
    matches.extend(myc)

    fc, mc = _clamav_cli(name, data)
    if fc or mc:
        engines.append("clamav")
    findings.extend(fc)
    matches.extend(mc)

    fs, ms = _sandbox_local(name, data, sha256)
    if fs or ms:
        engines.append("sandbox")
    findings.extend(fs)
    matches.extend(ms)

    seen = set()
    uniq = []
    for x in findings:
        k = (x.get("source"), x.get("reason"))
        if k in seen:
            continue
        seen.add(k)
        uniq.append(x)
    return {"findings": uniq, "matches": matches[:50], "engines": sorted(set(engines))}
