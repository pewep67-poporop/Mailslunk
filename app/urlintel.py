"""URL import / re-analysis (offline local rules).

The analyst can export every URL of a case, analyse it in an Internet-connected
sandbox, then import the result (CSV/JSON/XML/TXT). Imported verdicts are
merged with the local deterministic rules exactly once; no external service is
called by this server.
"""
import csv
import io
import json
import re
import xml.etree.ElementTree as ET

from .urls import analyze_url

MAX_ENTRIES = 5000
MAX_BYTES = 5 * 1024 * 1024


def _safe_csv(v):
    s = str(v if v is not None else "")
    if s[:1] in ("=", "+", "-", "@", "\t", "\r"):
        s = "'" + s
    return s

_LOCAL_RULES = [
    ("executable_download", re.compile(r"(?i)\.(exe|scr|js|vbs|ps1|bat|cmd|msi|jar|apk|hta)(?:[?#]|$)"), 45),
    ("active_content", re.compile(r"(?i)^(?:javascript|data):"), 55),
    ("path_traversal", re.compile(r"(?i)(?:\.\./|%2e%2e|%00)"), 30),
    ("encoded_payload", re.compile(r"(?i)(?:base64|%[0-9a-f]{2}%[0-9a-f]{2}%[0-9a-f]{2})"), 20),
    ("shortener", re.compile(r"(?i)^https?://(?:bit\.ly|t\.co|goo\.gl|tinyurl\.com|is\.gd|ow\.ly|cutt\.ly)/"), 20),
    ("credential_form", re.compile(r"(?i)/(?:login|signin|verify|account|password|otp)(?:[/?#.]|$)"), 15),
]


def _verdict(v):
    v = str(v or "").strip().lower()
    if v in ("malicious", "malware", "phishing", "bad", "blocked", "1", "true", "yes"):
        return "malicious"
    if v in ("suspicious", "warn", "warning", "unknown", "medium"):
        return "suspicious"
    if v in ("clean", "safe", "ok", "benign", "0", "false", "no"):
        return "clean"
    return ""


def _risk(v, verdict):
    try:
        return max(0, min(100, int(float(v))))
    except Exception:
        return {"malicious": 90, "suspicious": 50, "clean": 0}.get(verdict, 0)


def _entry(url, verdict="", risk="", reasons="", source="", target="", host=""):
    return {"url": str(url or "").strip()[:2000], "verdict": _verdict(verdict),
            "risk": risk, "reasons": reasons, "source": str(source or "")[:80],
            "target": str(target or "")[:200], "host": str(host or "")[:255]}


def parse_csv(text: str) -> list:
    out = []
    try:
        rows = list(csv.reader(io.StringIO(text)))
    except Exception:
        return out
    if not rows:
        return out
    header = [h.strip().lower() for h in rows[0]]
    has_header = any(h in ("url", "link", "uri") for h in header)
    if has_header:
        idx = {h: i for i, h in enumerate(header)}
        for row in rows[1:]:
            def get(*names):
                for n in names:
                    if n in idx and idx[n] < len(row):
                        return row[idx[n]]
                return ""
            u = get("url", "link", "uri")
            if u:
                out.append(_entry(u, get("verdict", "status"), get("risk", "score"),
                                  get("reasons", "reason", "note"), get("source", "tool"),
                                  get("target", "message", "subject"), get("host")))
    else:
        for row in rows:
            if row and row[0].strip():
                out.append(_entry(row[0], row[1] if len(row) > 1 else "",
                                  row[2] if len(row) > 2 else "",
                                  row[3] if len(row) > 3 else ""))
    return out


def parse_json(text: str) -> list:
    try:
        data = json.loads(text)
    except Exception:
        return []
    if isinstance(data, dict):
        for k in ("urls", "data", "items", "results", "indicators"):
            if isinstance(data.get(k), list):
                data = data[k]
                break
        else:
            data = [data]
    out = []
    for x in data if isinstance(data, list) else []:
        if isinstance(x, str):
            out.append(_entry(x))
        elif isinstance(x, dict):
            u = x.get("url") or x.get("link") or x.get("uri") or x.get("indicator")
            if u:
                out.append(_entry(u, x.get("verdict") or x.get("status"),
                                  x.get("risk") or x.get("score"),
                                  x.get("reasons") or x.get("reason") or x.get("note"),
                                  x.get("source") or x.get("tool"),
                                  x.get("target") or x.get("message") or x.get("subject"),
                                  x.get("host")))
    return out


def parse_xml(text: str) -> list:
    try:
        try:
            from defusedxml import ElementTree as DET
            root = DET.fromstring(text)
        except Exception:
            root = ET.fromstring(text)
    except Exception:
        return []
    out = []
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1].lower()
        if tag not in ("url", "link", "uri", "indicator"):
            continue
        u = (el.text or "").strip() or el.attrib.get("url") or el.attrib.get("value") or ""
        if not u:
            continue
        vals = {}
        for child in el:
            vals[child.tag.rsplit("}", 1)[-1].lower()] = (child.text or "").strip()
        out.append(_entry(u, vals.get("verdict") or vals.get("status") or el.attrib.get("verdict"),
                          vals.get("risk") or vals.get("score") or el.attrib.get("risk"),
                          vals.get("reasons") or vals.get("reason") or vals.get("note"),
                          vals.get("source") or el.attrib.get("source"),
                          vals.get("target") or vals.get("message") or vals.get("subject")))
    return out


def parse_txt(text: str) -> list:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"[\t,;]", line)
        u = parts[0].strip()
        if not re.match(r"(?i)^(?:https?://|www\.)", u):
            continue
        out.append(_entry(u, parts[1] if len(parts) > 1 else "",
                          parts[2] if len(parts) > 2 else "",
                          parts[3] if len(parts) > 3 else ""))
    return out


def parse_upload(name: str, data: bytes) -> list:
    if len(data) > MAX_BYTES:
        raise ValueError("file_too_large")
    text = data.decode("utf-8-sig", "replace")
    ext = (name or "").lower().rsplit(".", 1)[-1] if "." in (name or "") else ""
    if ext == "csv":
        return parse_csv(text)
    if ext == "json":
        return parse_json(text)
    if ext == "xml":
        return parse_xml(text)
    return parse_txt(text)


def analyze_entries(entries: list) -> list:
    """Merge the imported verdict with the local deterministic URL rules."""
    out = []
    for e in (entries or [])[:MAX_ENTRIES]:
        url = str(e.get("url") or "").strip()
        if not url:
            continue
        local = analyze_url(url)
        reasons = list(local.get("reasons") or [])
        risk = int(local.get("risk") or 0)
        verdict = local.get("verdict") or "clean"
        for rid, rx, weight in _LOCAL_RULES:
            if rx.search(url):
                risk += weight
                reasons.append("local rule: " + rid)
                if weight >= 45:
                    verdict = "malicious"
                elif weight >= 15 and verdict == "clean":
                    verdict = "suspicious"
        ext_v = _verdict(e.get("verdict"))
        if ext_v:
            risk = max(risk, _risk(e.get("risk"), ext_v))
            if ext_v == "malicious":
                verdict = "malicious"
            elif ext_v == "suspicious" and verdict == "clean":
                verdict = "suspicious"
            reasons.append("imported: " + ext_v)
        if e.get("reasons"):
            reasons.append(str(e["reasons"])[:200])
        risk = max(0, min(100, risk))
        out.append({
            "url": url[:2000], "host": local.get("host") or e.get("host") or "",
            "risk": risk, "verdict": verdict,
            "reasons": list(dict.fromkeys(reasons))[:10],
            "source": e.get("source") or "import",
            "target": e.get("target") or "",
            "local": {"risk": local.get("risk"), "verdict": local.get("verdict")},
            "imported": {"verdict": ext_v or None, "risk": e.get("risk") or None},
        })
    return out


def summary(entries: list) -> dict:
    c = {"total": len(entries), "malicious": 0, "suspicious": 0, "clean": 0}
    for e in entries:
        v = e.get("verdict") or "clean"
        c[v] = c.get(v, 0) + 1
    return c


def to_csv(entries: list, lang: str = "en") -> str:
    en = (lang or "en") != "vi"
    out = io.StringIO()
    w = csv.writer(out, quoting=csv.QUOTE_ALL)
    w.writerow(["target", "url", "host", "local_verdict", "local_risk",
                "imported_verdict", "final_verdict", "final_risk", "reasons", "source"]
               if en else ["mục_tiêu", "url", "host", "kết_quả_cục_bộ", "điểm_cục_bộ",
                           "kết_quả_nhập", "kết_quả_cuối", "điểm_cuối", "lý_do", "nguồn"])
    for e in entries:
        w.writerow([_safe_csv(v) for v in [
            e.get("target", ""), e.get("url", ""), e.get("host", ""),
            (e.get("local") or {}).get("verdict", ""),
            (e.get("local") or {}).get("risk", ""),
            (e.get("imported") or {}).get("verdict") or "",
            e.get("verdict", ""), e.get("risk", ""),
            " | ".join(e.get("reasons") or []), e.get("source", "")]])
    return "\ufeff" + out.getvalue()
