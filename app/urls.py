"""URL facts for offline forensic analysis (stdlib + BeautifulSoup + idna).

No reputation API, no brand-name guessing. Every reason comes from a field that
exists in the URL/HTML and is backed by analysis/rules/indicators.json.
"""
import html as html_mod
import ipaddress
import re
from email import policy
from email.parser import BytesParser
from urllib.parse import unquote, urlsplit

from bs4 import BeautifulSoup

try:
    from ..analysis import rules
except ImportError:  # chạy trực tiếp từ project root
    from analysis import rules

URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"'`)\]\\]+")
MAX_URLS = 60


def _host(url: str) -> str:
    """Return a normalized host without guesswork."""
    u = url.strip()
    if u.lower().startswith("www."):
        u = "//" + u
    try:
        p = urlsplit(u)
        host = p.hostname or ""
    except Exception:
        host = ""
    if not host:
        m = re.match(r"(?i)^([^/@?#]+)", u)
        host = m.group(1) if m else ""
    host = host.strip().lower().rstrip(".")
    if "@" in host:                 # user:pass@host trick
        host = host.split("@")[-1]
    return host


def analyze_url(url: str) -> dict:
    """-> {url, host, risk, verdict, reasons[]} - deterministic facts only."""
    u = str(url or "")[:2000]
    host = _host(u)
    if not host:
        return {"url": u[:300], "host": "", "risk": 0, "verdict": "clean", "reasons": []}

    cfg = rules.url_rules()
    w = rules.weights()
    reasons = []
    risk = 0

    def add(rid, reason):
        nonlocal risk
        risk += int(w.get(rid, 0))
        reasons.append(reason)

    # IP literal (evidence-backed: no name resolution performed)
    try:
        ipaddress.ip_address(host)
        add("url_raw_ip", "host is a raw IP address")
    except ValueError:
        pass

    # Internationalized host facts
    if host.startswith("xn--"):
        add("url_punycode", "punycode (IDN) host")
    elif any(ord(c) > 127 for c in host):
        try:
            import idna
            idna.encode(host, uts46=True)
        except Exception:
            add("url_punycode", "non-ASCII host failed IDNA validation")

    try:
        p = urlsplit(u if u.lower().startswith(("http://", "https://")) else "http://" + u)
        scheme = p.scheme.lower()
        path = unquote(p.path or "").lower()
    except Exception:
        scheme, path = "", ""

    if scheme == "http":
        add("url_http", "no TLS (http)")
    if scheme in cfg.get("active_schemes", []):
        add("url_active_scheme", f"active scheme ({scheme})")
    if "@" in (u.split("//", 1)[-1].split("/", 1)[0] if "//" in u else ""):
        add("url_userinfo", "'@' userinfo trick in URL")
    if len(u) > 100:
        add("url_long", f"very long URL ({len(u)} chars)")

    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in cfg.get("risky_tld", []):
        add("url_risky_tld", f"risky TLD .{tld}")

    for ext in cfg.get("executable_ext", []):
        if path.endswith(ext):
            add("url_exec_ext", f"executable download path ({ext})")
            break

    segments = [s for s in re.split(r"[/._-]", path) if s]
    hits = [t for t in cfg.get("credential_tokens", []) if t in segments]
    if hits:
        add("url_credential_token", "credential path tokens: " + ", ".join(hits[:4]))

    low = u.lower()
    if any(tok in low for tok in cfg.get("traversal_tokens", [])):
        add("url_traversal", "path traversal / null byte pattern")
    if any(host.endswith(s) or host == s for s in cfg.get("shorteners", [])):
        add("url_shortener", "known URL shortener host")

    risk = max(0, min(100, risk))
    verdict = "malicious" if risk >= 65 else ("suspicious" if risk >= 40 else "clean")
    return {"url": u[:300], "host": host, "risk": risk, "verdict": verdict,
            "reasons": reasons[:8]}


def _bodies(raw: bytes):
    """Collect body text + hrefs using the email stdlib + BeautifulSoup."""
    texts, htmls, hrefs = [], [], []
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw)
        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            if part.get_content_disposition() == "attachment":
                fn = (part.get_filename() or "").lower()
                if fn.endswith((".html", ".htm")):
                    try:
                        htmls.append(part.get_content())
                    except Exception:
                        pass
                continue
            ct = part.get_content_type()
            try:
                if ct == "text/plain":
                    texts.append(part.get_content())
                elif ct in ("text/html", "application/xhtml+xml"):
                    htmls.append(part.get_content())
            except Exception:
                pass
    except Exception:
        pass
    if not texts and not htmls:
        text = raw[:2 * 1024 * 1024].decode("utf-8", "replace")
        if text.strip():
            texts.append(text)
    for h in htmls:
        try:
            soup = BeautifulSoup(h, "html.parser")
            texts.append(soup.get_text(" "))
            for a in soup.find_all("a", href=True):
                hrefs.append(html_mod.unescape(str(a["href"])))
            for f in soup.find_all("form", action=True):
                hrefs.append(html_mod.unescape(str(f["action"])))
        except Exception:
            hrefs += re.findall(r"(?i)href\s*=\s*[\"']([^\"']+)[\"']", h or "")
    return texts, hrefs


def analyze_raw(raw: bytes, max_urls: int = MAX_URLS) -> list:
    texts, hrefs = _bodies(raw)
    candidates = []
    for t in texts:
        candidates += URL_RE.findall(t or "")
    candidates += [h for h in hrefs if h and len(h) >= 7]
    seen, out = set(), []
    for u in candidates:
        u = html_mod.unescape(u.strip().strip("'\",;:)].}"))
        if not u or len(u) < 7 or u.lower() in seen:
            continue
        seen.add(u.lower())
        out.append(analyze_url(u))
        if len(out) >= max_urls:
            break
    return out


def analyze(raw: bytes, user: str = "") -> dict:
    urls = analyze_raw(raw)
    findings = []
    for i, u in enumerate(urls, 1):
        if u["verdict"] == "clean":
            continue
        sev = 3 if u["verdict"] == "malicious" else 2
        ftype = "phishing_url" if sev == 3 else "suspicious_url"
        weight = min(20, 5 + u["risk"] // 5) if sev == 3 else min(12, 3 + u["risk"] // 10)
        findings.append({"id": f"U-{i:03d}", "sev": sev,
                         "severity": "high" if sev == 3 else "medium",
                         "type": ftype,
                         "evidence": f"{u['url'][:160]} - {'; '.join(u['reasons'])}"[:300],
                         "weight": weight})
    return {"urls": urls, "findings": findings}
