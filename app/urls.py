"""M4 — Phishing URL analysis (offline heuristics; reputation APIs pluggable later).

Extracts URLs from plain-text bodies, HTML (href + text) and HTML attachments,
then scores each one with deterministic heuristics. Finding ids are prefixed U-.
Reputation (URLhaus/VT/Safe Browsing) is a stub on purpose: keys per-user will
be wired in a later phase — no external call is made here.
"""
import re, os, html as html_mod
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"'`)\]\\]+")
HREF_RE = re.compile(r"(?i)href\s*=\s*[\"']([^\"']+)[\"']")
MAX_REP_URLS = int(os.getenv("REPUTATION_MAX_URLS", "10") or 10)  # URLs sent to threat feeds
BAIT = ("login", "verify", "secure", "update", "confirm", "account", "password",
        "otp", "wallet", "seed", "recover", "suspend", "unlock", "billing",
        "invoice", "payment", "gift", "bonus", "authenticate", "signin")
BRANDS = ("paypal", "google", "facebook", "amazon", "apple", "microsoft", "netflix",
          "linkedin", "instagram", "whatsapp", "twitter", "ebay", "chase", "wellsfargo",
          "bankofamerica", "citibank", "hsbc", "dhl", "fedex", "ups", "usps",
          "binance", "coinbase", "metamask", "steam", "discord", "dropbox", "adobe",
          "docusign", "zoom", "outlook", "icloud", "gmail")
RISKY_TLD = ("zip", "mov", "top", "xyz", "gq", "tk", "ml", "cf", "click", "country", "work")
SUFFIX_WORDS = {"secure", "verify", "verification", "account", "login", "support",
                "service", "official", "online", "help", "care", "id", "com", "www"}
IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

F = lambda **kw: kw


def _lev(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 3: return 99
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _host(url: str) -> str:
    m = re.match(r"(?i)^[a-z]+://([^/@?#]+)", url) or re.match(r"(?i)^www\.([^/@?#]+)", url)
    if not m:
        m = re.match(r"(?i)^([^/@?#]+)", url.replace("www.", "", 1))
    host = (m.group(1) if m else "").split(":")[0].strip().lower()
    if "@" in host:  # user:pass@host trick
        host = host.split("@")[-1]
    return host.rstrip(".")


def analyze_url(url: str) -> dict:
    """-> {url, host, risk, verdict, reasons[]}"""
    reasons = []
    risk = 0
    host = _host(url)
    if not host: return {"url": url[:300], "host": "", "risk": 0, "verdict": "clean", "reasons": []}
    labels = re.split(r"[._-]", host)
    main_labels = [l for l in labels if l and l not in SUFFIX_WORDS]
    tld = host.rsplit(".", 1)[-1] if "." in host else ""

    if IP_RE.match(host):
        risk += 55; reasons.append("host is a raw IP address")
    if "xn--" in host:
        risk += 35; reasons.append("punycode (IDN homograph) host")
    elif any(ord(c) > 127 for c in host):
        risk += 35; reasons.append("non-ASCII characters in host (homoglyph)")
    if tld in RISKY_TLD:
        risk += 15; reasons.append(f"risky TLD .{tld}")
    if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
        risk += 25; reasons.append("'@' userinfo trick in URL")
    if url.startswith("http://"):
        risk += 5; reasons.append("no TLS (http)")
    if len(url) > 100:
        risk += 10; reasons.append(f"very long URL ({len(url)} chars)")

    path_l = url.lower()
    bait_hits = [k for k in BAIT if k in path_l]
    if bait_hits:
        risk += min(24, 8 * len(bait_hits)); reasons.append("bait keywords: " + ", ".join(bait_hits[:4]))

    lookalike = False
    for brand in BRANDS:
        if host == brand + ".com" or host == "www." + brand + ".com":
            break  # official domain
        if brand in host:
            risk += 30; reasons.append(f"brand '{brand}' appears in non-official domain {host}")
            break
        # Short labels such as "mail", "pr" or "aol" are ordinary words; only
        # compare brand-length tokens to avoid the old false positives.
        for tok in main_labels:
            if len(brand) < 5 or len(tok) < 5:
                continue
            d = _lev(tok, brand)
            if 0 < d <= 2 and len(tok) <= len(brand) + 3:
                risk += 35; lookalike = True
                reasons.append(f"lookalike domain: '{tok}' ~ '{brand}' (distance {d})")
                break
        else:
            continue
        break
    if lookalike and bait_hits:
        risk += 15; reasons.append("brand lookalike combined with bait keywords")

    risk = max(0, min(100, risk))
    verdict = "malicious" if risk >= 65 else ("suspicious" if risk >= 40 else "clean")
    return {"url": url[:300], "host": host, "risk": risk, "verdict": verdict,
            "reasons": reasons[:6]}


def _bodies(raw: bytes):
    """Collect text + html bodies from an EML (and text URLs inside HTML).

    A plain .txt upload is not an EML: when parsing yields no MIME parts the
    decoded bytes are scanned as one text body.
    """
    texts, htmls = [], []
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw)
        for part in msg.walk():
            if part.get_content_maintype() == "multipart": continue
            if part.get_content_disposition() == "attachment":
                fn = part.get_filename() or ""
                if fn.lower().endswith((".html", ".htm")):
                    try: htmls.append(part.get_content())
                    except Exception: pass
                continue
            ct = part.get_content_type()
            try:
                if ct == "text/plain": texts.append(part.get_content())
                elif ct in ("text/html", "application/xhtml+xml"): htmls.append(part.get_content())
            except Exception:
                pass
    except Exception:
        pass
    if not texts and not htmls:
        text = raw[:2 * 1024 * 1024].decode("utf-8", "replace")
        if text.strip():
            texts.append(text)
    return texts, htmls


def analyze_raw(raw: bytes, max_urls: int = 60) -> list:
    """Extract + score all URLs in a raw EML -> list of analyze_url dicts."""
    texts, htmls = _bodies(raw)
    candidates = []
    for t in texts: candidates += URL_RE.findall(t or "")
    for h in htmls:
        candidates += HREF_RE.findall(h or "") + URL_RE.findall(html_mod.unescape(h or ""))
    seen, out = set(), []
    for u in candidates:
        u = html_mod.unescape(u.strip().strip("'\",;:)].}"))
        if not u or len(u) < 7: continue
        key = u.lower()
        if key in seen: continue
        seen.add(key)
        out.append(analyze_url(u))
        if len(out) >= max_urls: break
    return out


def analyze(raw: bytes, user: str = "") -> dict:
    """-> {urls, findings} — findings reuse UI i18n keys, ids U-xxx."""
    urls = analyze_raw(raw)
    findings = []
    nid = [0]

    def add(sev, ftype, evidence, weight):
        nid[0] += 1
        findings.append({"id": f"U-{nid[0]:03d}", "sev": int(sev),
                         "severity": {0: "info", 1: "low", 2: "medium", 3: "high"}.get(int(sev)),
                         "type": ftype, "evidence": evidence[:300], "weight": weight})

    # --- M9 reputation (off by default; only the URL leaves the server) ---
    reputation = None
    try:
        from . import reputation as _rep
        reputation = _rep
    except Exception:
        reputation = None
    if reputation is not None and reputation.enabled():
        for u in urls[:MAX_REP_URLS]:
            try:
                rep = reputation.check_url(u["url"], user)
            except Exception:
                continue
            u["reputation"] = rep
            if rep.get("verdict") == "malicious":
                who = ", ".join(p.get("provider", "") for p in rep.get("providers", [])
                                if p.get("verdict") == "malicious")
                add(3, "url_blocklisted", f"{u['url'][:160]} — listed by {who}", 25)
                u["verdict"] = "malicious"
                u["risk"] = max(int(u.get("risk") or 0), 80)
            elif rep.get("verdict") == "suspicious":
                add(2, "url_blocklisted", f"{u['url'][:160]} — suspicious in a threat feed", 10)

    for u in urls:
        if u["verdict"] == "clean": continue
        reasons = "; ".join(u["reasons"])
        if u["verdict"] == "malicious":
            add(3, "phishing_url", f"{u['url'][:160]} — {reasons}", min(20, 5 + u["risk"] // 5))
        else:
            add(2, "suspicious_url", f"{u['url'][:160]} — {reasons}", min(12, 3 + u["risk"] // 10))
    return {"urls": urls, "findings": findings}
