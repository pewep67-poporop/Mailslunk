"""M1 — Deep Email Header Analysis.

Checks the raw header block of an EML/MSG-converted message for anti-spoofing
signals. Finding ids are prefixed H- and reuse the UI's ft_* i18n type keys
(the shared public/app.js dictionary already knows the common ones).
"""
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, parsedate_to_datetime

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Headers worth showing in the UI table, in order (case-insensitive match).
_INTERESTING = ["return-path", "received", "from", "to", "cc", "reply-to",
                "date", "message-id", "subject", "authentication-results",
                "received-spf", "dkim-signature", "x-originating-ip", "x-mailer",
                "x-priority", "x-sender", "x-spam-status", "x-spam-flag"]
_DUPLICATE_WATCH = {"from", "to", "subject", "date", "message-id", "reply-to"}

F = lambda **kw: kw  # finding factory


def _domain(addr: str) -> str:
    a = parseaddr(str(addr or ""))[1]
    return a.split("@")[-1].lower().rstrip(".") if "@" in a else ""


def _severity(sev: int) -> str:
    return {0: "info", 1: "low", 2: "medium", 3: "high"}.get(int(sev), "info")


def _all_headers(raw: bytes):
    msg = BytesParser(policy=policy.compat32).parsebytes(raw, headersonly=True)
    pairs, seen = [], {}
    for k, v in msg.items():
        name = str(k); val = str(v).replace("\r", " ").replace("\n", " ").strip()
        pairs.append({"name": name, "value": val})
        seen.setdefault(name.lower(), []).append(val)
    return pairs, seen, msg


def _received_entries(pairs):
    out = []
    for p in pairs:
        if p["name"].lower() != "received": continue
        v = p["value"]
        ts = None
        m = re.search(r";\s*(.+?)\s*$", v)
        if m:
            try: ts = parsedate_to_datetime(m.group(1))
            except Exception: ts = None
        fm = re.match(r"(?i)from\s+([^;\s]+)", v)
        from_host = fm.group(1).strip("()") if fm else ""
        bm = re.search(r"(?i)\bby\s+([^;\s]+)", v)
        ip = None
        fmip = re.search(r"\(([^)]*)\)", v)
        if fmip:
            ips = _IP_RE.findall(fmip.group(1))
            if ips: ip = ips[0]
        if not ip: ip = _IP_RE.search(v.split("by ", 1)[0]).group(0) if _IP_RE.search(v.split("by ", 1)[0]) else None
        out.append({"raw": v[:300], "from": from_host, "by": bm.group(1) if bm else "", "ts": ts, "ip": ip})
    return out


def analyze_headers(raw: bytes) -> dict:
    """-> {headers, receivedCount, checks, fromDomain, returnPathDomain, ...}"""
    pairs, seen, msg = _all_headers(raw)
    checks = []
    nid = [0]

    def add(sev: int, ftype: str, evidence: str, weight: int = 0):
        nid[0] += 1
        checks.append({"id": f"H-{nid[0]:03d}", "sev": int(sev), "severity": _severity(sev),
                       "type": ftype, "evidence": evidence[:300], "weight": weight})

    from_h = seen.get("from", [""])[0]
    from_domain = _domain(from_h)
    return_path = seen.get("return-path", [""])[0]
    reply_to = seen.get("reply-to", [""])[0]
    message_id = seen.get("message-id", [""])[0]

    # --- From present at all? -------------------------------------------------
    if not from_domain:
        add(3, "missing_header", "From header missing or has no valid address", 15)

    # --- From vs Return-Path (envelope) --------------------------------------
    rp_domain = ""
    m = re.search(r"@([\w.-]+)", return_path)
    if m: rp_domain = m.group(1).lower().rstrip(".")
    if from_domain and rp_domain and rp_domain != from_domain:
        add(2, "from_returnpath_mismatch", f"From={from_domain} but Return-Path={rp_domain}", 5)

    # --- From vs Reply-To ----------------------------------------------------
    rt_domain = _domain(reply_to)
    if from_domain and rt_domain and rt_domain != from_domain:
        add(2, "from_replyto_mismatch", f"From={from_domain} but Reply-To={rt_domain}", 8)

    # --- Message-ID domain ---------------------------------------------------
    mid_domain = ""
    m = re.search(r"@([\w.-]+)>?", message_id)
    if m: mid_domain = m.group(1).lower().rstrip(".>")
    if from_domain and mid_domain and mid_domain != from_domain:
        add(1, "message_id_mismatch", f"Message-ID domain={mid_domain} but From={from_domain}", 2)

    # --- Duplicate headers ---------------------------------------------------
    for h in sorted(_DUPLICATE_WATCH):
        vals = seen.get(h) or []
        if len(vals) > 1:
            add(2, "duplicate_headers", f"{len(vals)}x {h}: {vals[0][:120]}", 5)

    # --- Missing core headers -------------------------------------------------
    if not seen.get("message-id"):
        add(1, "missing_header", "Message-ID missing (bulk tool or spoof attempt)", 2)
    if not seen.get("date"):
        add(1, "missing_header", "Date header missing", 2)
    if not seen.get("to") and not seen.get("bcc") and from_domain:
        add(1, "missing_header", "No To header (possible BCC spam)", 2)

    # --- Display-name spoofing: name hides a different mailbox ---------------
    dn = parseaddr(from_h)[0] or ""
    mail_in_name = re.search(r"[\w.+-]+@[\w.-]+", dn)
    if mail_in_name and from_domain:
        name_dom = mail_in_name.group(0).split("@")[-1].lower().rstrip(".")
        if name_dom and name_dom != from_domain:
            add(2, "display_name_spoof", f'display name "{dn[:80]}" suggests {name_dom}, real From={from_domain}', 8)

    # --- Date vs topmost Received skew ---------------------------------------
    rec = _received_entries(pairs)
    if rec and rec[0]["ts"] is not None:
        try:
            dh = seen.get("date", [""])[0]
            date_ts = parsedate_to_datetime(dh) if dh else None
            if date_ts is not None:
                skew = (rec[0]["ts"].replace(tzinfo=None) - date_ts.replace(tzinfo=None)).total_seconds()
                if abs(skew) > 24 * 3600:
                    add(1, "date_skew", f"Date vs topmost Received skew {int(skew // 3600)}h", 3)
                elif skew < -300:
                    add(2, "date_skew", f"Date is {int(-skew // 60)}min in the future of first hop", 4)
        except Exception:
            pass

    # --- X-Originating-IP ----------------------------------------------------
    xip = seen.get("x-originating-ip", [])
    if xip:
        ips = _IP_RE.findall(xip[0])
        add(0, "x_originating_ip", f"X-Originating-IP: {ips[0] if ips else xip[0][:120]}", 0)

    # --- Header list for UI (ordered, cap 80) --------------------------------
    wanted = {h: i for i, h in enumerate(_INTERESTING)}
    shown = [p for p in pairs if p["name"].lower() in wanted]
    shown.sort(key=lambda p: wanted[p["name"].lower()])
    headers = [{"name": p["name"], "value": p["value"][:400]} for p in shown[:80]]

    return {"headers": headers, "receivedCount": len(rec),
            "checks": checks, "fromDomain": from_domain or None,
            "returnPathDomain": rp_domain or None, "replyToDomain": rt_domain or None,
            "messageIdDomain": mid_domain or None}
