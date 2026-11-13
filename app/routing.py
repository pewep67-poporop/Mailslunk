"""M3 — SMTP / Email Routing reconstruction from Received chain.

Reads every Received header (top = last hop, bottom = first hop), rebuilds the
hop path with delays and flags anomalies (missing from-clause, loops, negative
delays, long pauses, private IPs). Finding ids are prefixed R-.
"""
import re
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from .parsers import is_private

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_GATEWAYS = {"google": ["google", "gmail"], "microsoft": ["outlook", "microsoft", "office365", "protection.outlook"],
             "proofpoint": ["proofpoint", "pphosted"], "mimecast": ["mimecast"], "barracuda": ["barracuda"],
             "zoho": ["zoho"], "yandex": ["yandex"], "tencent": ["qq.com", "tencent"], "amazon": ["amazonaws", "amazonses"],
             "ovh": ["ovh"], "hetzner": ["hetzner"], "cloudflare": ["cloudflare"]}


def _gateway(text: str) -> str:
    t = (text or "").lower()
    for gw, keys in _GATEWAYS.items():
        if any(k in t for k in keys): return gw
    return ""


def _received_raw(raw: bytes):
    msg = BytesParser(policy=policy.compat32).parsebytes(raw, headersonly=True)
    return [str(v).replace("\r", " ") for k, v in msg.items() if str(k).lower() == "received"]


def _parse_hop(v: str, idx: int) -> dict:
    ts = None
    m = re.search(r";\s*(.+?)\s*$", v)
    if m:
        try: ts = parsedate_to_datetime(m.group(1))
        except Exception: ts = None
    head = v.split(";", 1)[0]
    fm = re.match(r"(?i)^\s*from\s+(\S+)", head)
    paren = re.match(r"(?i)^\s*from\s+\S+\s*\(([^)]*)\)", head)
    ip = None
    if paren:
        ips = _IP_RE.findall(paren.group(1))
        if ips: ip = ips[0]
    if not ip:
        pre_by = head.split(" by ", 1)[0]
        m2 = _IP_RE.search(pre_by)
        if m2: ip = m2.group(0)
    host = fm.group(1).strip("()") if fm else ""
    if ip and "(" in host: host = host.split("(")[0].strip()
    return {"idx": idx, "from": host[:200] or None, "ip": ip,
            "private": bool(ip and is_private(ip)),
            "by": (re.search(r"(?i)\bby\s+(\S+)", head) or [None, None])[1][:200] if re.search(r"(?i)\bby\s+(\S+)", head) else None,
            "with": (re.search(r"(?i)\bwith\s+(\S+)", head) or [None, None])[1][:60] if re.search(r"(?i)\bwith\s+(\S+)", head) else None,
            "via": (re.search(r"(?i)\bvia\s+(\S+)", head) or [None, None])[1][:200] if re.search(r"(?i)\bvia\s+(\S+)", head) else None,
            "for": (re.search(r"(?i)\bfor\s+<([^>]+)>", head) or [None, None])[1][:200] if re.search(r"(?i)\bfor\s+<([^>]+)>", head) else None,
            "ts": ts.isoformat() if ts else None, "_ts": ts, "delayMs": None,
            "gateway": _gateway(head)}


def analyze_routing(raw: bytes) -> dict:
    """-> {hops, anomalies, totalDelayMs}"""
    received = _received_raw(raw)
    hops = [_parse_hop(v, i + 1) for i, v in enumerate(received[:40])]
    anomalies = []
    nid = [0]

    def add(sev: int, ftype: str, evidence: str, weight: int = 0):
        nid[0] += 1
        anomalies.append({"id": f"R-{nid[0]:03d}", "sev": int(sev),
                          "severity": {0: "info", 1: "low", 2: "medium", 3: "high"}.get(int(sev)),
                          "type": ftype, "evidence": evidence[:300], "weight": weight})

    # delays walking the chain oldest (last hop) -> newest (first hop)
    total = 0
    for i in range(len(hops) - 1, 0, -1):
        older, newer = hops[i], hops[i - 1]
        if older["_ts"] and newer["_ts"]:
            d_ms = int((newer["_ts"].replace(tzinfo=None) - older["_ts"].replace(tzinfo=None)).total_seconds() * 1000)
            newer["delayMs"] = d_ms
            total += d_ms
            if d_ms < -120000:
                add(2, "hop_negative_delay", f"hop #{newer['idx']} timestamp runs {abs(d_ms)//60000}min backwards (clock skew or forgery)", 4)
            elif d_ms > 24 * 3600 * 1000:
                add(1, "hop_delay", f"hop #{newer['idx']} delayed {d_ms // 3600000}h", 2)
    for h in hops: h.pop("_ts", None)

    for h in hops:
        if not h["from"] and not h["ip"]:
            add(2, "hop_missing_from", f"hop #{h['idx']} has no from clause (possible forged entry)", 4)
        if h["ip"] and h["private"]:
            add(0, "private_ip_hop", f"hop #{h['idx']} from private IP {h['ip']} (internal relay)", 0)

    seen_ip = {}
    for h in hops:
        if h["ip"]:
            if h["ip"] in seen_ip:
                add(2, "hop_loop", f"IP {h['ip']} appears in hop #{seen_ip[h['ip']]} and #{h['idx']} (routing loop)", 5)
            else: seen_ip[h["ip"]] = h["idx"]

    return {"hops": hops, "anomalies": anomalies,
            "totalDelayMs": total if total > 0 else 0,
            "hopCount": len(hops)}
