"""Offline DNS cho dataset lịch sử - KHÔNG resolver mạng.

Snapshot là file JSON do điều tra viên cung cấp (xem tools/dns_snapshot.py).
Mọi kết quả đều gắn `source = local-snapshot`; thiếu snapshot -> not_run.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

_CACHE = {}


def _snapshot_path() -> Path:
    env = os.getenv("DNS_SNAPSHOT", "").strip()
    p = Path(env) if env else Path(__file__).resolve().parents[1] / "data" / "dns_snapshot.json"
    return p


def snapshot() -> dict:
    """Trả snapshot đã load (cache theo đường dẫn)."""
    p = _snapshot_path()
    key = str(p)
    if key not in _CACHE:
        data = {"generated_at": "", "sources": [], "records": {}}
        try:
            if p.is_file():
                loaded = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(loaded, dict) and isinstance(loaded.get("records"), dict):
                    data = loaded
                    data.setdefault("generated_at", "")
                    data.setdefault("sources", [])
        except Exception:
            pass
        _CACHE.clear()
        _CACHE[key] = data
    return _CACHE[key]


def source_info() -> dict:
    s = snapshot()
    return {"available": bool(s["records"]), "generated_at": s.get("generated_at", ""),
            "sources": s.get("sources", [])}


def normalize_domain(raw, allow_ip=False):
    d = str(raw or "").strip().rstrip(".").lower()
    if not d:
        return None
    if "@" in d:
        d = d.split("@")[-1]
    if allow_ip:
        try:
            ipaddress.ip_address(d)
            return d
        except ValueError:
            pass
    return d if re.match(r"^[a-z0-9.\-_]+$", d) else None


def normalize_selector(raw):
    s = str(raw or "").strip()
    return s if re.match(r"^[A-Za-z0-9._-]+$", s) else None


def _resolve(name, rdtype):
    """-> (records:list[str], errors:list). Chỉ đọc snapshot."""
    n = str(name or "").strip().rstrip(".").lower()
    recs = (snapshot()["records"].get(n) or {}).get(str(rdtype).upper(), []) or []
    if isinstance(recs, str):
        recs = [recs]
    if not recs:
        return [], [{"code": "not_run", "message": "no local snapshot record"}]
    return [str(x) for x in recs], []


def dnsfunc(name, timeout=5):
    """Hàm dnsfunc cho pyspf/dkimpy: trả TXT đầu tiên từ snapshot."""
    recs, _ = _resolve(name, "TXT")
    return recs[0] if recs else None


def lookup_domain(domain, rdtype="a", selector=None):
    d = normalize_domain(domain)
    if not d:
        return {"ok": False, "error": "bad_domain"}
    t = str(rdtype or "a").lower()
    if t == "ptr":
        try:
            rev = ipaddress.ip_address(d).reverse_pointer
        except ValueError:
            return {"source": "local-snapshot", "domain": d, "type": "ptr",
                    "records": {"ptr": []}, "errors": [{"code": "bad_ip"}]}
        recs, errs = _resolve(rev, "PTR")
        return {"source": "local-snapshot", "domain": d, "type": "ptr",
                "records": {"ptr": recs}, "errors": errs}
    if t in ("spf", "dmarc", "dkim"):
        name = d
        if t == "dmarc":
            name = f"_dmarc.{d}"
        elif t == "dkim":
            sel = normalize_selector(selector)
            if not sel:
                return {"error": "selector"}
            name = f"{sel}._domainkey.{d}"
        recs, errs = _resolve(name, "TXT")
        return {"source": "local-snapshot", "domain": d, "type": t,
                "records": {"txt": recs}, "errors": errs}
    recs, errs = _resolve(d, t.upper())
    return {"source": "local-snapshot", "domain": d, "type": t,
            "records": {t: recs}, "errors": errs}


def lookup_auth(domain):
    d = normalize_domain(domain)
    out = {"source": "local-snapshot", "domain": d or "", "auth": {}, "records": {}, "errors": []}
    if not d:
        out["errors"] = [{"code": "bad_domain"}]
        return out
    spf = [x for x in _resolve(d, "TXT")[0] if x.startswith("v=spf1")]
    out["auth"]["spf"] = {"found": bool(spf), "raw": spf[0] if spf else "", "records": spf}
    dm = [x for x in _resolve(f"_dmarc.{d}", "TXT")[0] if "v=DMARC1" in x]
    m = re.search(r"p=([a-z]+)", dm[0]) if dm else None
    out["auth"]["dmarc"] = {"found": bool(dm), "raw": dm[0] if dm else "",
                            "policy": m.group(1) if m else None}
    mx, _ = _resolve(d, "MX")
    out["records"]["mx"] = mx
    out["records"]["txt"] = _resolve(d, "TXT")[0]
    return out


def reverse_ptr(ip):
    try:
        rev = ipaddress.ip_address(str(ip)).reverse_pointer
    except ValueError:
        return {"names": [], "errors": [{"code": "bad_ip"}], "source": "local-snapshot"}
    names, errs = _resolve(rev, "PTR")
    return {"names": names, "errors": errs, "source": "local-snapshot"}
