"""Offline DNS for historical datasets (no network).

P3 will load a user-supplied snapshot (zone/JSON). Until then every lookup
returns an explicit unavailable/not_run result - never a live resolver query.
"""
import re


def normalize_domain(raw, allow_ip=False):
    d = str(raw or "").strip().rstrip(".").lower()
    if not d:
        return None
    if "@" in d:
        d = d.split("@")[-1]
    return d if re.match(r"^[a-z0-9.-]+$", d) else None


def normalize_selector(raw):
    s = str(raw or "").strip()
    return s if re.match(r"^[A-Za-z0-9._-]+$", s) else None


def lookup_domain(domain, rdtype="a", selector=None):
    d = normalize_domain(domain)
    if not d:
        return {"ok": False, "error": "bad_domain"}
    return {"source": "snapshot-unavailable", "domain": d, "type": rdtype,
            "records": {}, "errors": [], "note": "not_run: no local DNS snapshot provided"}


def lookup_auth(domain):
    d = normalize_domain(domain)
    return {"source": "snapshot-unavailable", "domain": d or "", "auth": {},
            "records": {}, "errors": [], "note": "not_run: no local DNS snapshot provided"}


def reverse_ptr(ip):
    return {"names": [], "errors": [], "source": "snapshot-unavailable"}


def _resolve(name, rdtype):
    """Offline-only resolver stub. Trả về rỗng; P3 sẽ nạp snapshot local."""
    return [], []
