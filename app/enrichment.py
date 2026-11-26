"""Enrichment — GeoLite2, DNS stub, confidence %, server classification."""
import os, ipaddress as ipmod, socket
from pathlib import Path

def _geo_dir() -> Path:
    env = os.getenv("GEOIP_DIR", "")
    p = Path(env) if env else (Path(__file__).resolve().parents[1] / ".." / "mailsleuth" / "geoip")
    return p.resolve()

_city = _asn = _country = None

def _open():
    global _city, _asn, _country
    if _city is not None: return
    try:
        import geoip2.database
    except Exception:
        _city = _asn = _country = False; return
    d = _geo_dir()
    try:
        _city = geoip2.database.Reader(str(d / "GeoLite2-City.mmdb"))
    except Exception: _city = False
    try:
        _asn = geoip2.database.Reader(str(d / "GeoLite2-ASN.mmdb"))
    except Exception: _asn = False
    try:
        _country = geoip2.database.Reader(str(d / "GeoLite2-Country.mmdb"))
    except Exception: _country = False

def geo_lookup(ip: str) -> dict:
    _open()
    out = {"city": None, "country": None, "countryIso": None, "asn": None, "organization": None,
           "location": None, "subdivisions": []}
    try: ipmod.ip_address(ip)
    except Exception: return out
    if _city and hasattr(_city, "city"):
        try:
            r = _city.city(ip)
            out["city"] = r.city.name; out["country"] = r.country.name
            out["countryIso"] = r.country.iso_code
            out["location"] = {"latitude": r.location.latitude, "longitude": r.location.longitude,
                               "accuracyRadiusKm": r.location.accuracy_radius, "timeZone": r.location.time_zone}
            out["subdivisions"] = [s.name for s in (r.subdivisions or [])]
            out["asn"] = getattr(r, "traits", None) and None
        except Exception: pass
    if _asn and hasattr(_asn, "asn"):
        try:
            r = _asn.asn(ip); out["asn"] = r.autonomous_system_number
            out["organization"] = r.autonomous_system_organization
        except Exception: pass
    return out

def confidence(geo: dict | None, ptr_names: list) -> int:
    c = 0
    loc = (geo or {}).get("location") or {}
    if loc.get("latitude") is not None and loc.get("longitude") is not None: c += 40
    if (geo or {}).get("city"): c += 15
    if (geo or {}).get("country"): c += 15
    if (geo or {}).get("asn") is not None or (geo or {}).get("organization"): c += 15
    if ptr_names: c += 15
    return c

def reverse_ptr(ip: str) -> dict:
    # dnspython only — lifetime capped 4s. No socket.gethostbyaddr fallback:
    # the OS resolver has no timeout control and hangs for tens of seconds per IP
    # on VM/NAT networks (this froze big-dataset analysis).
    try:
        from .dns_local import reverse_ptr as dns_ptr
        return dns_ptr(ip)
    except Exception:
        return {"names": [], "errors": []}

def classify_server(ptr: list, geo: dict, is_mx_of: list) -> dict:
    org = str((geo or {}).get("organization") or "").lower()
    if is_mx_of: return {"key": "mail", "evidence": f"MX of {', '.join(is_mx_of)}"}
    if any(x in org for x in ("hosting", "datacenter", "cloud", "vultr", "digitalocean")):
        return {"key": "hosting", "evidence": (geo or {}).get("organization") or ""}
    if any(x in org for x in ("cdn", "fastly", "cloudflare", "akamai")):
        return {"key": "cdn", "evidence": (geo or {}).get("organization") or ""}
    return {"key": "unknown", "evidence": ""}

def score(messages: list) -> tuple:
    s, v = 100, "clean"
    if not messages: return 100, "clean"
    if not any(m.get("originIPs") for m in messages): s -= 20
    s = max(0, s); return s, v
