"""MapGlot reverse geocoding — faithful port of server/mapglot.js.

GET {MAPGLOT_BASE}/api/v1/reverse?lat=&lon=&lang=&key=
  MAPGLOT_BASE default https://mapglot.com (NOT api.mapglot.com)
  key as query param, lang whitelist, 7-day cache (max 500),
  last-error per key: quota | unverified | invalid | unavailable
Map image remains OSM tiles (MapGlot has no static-image API).
"""
import os, re, time, threading
import requests

TIMEOUT = 8
CACHE_MS = 7 * 24 * 3600 * 1000
MAX_CACHE = 500
LANGS = {"ko","en","ja","zh","es","fr","de","ru","ar","pt","hi"}
KEY_RE = re.compile(r"^[\x21-\x7e]{1,200}$")

_cache = {}
_last_err = {}
_lock = threading.Lock()

def get_base() -> str:
    return (os.getenv("MAPGLOT_BASE") or "https://mapglot.com").rstrip("/")

def key_ok(key: str) -> bool:
    return bool(KEY_RE.match(str(key or "")))

def last_error_of(key: str):
    return _last_err.get(key)

def _norm_lang(lang: str) -> str:
    return lang if lang in LANGS else "en"

def reverse(lat, lng, key, lang="en"):
    """-> {display, address} | None"""
    if not key or not key_ok(key): return None
    try:
        lat = float(lat); lng = float(lng)
    except Exception: return None
    lang = _norm_lang(lang)
    ck = f"{lat:.4f},{lng:.4f},{lang}"
    now = time.time() * 1000
    with _lock:
        hit = _cache.get(ck)
        if hit and now - hit[0] < CACHE_MS:
            return hit[1]
    data = None
    try:
        r = requests.get(get_base() + "/api/v1/reverse",
                         params={"lat": lat, "lon": lng, "lang": lang, "key": key},
                         headers={"accept": "application/json"}, timeout=TIMEOUT)
        if r.ok:
            j = r.json()
            if isinstance(j, dict):
                admin = j.get("admin") or {}
                data = {
                    "display": str(j.get("display_name") or "")[:300] or None,
                    "address": str(admin.get("formatted_address") or admin.get("road_address") or "")[:300] or None,
                }
            with _lock: _last_err.pop(key, None)
        else:
            msg = r.text or ""
            code = "quota" if r.status_code == 429 else ("unverified" if re.search(r"not verified", msg, re.I) else ("invalid" if r.status_code in (401, 403) else "unavailable"))
            with _lock: _last_err[key] = code
    except Exception:
        with _lock: _last_err[key] = "unavailable"
    with _lock:
        if len(_cache) >= MAX_CACHE:
            if _cache: _cache.pop(next(iter(_cache)))
        _cache[ck] = (now, data)
    return data
