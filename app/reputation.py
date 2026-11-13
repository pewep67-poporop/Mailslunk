"""M9 — Reputation lookups (URL / file hash) against public threat feeds.

Design rules (forensic + privacy):
  * OFF by default (`REPUTATION_ENABLED=0`) -> the server stays offline-safe
    and behaviour is byte-identical to a build without this module.
  * Keys live per-user in the `kv` table (never echoed, never logged); env
    vars are only a fallback for unattended deployments.
  * Only the URL / the SHA-256 is ever sent to a provider - never mail
    content, headers, recipients or file bodies.
  * Every provider call goes through a circuit breaker: a failing feed is
    skipped for 60 s instead of blocking requests on timeouts.
  * A lookup never raises: failures degrade to "unknown".

Providers
  URLhaus          POST https://urlhaus-api.abuse.ch/v1/url/   (header Auth-Key)
  VirusTotal       GET  https://www.virustotal.com/api/v3/urls/{id}  (hash-only for files)
  Safe Browsing    POST https://safebrowsing.googleapis.com/v4/threatMatches:find
"""
import base64
import hashlib
import os
import time

from .breaker import CircuitOpen, get_breaker

CACHE_TTL = int(os.getenv("REPUTATION_CACHE_TTL", "3600") or 3600)
MAX_URLS = int(os.getenv("REPUTATION_MAX_URLS", "10") or 10)
TIMEOUT = float(os.getenv("REPUTATION_TIMEOUT", "6") or 6)

_URLHAUS = "https://urlhaus-api.abuse.ch/v1/url/"
_URLHAUS_HOST = "https://urlhaus-api.abuse.ch/v1/host/"
_VT_URL = "https://www.virustotal.com/api/v3/urls/"
_VT_FILE = "https://www.virustotal.com/api/v3/files/"
_SB = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

_cache = {}          # key -> (expires_at, value)
_cache_order = []


def enabled() -> bool:
    return os.getenv("REPUTATION_ENABLED", "0") == "1" and os.getenv("LIVE_DNS", "1") != "0"


def _cache_get(key):
    hit = _cache.get(key)
    if hit and hit[0] > time.time():
        return hit[1]
    return None


def _cache_put(key, value):
    _cache[key] = (time.time() + CACHE_TTL, value)
    _cache_order.append(key)
    if len(_cache_order) > 2048:                      # bounded cache
        for k in _cache_order[:1024]:
            _cache.pop(k, None)
        del _cache_order[:1024]
    return value


def clear_cache() -> None:
    _cache.clear()
    del _cache_order[:]


def _key(name: str, user: str = "") -> str:
    """Per-user key from `kv` first, env as fallback. Never logged."""
    if user:
        try:
            from .db import kv_get
            v = kv_get(f"reputation.{name}:{user}")
            if v:
                return v
        except Exception:
            pass
    return (os.getenv(f"{name.upper()}_KEY") or "").strip()


def _requests():
    import requests
    return requests


def _verdict(malicious: bool, suspicious: bool = False) -> str:
    if malicious:
        return "malicious"
    if suspicious:
        return "suspicious"
    return "clean"


# --------------------------------------------------------------------------
# Providers
# --------------------------------------------------------------------------
def _urlhaus(url: str, key: str) -> dict:
    br = get_breaker("reputation.urlhaus")
    r = br.call(_requests().post, _URLHAUS, data={"url": url},
                headers={"Auth-Key": key} if key else {}, timeout=TIMEOUT)
    j = r.json() if r.content else {}
    if str(j.get("query_status")) == "no_results":
        return {"provider": "urlhaus", "verdict": "clean", "detail": "not listed"}
    return {"provider": "urlhaus", "verdict": "malicious",
            "detail": f"{j.get('threat', '?')} · {j.get('urlhaus_link', '')[:120]}"}


def _virustotal_url(url: str, key: str) -> dict:
    br = get_breaker("reputation.virustotal")
    uid = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    r = br.call(_requests().get, _VT_URL + uid, headers={"x-apikey": key}, timeout=TIMEOUT)
    j = r.json() if r.content else {}
    stats = ((j.get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
    mal = int(stats.get("malicious") or 0)
    sus = int(stats.get("suspicious") or 0)
    if mal or sus:
        return {"provider": "virustotal", "verdict": _verdict(mal > 0, sus > 0),
                "detail": f"malicious={mal} suspicious={sus}"}
    return {"provider": "virustotal", "verdict": "clean", "detail": "not listed"}


def _virustotal_hash(sha256: str, key: str) -> dict:
    br = get_breaker("reputation.virustotal")
    r = br.call(_requests().get, _VT_FILE + sha256, headers={"x-apikey": key}, timeout=TIMEOUT)
    j = r.json() if r.content else {}
    stats = ((j.get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
    mal = int(stats.get("malicious") or 0)
    sus = int(stats.get("suspicious") or 0)
    if mal or sus:
        return {"provider": "virustotal", "verdict": _verdict(mal > 0, sus > 0),
                "detail": f"malicious={mal} suspicious={sus}"}
    return {"provider": "virustotal", "verdict": "clean", "detail": "not listed"}


def _safebrowsing(url: str, key: str) -> dict:
    br = get_breaker("reputation.safebrowsing")
    payload = {"client": {"clientId": "mailsleuth", "clientVersion": "1.0"},
               "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING",
                                              "UNWANTED_SOFTWARE", "PHISHING"],
                              "url": url}}
    r = br.call(_requests().post, _SB, params={"key": key}, json=payload, timeout=TIMEOUT)
    j = r.json() if r.content else {}
    matches = j.get("matches") or []
    if matches:
        types = sorted({str(m.get("threatType", "")) for m in matches})
        return {"provider": "safebrowsing", "verdict": "malicious", "detail": ", ".join(types)}
    return {"provider": "safebrowsing", "verdict": "clean", "detail": "no threat match"}


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------
def check_url(url: str, user: str = "") -> dict:
    """-> {verdict: clean|suspicious|malicious|unknown, providers:[...]}"""
    out = {"verdict": "unknown", "providers": []}
    if not url or not enabled():
        out["verdict"] = "unknown"
        return out
    ck = "url:" + url
    hit = _cache_get(ck)
    if hit is not None:
        return hit
    results = []
    ah = _key("abusech", user)
    vt = _key("vt", user)
    sb = _key("sb", user)
    for fn, arg, key, label in ((_urlhaus, url, ah, "urlhaus"),
                                (_virustotal_url, url, vt, "virustotal"),
                                (_safebrowsing, url, sb, "safebrowsing")):
        if label == "urlhaus" and not ah:
            continue                      # abuse.ch requires Auth-Key since 2024
        if label == "virustotal" and not vt:
            continue
        if label == "safebrowsing" and not sb:
            continue
        try:
            results.append(fn(arg, key))
        except CircuitOpen:
            results.append({"provider": label, "verdict": "unknown", "detail": "circuit open"})
        except Exception as e:
            results.append({"provider": label, "verdict": "unknown",
                            "detail": f"{type(e).__name__}"})
    out["providers"] = results
    verdicts = [r.get("verdict") for r in results]
    if "malicious" in verdicts:
        out["verdict"] = "malicious"
    elif "suspicious" in verdicts:
        out["verdict"] = "suspicious"
    elif results and all(v == "clean" for v in verdicts):
        out["verdict"] = "clean"
    else:
        out["verdict"] = "unknown"
    return _cache_put(ck, out)


def check_hash(sha256: str, user: str = "") -> dict:
    """Hash lookup only - the file itself is never uploaded anywhere."""
    out = {"verdict": "unknown", "providers": []}
    if not sha256 or not enabled():
        return out
    ck = "sha:" + sha256
    hit = _cache_get(ck)
    if hit is not None:
        return hit
    results = []
    vt = _key("vt", user)
    if vt:
        try:
            results.append(_virustotal_hash(sha256, vt))
        except CircuitOpen:
            results.append({"provider": "virustotal", "verdict": "unknown", "detail": "circuit open"})
        except Exception as e:
            results.append({"provider": "virustotal", "verdict": "unknown",
                            "detail": f"{type(e).__name__}"})
    out["providers"] = results
    verdicts = [r.get("verdict") for r in results]
    if "malicious" in verdicts:
        out["verdict"] = "malicious"
    elif "suspicious" in verdicts:
        out["verdict"] = "suspicious"
    elif results and all(v == "clean" for v in verdicts):
        out["verdict"] = "clean"
    return _cache_put(ck, out)
