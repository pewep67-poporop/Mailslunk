"""Native DNS via dnspython — port of server/dns.js (core records)."""
import os, re
try:
    import dns.resolver, dns.reversename, dns.exception
    HAVE_DNS = True
except Exception:
    HAVE_DNS = False

if HAVE_DNS:
    try:  # cap the DEFAULT resolver too — pyspf (SPF) queries go through it,
          # so include/redirect chains cannot hang for minutes on a slow resolver
        _r = dns.resolver.get_default_resolver()
        _r.timeout = 2.0
        _r.lifetime = 5.0
    except Exception:
        pass

def normalize_domain(raw, allow_ip=False):
    d = str(raw or "").strip().rstrip(".").lower()
    if not d: return None
    if "@" in d: d = d.split("@")[-1]
    return d if re.match(r"^[a-z0-9.-]+$", d) else None

def normalize_selector(raw):
    s = str(raw or "").strip()
    return s if re.match(r"^[A-Za-z0-9._-]+$", s) else None

def _resolve(name, rdtype):
    if not HAVE_DNS: return [], []
    r = dns.resolver.Resolver()
    r.lifetime = 4
    try:
        ans = r.resolve(name, rdtype, lifetime=4)
        out = []
        for x in ans:
            s = str(x).rstrip(".")
            if str(rdtype).upper() == "TXT":
                if hasattr(x, "strings"):  # join TXT chunks, drop dnspython quotes
                    s = "".join(p.decode("utf-8", "ignore") for p in x.strings)
            out.append(s)
        return out, []
    except dns.exception.Timeout:
        return [], [{"code": "dns_timeout", "message": "DNS query timed out"}]
    except Exception as e:
        return [], [{"code": "dns_error", "message": str(e)[:200]}]

def lookup_domain(domain, rdtype="a", selector=None):
    domain = normalize_domain(domain)
    if not domain: return {"ok": False, "error": "bad_domain"}
    t = (rdtype or "a").lower()
    if t == "all":
        recs = {}
        for k in ("a","aaaa","mx","txt","ns","soa"):
            v, _ = _resolve(domain, k.upper()); recs[k] = v
        return {"source": "native", "domain": domain, "type": "all", "records": recs, "errors": [], "resolver": []}
    if t in ("a","aaaa","mx","txt","ns","soa","cname"):
        v, errs = _resolve(domain, t.upper())
        return {"source": "native", "domain": domain, "type": t, "records": {t: v}, "errors": errs, "resolver": []}
    if t == "ptr":
        import ipaddress as ipmod
        try:
            rn = dns.reversename.from_address(domain)
            v, errs = _resolve(str(rn), "PTR")
            return {"source": "native", "domain": domain, "type": "ptr",
                    "records": {"ptr": v}, "errors": errs, "resolver": []}
        except Exception:
            return {"source": "native", "domain": domain, "type": "ptr", "records": {"ptr": []}, "errors": [], "resolver": []}
    if t in ("spf", "dmarc", "dkim"):
        if t == "spf":
            v, errs = _resolve(domain, "TXT")
            spf = [x for x in v if x.startswith("v=spf1")]
            return {"source": "native", "domain": domain, "type": "spf",
                    "auth": {"spf": {"found": bool(spf), "raw": spf[0] if spf else "", "records": spf, "all": (spf[0].split("all=")[-1] if spf and "all=" in spf[0] else None)}},
                    "records": {"txt": v}, "errors": errs, "resolver": []}
        if t == "dmarc":
            v, errs = _resolve(f"_dmarc.{domain}", "TXT")
            dm = [x for x in v if "v=DMARC1" in x]
            pol = None
            if dm:
                m = re.search(r"p=([a-z]+)", dm[0]); pol = m.group(1) if m else None
            return {"source": "native", "domain": domain, "type": "dmarc",
                    "auth": {"dmarc": {"found": bool(dm), "raw": dm[0] if dm else "", "policy": pol}},
                    "records": {"txt": v}, "errors": errs, "resolver": []}
        sel = normalize_selector(selector)
        if not sel: return {"error": "selector"}
        v, errs = _resolve(f"{sel}._domainkey.{domain}", "TXT")
        return {"source": "native", "domain": domain, "type": "dkim",
                "auth": {"dkim": {"found": bool(v), "raw": v[0] if v else "", "selector": sel}},
                "records": {"txt": v}, "errors": errs, "resolver": []}
    if t == "asn":
        return {"source": "native", "type": "asn", "domain": domain, "records": {}, "errors": [], "resolver": []}
    return {"error": "bad_type"}

def lookup_auth(domain):
    d = normalize_domain(domain)
    out = {"auth": {}, "records": {}, "errors": []}
    if not d: return out
    spf = lookup_domain(d, "spf"); dm = lookup_domain(d, "dmarc")
    out["auth"]["spf"] = (spf.get("auth") or {}).get("spf", {"found": False})
    out["auth"]["dmarc"] = (dm.get("auth") or {}).get("dmarc", {"found": False})
    mx, _ = _resolve(d, "MX")
    out["records"]["mx"] = [{"priority": int(x[0]), "exchange": x[1]} for m in mx for x in [m.split(" ",1)] if len(x)==2]
    if mx and not out["records"]["mx"]:
        out["records"]["mx"] = [{"priority": 10, "exchange": m} for m in mx]
    return out

def reverse_ptr(ip):
    if not HAVE_DNS: return {"names": [], "errors": [], "at": ""}
    try:
        rn = dns.reversename.from_address(ip)
        v, errs = _resolve(str(rn), "PTR")
        return {"names": v, "errors": errs, "at": ""}
    except Exception:
        return {"names": [], "errors": [], "at": ""}
