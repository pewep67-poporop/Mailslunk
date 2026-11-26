"""M2 — Real SPF / DKIM / DMARC verification (RFC 7208 / 6376 / 7489).

Everything reported here is verifiable evidence, never a guess:

  SPF   : pyspf evaluates the published SPF record of the *envelope sender*
          (MAIL FROM / Return-Path) against
            - the client IP of the bottom-most Received hop (the host that
              connected to the receiver), and
            - the HELO/EHLO name that hop announced.
          A message without Return-Path has an unknown MAIL FROM -> "none",
          never a guess based on the From: address.
  DKIM  : dkimpy verifies **every** DKIM-Signature header of the raw bytes
          (RSA / Ed25519, relaxed + simple canonicalisation) and fetches the
          public key from the real DNS (_domainkey.<selector>.<domain>).
          Each signature is reported separately so a message with one good and
          one bad signature is not judged by the wrong one.
  DMARC : the published _dmarc record is fetched and relaxed alignment
          (organisational domain, Public-Suffix aware) is evaluated for the
          SPF-authenticated domain and for the *verified* DKIM domain.

The Authentication-Results header written by the receiving mail server is
parsed as well ("upstream") so an analyst can compare what the original
receiver saw with what this tool computed.

DNS answers are cached (DNS_CACHE_TTL, default 300 s): a PST with 1000
messages would otherwise trigger thousands of identical lookups.
"""
import os
import re
import time

# --------------------------------------------------------------------------
# Public Suffix handling (compact list — enough for the common multi-label
# suffixes so relaxed alignment is correct for e.g. example.co.uk)
# --------------------------------------------------------------------------
_MULTI_SUFFIX = {
    # United Kingdom
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk", "sch.uk", "ltd.uk", "plc.uk",
    # Australia / New Zealand
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au", "asn.au",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "school.nz", "geek.nz",
    # Asia
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "lg.jp",
    "co.kr", "or.kr", "ne.kr", "go.kr", "re.kr", "pe.kr",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn", "mil.cn",
    "com.hk", "net.hk", "org.hk", "edu.hk", "gov.hk", "idv.hk",
    "com.tw", "net.tw", "org.tw", "edu.tw", "gov.tw", "idv.tw",
    "com.sg", "net.sg", "org.sg", "edu.sg", "gov.sg", "per.sg",
    "com.my", "net.my", "org.my", "edu.my", "gov.my", "mil.my",
    "com.ph", "net.ph", "org.ph", "edu.ph", "gov.ph",
    "co.th", "in.th", "or.th", "go.th", "ac.th", "mi.th", "net.th",
    "co.id", "or.id", "web.id", "go.id", "ac.id", "sch.id", "net.id", "my.id",
    "co.il", "org.il", "net.il", "ac.il", "gov.il", "k12.il",
    "com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn", "int.vn", "ac.vn",
    # America
    "com.br", "net.br", "org.br", "gov.br", "edu.br", "art.br",
    "com.mx", "org.mx", "gob.mx", "edu.mx", "net.mx",
    "com.ar", "net.ar", "org.ar", "gob.ar", "edu.ar", "mil.ar",
    "com.co", "net.co", "org.co", "gov.co", "edu.co", "mil.co",
    "com.pe", "net.pe", "org.pe", "gob.pe", "edu.pe",
    "com.uy", "net.uy", "org.uy", "gub.uy", "edu.uy",
    "com.ec", "net.ec", "org.ec", "gob.ec", "edu.ec", "fin.ec",
    "com.bo", "com.py", "com.do", "com.gt", "com.sv", "com.hn", "com.pa",
    "com.ni", "com.cr", "com.pr", "com.jm", "com.tt", "com.bs",
    "co.za", "org.za", "net.za", "gov.za", "ac.za", "web.za", "edu.za",
    "co.ke", "or.ke", "ne.ke", "go.ke", "ac.ke", "info.ke",
    "com.ng", "org.ng", "gov.ng", "edu.ng", "net.ng",
    "co.tz", "ac.tz", "go.tz", "or.tz", "ne.tz",
    "com.gh", "edu.gh", "gov.gh", "org.gh", "mil.gh",
    # Europe
    "com.es", "nom.es", "org.es", "gob.es", "edu.es",
    "com.pt", "edu.pt", "gov.pt", "org.pt", "net.pt",
    "com.gr", "edu.gr", "gov.gr", "net.gr", "org.gr",
    "com.cy", "net.cy", "org.cy", "gov.cy", "ac.cy",
    "com.hr", "com.ba", "com.mk", "com.al", "com.me", "com.mt",
    "co.rs", "org.rs", "edu.rs", "ac.rs", "gov.rs", "in.rs",
    "co.hu", "org.hu", "info.hu", "priv.hu", "sport.hu", "tm.hu",
    "com.pl", "net.pl", "org.pl", "gov.pl", "edu.pl", "waw.pl",
    "com.ua", "net.ua", "org.ua", "kiev.ua", "com.ru", "net.ru", "org.ru",
    "spb.ru", "msk.ru", "com.by", "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr",
    "com.ro", "org.ro", "tm.ro", "com.bg", "net.bg", "org.bg", "edu.bg",
    "co.rs", "com.de", "com.se", "com.ee", "org.ee", "fie.ee", "pri.ee",
    "com.lv", "org.lv", "edu.lv", "gov.lv", "com.lt", "gov.lt", "edu.lt",
    # Middle East / Africa
    "com.eg", "net.eg", "org.eg", "gov.eg", "edu.eg", "com.sa", "net.sa", "org.sa",
    "gov.sa", "edu.sa", "co.ae", "net.ae", "org.ae", "gov.ae", "ac.ae",
    "com.tr", "com.ng", "co.ug", "or.ug", "ac.ug", "go.ug",
    # hosting / PaaS suffixes (public in the PSL sense)
    "github.io", "gitlab.io", "herokuapp.com", "appspot.com", "cloudfront.net",
    "s3.amazonaws.com", "azurewebsites.net", "pages.dev", "workers.dev", "web.app",
    "firebaseapp.com", "vercel.app", "netlify.app", "onrender.com",
}


def _public_suffix(domain: str) -> str:
    """Public suffix of a domain (best effort, compact built-in list)."""
    d = (domain or "").lower().strip().strip(".")
    if not d:
        return ""
    parts = d.split(".")
    for i in range(1, min(4, len(parts))):
        cand = ".".join(parts[-i:])
        if cand in _MULTI_SUFFIX:
            return cand
    return parts[-1] if len(parts) >= 2 else d


def _org_domain(domain: str) -> str:
    """Organisational domain (eTLD+1) — used for relaxed DMARC alignment."""
    d = (domain or "").lower().strip().strip(".")
    if not d or "." not in d:
        return d
    suffix = _public_suffix(d)
    if not suffix:
        return d
    rest = d[: -(len(suffix) + 1)] if d.endswith("." + suffix) else ""
    if not rest:
        return d
    return ".".join([rest.split(".")[-1], suffix])


# --------------------------------------------------------------------------
# DNS cache
# --------------------------------------------------------------------------
def _cache_ttl() -> int:
    try:
        return max(0, int(os.getenv("DNS_CACHE_TTL", "300")))
    except Exception:
        return 300


_TXT_CACHE = {}
_SPF_CACHE = {}


def _cache_get(store, key):
    hit = store.get(key)
    if hit and hit[0] > time.time():
        return hit[1]
    return None


def _cache_put(store, key, value):
    store[key] = (time.time() + _cache_ttl(), value)
    if len(store) > 4096:  # keep the cache bounded
        for k in list(store.keys())[:1024]:
            store.pop(k, None)
    return value


def _txt_records(name: str) -> list:
    """TXT records of a domain (cached)."""
    key = (name or "").lower().strip().strip(".")
    if not key:
        return []
    hit = _cache_get(_TXT_CACHE, key)
    if hit is not None:
        return hit
    recs = []
    try:
        from .dns_local import _resolve
        recs, _err = _resolve(key, "TXT")
    except Exception:
        recs = []
    return _cache_put(_TXT_CACHE, key, recs)


def _dnsfunc(name, timeout=5):
    """dkimpy DNS interface: name (bytes) -> TXT record (bytes) or None."""
    if isinstance(name, bytes):
        name = name.decode("utf-8", "ignore")
    recs = _txt_records(name)
    if not recs:
        return None
    pick = next((r for r in recs if "p=" in r), recs[0])
    return pick.encode("utf-8", "ignore")


# --------------------------------------------------------------------------
# Header parsing
# --------------------------------------------------------------------------
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b")


def _is_public(ip: str) -> bool:
    import ipaddress as ipmod
    try:
        a = ipmod.ip_address(ip)
    except Exception:
        return False
    if a.is_private or a.is_loopback or a.is_link_local or a.is_multicast:
        return False
    if getattr(a, "is_reserved", False):
        return False
    if a.version == 4 and a in ipmod.ip_network("100.64.0.0/10"):  # CGNAT
        return False
    return True


def _ips_in(text: str) -> list:
    out = []
    for ip in _IPV4_RE.findall(text or ""):
        if ip not in out:
            out.append(ip)
    for ip in _IPV6_RE.findall(text or ""):
        if ip not in out:
            out.append(ip)
    return out


def _parse_headers(raw: bytes) -> dict:
    """Everything the auth checks need, taken from the raw evidence bytes."""
    from email import policy as _p
    from email.parser import BytesParser as _BP
    from email.utils import parseaddr
    out = {"received": [], "dkim_sigs": [], "ar": "", "authserv": "",
           "from_addr": "", "from_domain": "", "env_addr": "", "env_domain": "",
           "reply_to": "", "helo": "", "client_ip": None}
    try:
        msg = _BP(policy=_p.compat32).parsebytes(raw, headersonly=True)
    except Exception:
        return out
    hdrs = {}
    for k, v in msg.items():
        hdrs.setdefault(str(k).lower(), []).append(str(v).replace("\r", " ").strip())

    # --- Received chain (oldest = closest to the sender) ---
    rec = hdrs.get("received") or []
    out["received"] = rec
    for v in reversed(rec):  # bottom-most first
        head = v.split(" by ", 1)[0]
        for ip in _ips_in(head):
            if _is_public(ip):
                out["client_ip"] = ip
                break
        if out["client_ip"]:
            m = re.search(r"(?i)\bfrom\s+([A-Za-z0-9._\-\[\]:]+)", head)
            if m:
                helo = m.group(1).strip("[]").lower()
                if helo and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", helo):
                    out["helo"] = helo
            break
    if not out["client_ip"]:
        for v in reversed(rec):  # fall back: first public IP from the oldest hop
            for ip in _ips_in(v):
                if _is_public(ip):
                    out["client_ip"] = ip
                    break
            if out["client_ip"]:
                break

    # --- DKIM signatures ---
    for v in hdrs.get("dkim-signature") or []:
        d = re.search(r"(?i)\bd\s*=\s*([\w.\-]+)", v)
        s = re.search(r"(?i)\bs\s*=\s*([\w.\-]+)", v)
        a = re.search(r"(?i)\ba\s*=\s*([\w\-]+)", v)
        out["dkim_sigs"].append({"domain": (d.group(1).lower().rstrip(".") if d else ""),
                                 "selector": (s.group(1).lower() if s else None),
                                 "algorithm": (a.group(1).lower() if a else None),
                                 "header": v[:400]})

    # --- Authentication-Results written by the receiving server ---
    ar = hdrs.get("authentication-results") or []
    out["ar"] = ar[0] if ar else ""
    if out["ar"]:
        m = re.match(r"\s*([A-Za-z0-9._\-]+)", out["ar"])
        out["authserv"] = m.group(1).lower() if m else ""

    # --- addresses ---
    from_addr = (hdrs.get("from") or [""])[0]
    out["from_addr"] = from_addr
    fa = parseaddr(from_addr)[1]
    out["from_domain"] = fa.split("@")[-1].lower().rstrip(".") if "@" in fa else ""
    return_path = (hdrs.get("return-path") or [""])[0]
    rp = re.search(r"<([^>]+)>", return_path)
    env = (rp.group(1) if rp else "").strip()
    out["env_addr"] = env
    if env and "@" in env:
        out["env_domain"] = env.split("@")[-1].lower().rstrip(".")
    elif out["from_domain"]:
        out["env_domain"] = out["from_domain"]
    else:
        out["env_domain"] = ""
    out["reply_to"] = (hdrs.get("reply-to") or [""])[0]
    return out


# --------------------------------------------------------------------------
# SPF
# --------------------------------------------------------------------------
def _check_spf(client_ip: str, sender: str, helo: str) -> dict:
    """-> {result, domain, record, reason, clientIp, helo}"""
    domain = (sender or "").split("@")[-1].lower().rstrip(".") if "@" in (sender or "") else ""
    base = {"result": "none", "domain": domain, "record": "", "reason": "",
            "clientIp": client_ip, "helo": helo, "sender": sender}
    if os.getenv("LIVE_DNS") == "0":
        base.update({"result": "not_run", "reason": "LIVE_DNS disabled"})
        return base
    if not sender:
        base["reason"] = "no Return-Path (MAIL FROM unknown)"
        return base
    if not client_ip:
        base["reason"] = "no public client IP in the Received chain"
        return base
    try:
        import spf
    except Exception:
        base.update({"result": "not_run", "reason": "pyspf not installed"})
        return base
    key = (client_ip, sender.lower(), (helo or "").lower())
    hit = _cache_get(_SPF_CACHE, key)
    if hit is not None:
        return hit
    h = helo or domain
    try:
        r = spf.check2(i=client_ip, s=sender, h=h)
        if len(r) == 3:
            result, _code, expl = r
        else:
            result, expl = r
        res = str(result)
        reason = str(expl) if expl else ""
    except Exception as e:
        res, reason = "temperror", str(e)[:150]
    recs = _txt_records(domain)
    spf_rec = next((x for x in recs if x.lower().startswith("v=spf1")), "")
    out = dict(base)
    out.update({"result": res, "reason": reason[:300], "record": spf_rec[:300]})
    return _cache_put(_SPF_CACHE, key, out)


# --------------------------------------------------------------------------
# DKIM
# --------------------------------------------------------------------------
def _dkim_reason(exc: Exception) -> str:
    msg = str(exc)
    low = msg.lower()
    if "no key" in low or "no public key" in low:
        return "public key not found in DNS"
    if "body hash" in low:
        return "body hash does not match (content modified in transit)"
    if "signature" in low and "hash" in low:
        return "signature hash does not match"
    if "timeout" in low:
        return "DNS timeout while fetching the key"
    return msg[:200]


def _check_dkim(raw: bytes, sigs: list) -> dict:
    """Verify every DKIM-Signature separately -> per-signature verdicts."""
    out = {"result": "none", "signatures": [], "verifiedDomain": None,
           "verifiedSelector": None, "reason": "", "domain": None, "selector": None}
    if not sigs:
        out["reason"] = "no DKIM-Signature header"
        return out
    out["signatures"] = [{"domain": s["domain"], "selector": s["selector"],
                           "algorithm": s.get("algorithm"), "result": "not_run"}
                          for s in sigs]
    if os.getenv("LIVE_DNS") == "0":
        out["result"] = "not_run"
        out["reason"] = "LIVE_DNS disabled"
        return out
    try:
        import dkim
    except Exception:
        out["result"] = "not_run"
        out["reason"] = "dkimpy not installed"
        return out
    try:
        obj = dkim.DKIM(raw)
    except Exception as e:
        out["result"] = "fail"
        out["reason"] = "malformed DKIM signature: " + str(e)[:150]
        return out
    n = len(sigs)
    for idx in range(n):
        entry = out["signatures"][idx]
        sel, dom = sigs[idx].get("selector"), sigs[idx].get("domain")
        # Fetch the key ourselves first: dkimpy swallows "missing public key"
        # and returns False, which would hide the real reason from the analyst.
        if sel and dom:
            key_name = f"{sel}._domainkey.{dom}"
            key_recs = _txt_records(key_name)
            if not key_recs:
                entry["result"] = "fail"
                entry["reason"] = f"public key not found in DNS ({key_name})"
                continue
            rec = next((r for r in key_recs if "p=" in r), key_recs[0])
            mp = re.search(r"(?i)\bp\s*=\s*([^;]*)", rec)
            if mp and not mp.group(1).strip():
                entry["result"] = "fail"
                entry["reason"] = f"DKIM key revoked (empty p= in {key_name})"
                continue
        try:
            ok = obj.verify(idx=idx, dnsfunc=_dnsfunc)
            entry["result"] = "pass" if ok else "fail"
            if not ok:
                entry["reason"] = "signature did not verify (hash mismatch or wrong key)"
        except Exception as e:
            entry["result"] = "fail"
            entry["reason"] = _dkim_reason(e)
    passed = [s for s in out["signatures"] if s["result"] == "pass"]
    if passed:
        out["result"] = "pass"
        out["verifiedDomain"] = passed[0]["domain"]
        out["verifiedSelector"] = passed[0]["selector"]
        out["domain"] = passed[0]["domain"]
        out["selector"] = passed[0]["selector"]
        out["reason"] = ""
    else:
        out["result"] = "fail"
        reasons = [s.get("reason") for s in out["signatures"] if s.get("reason")]
        out["reason"] = "; ".join(reasons)[:250] or "no signature verified"
        out["domain"] = out["signatures"][0]["domain"]
        out["selector"] = out["signatures"][0]["selector"]
    return out


# --------------------------------------------------------------------------
# DMARC
# --------------------------------------------------------------------------
def _check_dmarc(from_domain: str, spf: dict, dkim: dict) -> dict:
    """-> {result, policy, record, alignment:{spf,dkim}, domain, policyDomain}"""
    out = {"result": "none", "policy": None, "record": "", "alignment": {"spf": None, "dkim": None},
           "domain": from_domain, "policyDomain": None, "reason": ""}
    if not from_domain:
        out["reason"] = "no From domain"
        return out
    if os.getenv("LIVE_DNS") == "0":
        out.update({"result": "not_run", "reason": "LIVE_DNS disabled"})
        return out

    def lookup(dom):
        recs = _txt_records(f"_dmarc.{dom}")
        return next((r for r in recs if "v=DMARC1" in r), None)

    rec = lookup(from_domain)
    policy_domain = from_domain
    if not rec:
        org = _org_domain(from_domain)
        if org and org != from_domain:
            rec = lookup(org)
            if rec:
                policy_domain = org
    if not rec:
        out["reason"] = "no DMARC policy published for this domain"
        return out

    def tag(name, default=None):
        m = re.search(r"(?i)\b%s\s*=\s*([\w\-]+)" % name, rec)
        return m.group(1).lower() if m else default

    policy = tag("p") or "none"
    spf_align = None
    dkim_align = None
    spf_domain = spf.get("domain") or ""
    if spf.get("result") == "pass" and spf_domain:
        spf_align = _org_domain(spf_domain) == _org_domain(from_domain)
    dkim_domain = dkim.get("verifiedDomain") or ""
    if dkim.get("result") == "pass" and dkim_domain:
        dkim_align = _org_domain(dkim_domain) == _org_domain(from_domain)

    aligned = bool(spf_align or dkim_align)
    out.update({
        "result": "pass" if aligned else "fail",
        "policy": policy,
        "subdomainPolicy": tag("sp"),
        "adkim": tag("adkim", "r"),
        "aspf": tag("aspf", "r"),
        "record": rec[:400],
        "policyDomain": policy_domain,
        "alignment": {"spf": spf_align, "dkim": dkim_align},
        "reason": "" if aligned else "neither SPF nor DKIM is aligned with the From domain",
    })
    return out


# --------------------------------------------------------------------------
# Upstream Authentication-Results (written by the receiving mail server)
# --------------------------------------------------------------------------
def _parse_upstream(ar: str) -> dict:
    out = {"spf": None, "dkim": None, "dmarc": None, "authserv": "", "raw": ar or ""}
    if not ar:
        return out
    m = re.match(r"\s*([A-Za-z0-9._\-]+)", ar)
    if m:
        out["authserv"] = m.group(1).lower()
    for k in ("spf", "dkim", "dmarc"):
        mm = re.search(r"(?i)\b%s\s*=\s*([a-z]+)" % k, ar)
        if mm:
            out[k] = mm.group(1).lower()
    return out


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------
def check_auth(raw: bytes, live: bool = True) -> dict:
    """-> {spf, dkim, dmarc, alignment, overall, authSeen, findings, ...}

    live=False -> only what the message itself carries (no DNS at all); used
    for the many messages of a large PST so DNS is queried a bounded number
    of times.
    """
    h = _parse_headers(raw)
    upstream = _parse_upstream(h["ar"])
    if not live:
        os.environ.setdefault("_AUTH_LIVE", "0")
    live = live and os.getenv("LIVE_DNS") != "0"

    if live:
        spf = _check_spf(h["client_ip"], h["env_addr"], h["helo"])
        dkim = _check_dkim(raw, h["dkim_sigs"])
        dmarc = _check_dmarc(h["from_domain"], spf, dkim)
    else:
        spf = {"result": "not_run", "domain": h["env_domain"], "record": "",
               "reason": "LIVE_DNS disabled", "clientIp": h["client_ip"], "helo": h["helo"],
               "sender": h["env_addr"]}
        dkim = {"result": "not_run", "signatures": [{"domain": s["domain"], "selector": s["selector"],
                                                     "algorithm": s.get("algorithm"), "result": "not_run"}
                                                    for s in h["dkim_sigs"]],
                "verifiedDomain": None, "verifiedSelector": None, "reason": "LIVE_DNS disabled",
                "domain": h["dkim_sigs"][0]["domain"] if h["dkim_sigs"] else None,
                "selector": h["dkim_sigs"][0]["selector"] if h["dkim_sigs"] else None}
        dmarc = {"result": "not_run", "policy": None, "record": "",
                 "alignment": {"spf": None, "dkim": None}, "domain": h["from_domain"],
                 "policyDomain": None, "reason": "LIVE_DNS disabled"}

    results = [spf.get("result"), dkim.get("result"), dmarc.get("result")]
    auth_seen = any(r not in (None, "none", "not_run") for r in results) or bool(upstream["raw"])

    passed = sum(1 for r in results if r == "pass")
    failed = sum(1 for r in results if r == "fail")
    if passed and not failed:
        overall = "pass"
    elif failed:
        overall = "fail"
    elif passed:
        overall = "partial"
    else:
        overall = "none"

    findings = []
    nid = [0]

    def add(sev, ftype, evidence, weight):
        nid[0] += 1
        findings.append({"id": f"A-{nid[0]:03d}", "sev": int(sev),
                         "severity": {0: "info", 1: "low", 2: "medium", 3: "high"}.get(int(sev)),
                         "type": ftype, "evidence": evidence[:300], "weight": weight})

    spf_r, dkim_r, dmarc_r = spf.get("result"), dkim.get("result"), dmarc.get("result")
    if spf_r == "fail":
        add(2, "spf_fail", f"SPF fail for {spf.get('domain') or h['env_domain']} (client {h['client_ip']})", 10)
    elif spf_r == "softfail":
        add(1, "spf_softfail", f"SPF soft-fail for {spf.get('domain') or h['env_domain']}", 5)
    elif spf_r == "neutral":
        add(1, "spf_neutral", f"SPF neutral for {spf.get('domain') or h['env_domain']}", 2)
    elif spf_r in ("permerror", "temperror"):
        add(1, "spf_permerror" if spf_r == "permerror" else "spf_temperror",
            f"SPF {spf_r} for {spf.get('domain') or h['env_domain']}", 2)
    elif spf_r == "none":
        add(1, "spf_none", f"no SPF record/result for {spf.get('domain') or h['env_domain']}", 3)

    if dkim_r == "fail":
        detail = dkim.get("reason") or "no signature verified"
        add(2, "dkim_fail", f"DKIM verification failed: {detail}", 10)
    elif dkim_r == "none" and h["dkim_sigs"] == []:
        add(1, "dkim_none", "message carries no DKIM-Signature header", 3)

    if dmarc_r == "fail":
        heavy = (dmarc.get("policy") or "") in ("reject", "quarantine")
        add(3 if heavy else 2, "dmarc_fail",
            f"DMARC fail: From={h['from_domain']}, policy p={dmarc.get('policy')}",
            20 if heavy else 5)
        al = dmarc.get("alignment") or {}
        if spf_r == "pass" and al.get("spf") is False:
            add(2, "spf_alignment_mismatch",
                f"SPF domain {spf.get('domain')} does not align with From={h['from_domain']}", 5)
        if dkim_r == "pass" and al.get("dkim") is False:
            add(2, "dkim_alignment_mismatch",
                f"DKIM domain(s) {dkim.get('verifiedDomain')} do not align with From={h['from_domain']}", 5)
    elif dmarc_r == "none":
        add(1, "dmarc_none", f"no DMARC policy published for {h['from_domain']}", 1)

    return {"spf": spf, "dkim": dkim, "dmarc": dmarc,
            "alignment": dmarc.get("alignment") or {"spf": None, "dkim": None},
            "overall": overall, "authSeen": auth_seen, "findings": findings,
            "clientIp": h["client_ip"], "fromDomain": h["from_domain"],
            "envDomain": h["env_domain"], "envAddr": h["env_addr"],
            "fromAddr": h["from_addr"], "replyTo": h["reply_to"],
            "headerFound": bool(h["ar"]), "authservId": h["authserv"],
            "raw": h["ar"][:1000], "upstream": upstream,
            "spfRecord": spf.get("record", ""), "dmarcRecord": dmarc.get("record", ""),
            "helo": h["helo"], "receivedCount": len(h["received"]),
            "dkimSignatures": dkim.get("signatures") or []}
