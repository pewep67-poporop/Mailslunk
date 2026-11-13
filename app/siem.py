"""M7 — SIEM correlation: Wazuh (syslog/CEF), Elastic (ECS _bulk), Splunk (HEC).

Builds normalized events from a case result and either PUSHES them (env-driven,
opt-in, keys never logged/echoed) or EXPORTS them as files:
  CEF      : one line per event, for Wazuh syslog ingestion
  RFC 5424 : syslog frame wrapping the CEF body
  ECS      : Elastic Common Schema ndjson (import with Filebeat or _bulk)
  HEC JSON : Splunk HTTP Event Collector payload

Env (all optional, off by default — offline-safe):
  WAZUH_HOST / WAZUH_PORT (default 5140) / WAZUH_PROTO (udp|tcp, default udp)
  SPLUNK_HEC_URL / SPLUNK_HEC_TOKEN
  ELASTIC_URL / ELASTIC_USER / ELASTIC_PASS / ELASTIC_API_KEY / ELASTIC_INDEX
"""
import os, json, socket, time
from datetime import datetime, timezone

CEF_FIELDS = ("fileName", "fileHash", "src", "msg", "cs1", "cs2")


def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _cef_escape(v, header=False):
    v = str(v or "")
    v = v.replace("\\", "\\\\").replace("=", "\\=").replace("\n", "\\n").replace("\r", "")
    if header: v = v.replace("|", "\\|")
    return v


# ---------- event generation ----------
def events_from_result(result: dict, user: str = "") -> list:
    """-> [{msgid, cef_id, cef_name, cef_sev(0-10), syslog_sev(0-7), fields{}}]"""
    custody = result.get("custody") or {}
    base = {"cs1": custody.get("caseId", ""), "cs2": result.get("verdict", ""),
            "fileHash": custody.get("sha256", ""),
            "msg": f"score={result.get('score')}/100 verdict={result.get('verdict')}"}
    sev_clean = {"clean": 3, "suspicious": 6, "malicious_or_phishing": 9}.get(result.get("verdict"), 6)
    events = [{"msgid": "case_analyzed", "cef_id": "MSL-CASE", "cef_name": "MailSleuth case analyzed",
               "cef_sev": sev_clean, "syslog_sev": 4 if sev_clean >= 6 else 6, "fields": dict(base)}]
    for a in result.get("attachments") or []:
        if a.get("verdict") == "malicious":
            f = dict(base, fileName=a.get("name", ""), fileHash=a.get("sha256", base["fileHash"]),
                     msg="; ".join(a.get("reasons") or [])[:200] or base["msg"])
            events.append({"msgid": "malware_detected", "cef_id": "MSL-MALWARE", "cef_name": "Malicious attachment detected",
                           "cef_sev": 9, "syslog_sev": 2, "fields": f})
    for u in result.get("urls") or []:
        if u.get("verdict") == "malicious":
            events.append({"msgid": "phishing_url_hit", "cef_id": "MSL-PHISH", "cef_name": "Phishing URL detected",
                           "cef_sev": 8, "syslog_sev": 3,
                           "fields": dict(base, msg=(u.get("url", "")[:150] + " — " + "; ".join(u.get("reasons") or []))[:200])})
    dm = (result.get("auth") or {}).get("dmarc") or {}
    if dm.get("result") == "fail" and (dm.get("policy") or "") in ("reject", "quarantine"):
        events.append({"msgid": "auth_failed", "cef_id": "MSL-AUTH", "cef_name": "Email authentication failed (DMARC)",
                       "cef_sev": 6, "syslog_sev": 4, "fields": dict(base, msg=f"DMARC fail p={dm.get('policy')}")})
    return events


# ---------- formatters ----------
def to_cef(events: list) -> str:
    lines = []
    for ev in events:
        ext = " ".join(f"{k}={_cef_escape(v)}" for k, v in ev["fields"].items()
                       if k in CEF_FIELDS and v not in ("", None))
        lines.append(f"CEF:0|MailSleuth|MailSleuth Python|2.0|{ev['cef_id']}|"
                     f"{_cef_escape(ev['cef_name'], header=True)}|{ev['cef_sev']}|{ext}")
    return "\n".join(lines) + ("\n" if lines else "")


def to_syslog(events: list, hostname: str = "") -> str:
    host = hostname or os.getenv("SIEM_HOSTNAME") or socket.gethostname()
    frames = []
    for ev in events:
        pri = 1 * 8 + ev["syslog_sev"]  # facility 1 (user), RFC 5424
        ts = _now_iso()
        sd = f'[mailsleuth@57487 case="{_sd_escape(ev["fields"].get("cs1", ""))}" verdict="{_sd_escape(ev["fields"].get("cs2", ""))}"]'
        msg = to_cef([ev]).strip()
        frames.append(f"<{pri}>1 {ts} {host} MailSleuth - {ev['msgid']} {sd} {msg}")
    return "\n".join(frames) + ("\n" if frames else "")


def _sd_escape(v):
    return str(v or "").replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def to_ecs(events: list, result: dict, user: str = "") -> str:
    lines = []
    custody = result.get("custody") or {}
    for ev in events:
        doc = {"@timestamp": _now_iso(),
               "event": {"kind": "alert", "module": "mailsleuth", "dataset": "mailsleuth.threats",
                         "action": f"mailsleuth.{ev['msgid']}", "severity": ev["cef_sev"],
                         "category": ["email", "threat" if ev["msgid"] != "case_analyzed" else "authentication"]},
               "message": ev["fields"].get("msg", ""),
               "user": {"name": user},
               "mailsleuth": {"case_id": custody.get("caseId", ""), "score": result.get("score"),
                              "verdict": result.get("verdict"), "sha256": custody.get("sha256", ""),
                              "original": custody.get("original", "")},
               "labels": {"event_type": ev["msgid"]}}
        f = ev["fields"]
        if f.get("fileName"): doc["file"] = {"name": f["fileName"], "hash": {"sha256": f.get("fileHash", "")}}
        if f.get("src"): doc["source"] = {"ip": f["src"]}
        lines.append(json.dumps(doc, ensure_ascii=False))
    return "\n".join(lines) + ("\n" if lines else "")


def to_bulk(events: list, result: dict, user: str = "", index: str = "mailsleuth-case") -> str:
    out = []
    for line in to_ecs(events, result, user).strip().splitlines():
        out.append(json.dumps({"index": {"_index": index}}))
        out.append(line)
    return "\n".join(out) + ("\n" if out else "")


def to_hec(events: list, result: dict, user: str = "") -> str:
    """Splunk HEC JSON (one event per line)."""
    custody = result.get("custody") or {}
    out = []
    for ev in events:
        out.append(json.dumps({"time": time.time(), "sourcetype": "mailsleuth",
                               "event": {"msgid": ev["msgid"], "severity": ev["cef_sev"],
                                         "case_id": custody.get("caseId", ""), "user": user,
                                         "score": result.get("score"), "verdict": result.get("verdict"),
                                         "sha256": custody.get("sha256", ""), "detail": ev["fields"]}},
                              ensure_ascii=False))
    return "\n".join(out) + ("\n" if out else "")


# ---------- pushers (opt-in via env) ----------
def _send_syslog(events: list):
    host = os.getenv("WAZUH_HOST"); port = int(os.getenv("WAZUH_PORT", "5140"))
    proto = os.getenv("WAZUH_PROTO", "udp").lower()
    payload = to_syslog(events).encode("utf-8")
    sent = 0
    if proto == "tcp":
        with socket.create_connection((host, port), timeout=3) as s:
            s.sendall(payload + b"\n"); sent += 1
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        s.sendto(payload, (host, port)); sent += 1
        s.close()
    return sent


def _post_splunk(events: list, result: dict, user: str):
    url = os.getenv("SPLUNK_HEC_URL"); token = os.getenv("SPLUNK_HEC_TOKEN", "")
    import requests
    r = requests.post(url, data=to_hec(events, result, user),
                      headers={"Authorization": f"Splunk {token}", "Content-Type": "application/json"},
                      timeout=8)
    r.raise_for_status(); return 1


def _post_elastic(events: list, result: dict, user: str):
    url = os.getenv("ELASTIC_URL").rstrip("/")
    index = os.getenv("ELASTIC_INDEX", "mailsleuth-case")
    headers = {"Content-Type": "application/x-ndjson"}
    if os.getenv("ELASTIC_API_KEY"):
        headers["Authorization"] = f"ApiKey {os.getenv('ELASTIC_API_KEY')}"
    elif os.getenv("ELASTIC_USER"):
        import requests
        req = requests.Request("POST", f"{url}/_bulk", data=to_bulk(events, result, user, index),
                               headers=headers)
        prep = req.prepare()
        import base64
        cred = base64.b64encode(f"{os.getenv('ELASTIC_USER')}:{os.getenv('ELASTIC_PASS','')}".encode()).decode()
        prep.headers["Authorization"] = f"Basic {cred}"
        import requests as rq
        s = rq.Session()
        r = s.send(prep, timeout=8); r.raise_for_status()
    else:
        import requests
        r = requests.post(f"{url}/_bulk", data=to_bulk(events, result, user, index),
                          headers=headers, timeout=8)
        r.raise_for_status()
    return 1


def emit_case(result: dict, user: str = "") -> dict:
    """Auto-push after analyze. Never raises; returns push summary for the audit log.
    Only targets with their env configured are attempted (offline-safe by default)."""
    events = events_from_result(result, user)
    out = {"events": len(events), "wazuh": 0, "splunk": 0, "elastic": 0, "errors": []}
    targets = []
    if os.getenv("WAZUH_HOST"):
        targets.append(("wazuh", lambda: _send_syslog(events)))
    if os.getenv("SPLUNK_HEC_URL"):
        targets.append(("splunk", lambda: _post_splunk(events, result, user)))
    if os.getenv("ELASTIC_URL"):
        targets.append(("elastic", lambda: _post_elastic(events, result, user)))
    for name, fn in targets:
        try:
            out[name] = fn() or 1
        except Exception as e:
            # only the error class, never tokens/keys
            out["errors"].append(f"{name}: {type(e).__name__}")
    return out
