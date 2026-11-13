"""M6 — IOC extraction & export (CSV + STIX 2.1 bundle).

Unifies indicators from every module of a stored case result:
  ip (origin + hops), domain (From/Reply-To/Return-Path/Message-ID + URL hosts),
  url, email (From/Reply-To addresses), file (attachment hashes + names).
Pure offline; reputation enrichment plugs in later. Values can be defanged.
"""
import csv, io, uuid

DEFANG = {"ip": lambda v: v.replace(".", "[.]"),
          "domain": lambda v: v.replace(".", "[.]"),
          "email": lambda v: v.replace("@", "[at]"),
          "url": lambda v: re_defang_url(v),
          "file": lambda v: v}


def re_defang_url(u: str) -> str:
    return u.replace("http", "hxxp", 1).replace(".", "[.]", 1) if u.startswith("http") else u.replace(".", "[.]")


def _domain_of(addr: str):
    a = (addr or "").strip()
    if "@" in a: return a.split("@")[-1].lower().rstrip(".>")
    return None


def extract(result: dict) -> dict:
    """result = stored case result dict -> {iocs: [{type, value, source}], counts}"""
    iocs = {}  # (type, value) -> source

    def put(t, v, src):
        if not v or len(str(v)) < 3: return
        v = str(v)[:300]
        key = (t, v.lower())
        if key not in iocs: iocs[key] = {"type": t, "value": v, "source": src}

    for x in result.get("ipInfo") or []:
        put("ip", x.get("ip"), "origin")
    for h in (result.get("routing") or {}).get("hops") or []:
        if h.get("ip") and not h.get("private"): put("ip", h["ip"], "routing")
    for m in result.get("messages") or []:
        frm = m.get("from") or ""
        import re as _re
        for e in _re.findall(r"[\w.+-]+@[\w.-]+\.\w+", frm):
            put("email", e, "from")
            put("domain", e.split("@")[-1], "from")
    for u in result.get("urls") or []:
        put("url", u.get("url"), "body")
        if u.get("host"): put("domain", u["host"], "url-host")
    for a in result.get("attachments") or []:
        put("file", a.get("sha256"), "attachment-sha256")
        if a.get("name") and a["name"] != "(unnamed)":
            put("file", a["name"], "attachment-name")

    order = {"ip": 0, "domain": 1, "url": 2, "email": 3, "file": 4}
    items = sorted(iocs.values(), key=lambda x: (order.get(x["type"], 9), x["value"]))
    counts = {}
    for x in items: counts[x["type"]] = counts.get(x["type"], 0) + 1
    return {"iocs": items, "counts": counts}


def to_csv(iocs: list, case_row: dict, defang: bool = True) -> str:
    out = io.StringIO()
    w = csv.writer(out, quoting=csv.QUOTE_ALL)
    w.writerow(["case_id", "type", "value", "source"])
    for x in iocs:
        v = DEFANG.get(x["type"], DEFANG["file"])(x["value"]) if defang else x["value"]
        w.writerow([case_row.get("id", ""), x["type"], v, x["source"]])
    return out.getvalue()


def to_stix(iocs: list, case_row: dict) -> dict:
    """STIX 2.1 bundle (manual serializer, no extra dependency)."""
    objs = [{"type": "note", "spec_version": "2.1", "id": f"note--{uuid.uuid4()}",
             "created": "1970-01-01T00:00:00.000Z", "modified": "1970-01-01T00:00:00.000Z",
             "abstract": f"MailSleuth case {case_row.get('id', '')}",
             "content": f"Indicators from case {case_row.get('id', '')} ({case_row.get('file', '')})"}]
    for x in iocs:
        v = x["value"]
        if x["type"] == "ip":
            objs.append({"type": "ipv4-addr", "spec_version": "2.1", "id": f"ipv4-addr--{uuid.uuid4()}",
                         "created": "1970-01-01T00:00:00.000Z", "value": v,
                         "object_marking_refs": [], "labels": [f"source:{x['source']}"]})
        elif x["type"] == "domain":
            objs.append({"type": "domain-name", "spec_version": "2.1", "id": f"domain-name--{uuid.uuid4()}",
                         "created": "1970-01-01T00:00:00.000Z", "value": v, "labels": [f"source:{x['source']}"]})
        elif x["type"] == "url":
            objs.append({"type": "url", "spec_version": "2.1", "id": f"url--{uuid.uuid4()}",
                         "created": "1970-01-01T00:00:00.000Z", "value": v, "labels": [f"source:{x['source']}"]})
        elif x["type"] == "email":
            objs.append({"type": "email-addr", "spec_version": "2.1", "id": f"email-addr--{uuid.uuid4()}",
                         "created": "1970-01-01T00:00:00.000Z", "value": v, "labels": [f"source:{x['source']}"]})
        elif x["type"] == "file" and re_hex64(v):
            objs.append({"type": "file", "spec_version": "2.1", "id": f"file--{uuid.uuid4()}",
                         "created": "1970-01-01T00:00:00.000Z", "hashes": {"SHA-256": v},
                         "labels": [f"source:{x['source']}"]})
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objs}


def re_hex64(v: str) -> bool:
    import re as _re
    return bool(_re.fullmatch(r"[0-9a-f]{64}", v or ""))
