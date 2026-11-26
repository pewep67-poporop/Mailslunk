"""Global evidence graph across ALL analysed cases (offline, evidence-backed).

Mọi node/cạnh truy về case_id + msg_index + field gốc. Không suy luận danh tính.
Dùng cho tab "Relations" (sàn lọc/index + vẽ đường ai->ai, từ đâu->đâu).
"""
from __future__ import annotations

import re
from collections import defaultdict
from email.utils import parseaddr

MAX_NODES = 240
MAX_EDGES = 500

_KIND_ORDER = {
    "actor": 0, "message": 1, "domain": 2, "ip": 3, "geo": 4, "url": 5, "attachment": 6,
}


def _addr(value) -> str:
    a = parseaddr(str(value or ""))[1].strip().lower()
    if not a and "@" in str(value or ""):
        a = str(value).strip().lower()
    return a.rstrip(">." )


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower().rstrip(".") if "@" in (addr or "") else ""


def load_index(rows: list) -> dict:
    """rows = danh sách dict từ bảng cases (có id, result JSON parse sẵn)."""
    actors = defaultdict(lambda: {"messages": [], "sent": 0, "received": 0})
    domains = defaultdict(list)
    ips = defaultdict(list)
    urls = defaultdict(list)
    hashes = defaultdict(list)
    messages = []

    for row in rows:
        cid = row.get("id")
        result = row.get("result") or {}
        for i, m in enumerate(result.get("messages") or []):
            mid = f"{cid}:{i}"
            sender = _addr(m.get("from"))
            recips = []
            for f in ("to", "cc", "bcc"):
                val = m.get(f) or []
                if isinstance(val, str):
                    val = re.split(r"[,;]", val)
                for raw in val[:10]:
                    a = _addr(raw)
                    if a:
                        recips.append(a)
            date = str(m.get("date") or "")
            messages.append({
                "id": mid, "case_id": cid, "msg_index": i,
                "subject": str(m.get("subject") or "")[:120],
                "from": sender, "to": recips[:10], "date": date,
                "verdict": result.get("verdict") or "",
                "score": result.get("score"),
                "origin_ips": list(m.get("originIPs") or [])[:8],
            })
            if sender:
                actors[sender]["messages"].append(mid)
                actors[sender]["sent"] += 1
                d = _domain(sender)
                if d:
                    domains[d].append(mid)
            for a in recips:
                actors[a]["messages"].append(mid)
                actors[a]["received"] += 1
                d = _domain(a)
                if d:
                    domains[d].append(mid)
            for ip in (m.get("originIPs") or [])[:8]:
                ips[str(ip)].append(mid)
        for u in (result.get("urls") or [])[:40]:
            host = str(u.get("host") or "")
            if host:
                urls[host].append(cid)
        for a in (result.get("attachments") or [])[:40]:
            h = str(a.get("sha256") or "")
            if h:
                hashes[h].append(cid)
    return {"actors": actors, "domains": domains, "ips": ips,
            "urls": urls, "hashes": hashes, "messages": messages}


def _node(nodes, nid, label, kind, evidence=""):
    if nid not in nodes:
        nodes[nid] = {"id": nid, "label": str(label)[:80], "kind": kind,
                      "evidence": str(evidence)[:240]}
    return nid


def neighborhood(idx: dict, focus: str, limit: int = MAX_NODES) -> dict:
    """focus = 'actor:...' / 'ip:...' / 'case:...' / 'url:...' / 'hash:...'"""
    nodes, edges = {}, []
    seen = set()

    def edge(src, dst, rel, evidence):
        key = (src, dst, rel)
        if key in seen or len(edges) >= MAX_EDGES:
            return
        seen.add(key)
        edges.append({"src": src, "dst": dst, "rel": rel, "evidence": evidence[:300]})

    msgs = idx["messages"]
    by_id = {m["id"]: m for m in msgs}
    seeds = []
    if focus.startswith("actor:"):
        addr = focus.split(":", 1)[1]
        seeds = [m for m in msgs if m["from"] == addr or addr in m["to"]][:limit]
    elif focus.startswith("ip:"):
        ip = focus.split(":", 1)[1]
        seeds = [m for m in msgs if ip in m["origin_ips"]][:limit]
    elif focus.startswith("domain:"):
        dom = focus.split(":", 1)[1]
        seeds = [m for m in msgs
                 if _domain(m["from"]) == dom or any(_domain(a) == dom for a in m["to"])][:limit]
    elif focus.startswith("url:"):
        host = focus.split(":", 1)[1]
        seeds = [m for m in msgs if m["case_id"] in idx["urls"].get(host, [])][:limit]
    elif focus.startswith("hash:"):
        h = focus.split(":", 1)[1]
        seeds = [m for m in msgs if m["case_id"] in idx["hashes"].get(h, [])][:limit]
    elif focus.startswith("case:"):
        cid = focus.split(":", 1)[1]
        seeds = [m for m in msgs if m["case_id"] == cid][:limit]
    else:
        seeds = msgs[:limit]

    for m in seeds:
        mid = "msg:" + m["id"]
        _node(nodes, mid, m["subject"] or m["id"], "message",
              f"case {m['case_id']} msg#{m['msg_index'] + 1} | {m['verdict']} {m['score']}")
        if m["from"]:
            aid = _node(nodes, "actor:" + m["from"], m["from"], "actor", "From header")
            edge(aid, mid, "SENT", f"{m['id']} From: {m['from']}")
        for a in m["to"]:
            rid = _node(nodes, "actor:" + a, a, "actor", "To/Cc/Bcc header")
            edge(mid, rid, "TO", f"{m['id']} recipient: {a}")
        for ip in m["origin_ips"]:
            iid = _node(nodes, "ip:" + ip, ip, "ip", "Received header")
            edge(mid, iid, "ORIGIN_IP", f"{m['id']} Received: {ip}")
        if len(nodes) >= limit:
            break

    # Chỉ giữ cạnh giữa các node tồn tại
    edges = [e for e in edges if e["src"] in nodes and e["dst"] in nodes]
    return {"nodes": list(nodes.values())[:limit], "edges": edges, "focus": focus,
            "returned": len(nodes), "truncated": len(nodes) >= limit}


def overview(idx: dict, limit: int = 120) -> dict:
    nodes, edges = {}, []
    for addr, info in list(sorted(idx["actors"].items(),
                                  key=lambda x: -len(x[1]["messages"])))[:limit // 2]:
        nid = _node(nodes, "actor:" + addr, addr, "actor",
                    f"{info['sent']} sent / {info['received']} received")
        for d in sorted({_domain(addr)} - {""}):
            did = _node(nodes, "domain:" + d, d, "domain", "email domain")
            edges.append({"src": nid, "dst": did, "rel": "USES_DOMAIN",
                          "evidence": f"{addr} domain {d}"})
    for ip, mids in list(sorted(idx["ips"].items(), key=lambda x: -len(x[1])))[:limit // 3]:
        nid = _node(nodes, "ip:" + ip, ip, "ip", f"{len(mids)} messages")
    return {"nodes": list(nodes.values())[:limit],
            "edges": [e for e in edges if e["src"] in nodes and e["dst"] in nodes][:MAX_EDGES],
            "focus": "overview", "returned": len(nodes), "truncated": True}


def to_csv(edges: list) -> str:
    import csv
    import io
    out = io.StringIO()
    w = csv.writer(out, quoting=csv.QUOTE_ALL)
    w.writerow(["src", "dst", "rel", "evidence"])
    for e in edges:
        w.writerow([e.get("src"), e.get("dst"), e.get("rel"), e.get("evidence")])
    return out.getvalue()
