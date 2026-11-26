"""Evidence-backed entity graph.

Every node and edge is derived from a field that actually exists in the case
result (headers, Received IPs, URLs, attachment hashes). Nothing is inferred
from names or guessed. The SVG is generated locally; no graph service is used.
"""
import html as _h
import re
from email.utils import parseaddr

MAX_NODES = 90
MAX_EDGES = 180


def _esc(x):
    return _h.escape(str(x or ""), quote=True)


def _addr(raw):
    name, addr = parseaddr(str(raw or ""))
    addr = (addr or "").strip().lower()
    if not addr and "@" in str(raw or ""):
        addr = str(raw).strip().lower()
    return name.strip(), addr


def _dom(addr):
    return addr.rsplit("@", 1)[-1].lower().rstrip(".") if "@" in (addr or "") else ""


class G:
    def __init__(self):
        self.nodes = {}
        self.edges = []
        self._edge_keys = set()

    def node(self, nid, label, kind, evidence="", **extra):
        if nid not in self.nodes:
            self.nodes[nid] = {"id": nid, "label": str(label or "")[:80],
                               "kind": kind, "evidence": str(evidence or "")[:240],
                               **extra}
        return nid

    def edge(self, src, dst, rel, evidence=""):
        if src not in self.nodes or dst not in self.nodes:
            return
        key = (src, dst, rel)
        if key in self._edge_keys:
            return
        self._edge_keys.add(key)
        if len(self.edges) < MAX_EDGES:
            self.edges.append({"src": src, "dst": dst, "rel": rel,
                               "evidence": str(evidence or "")[:240]})


def build(result: dict) -> dict:
    g = G()
    case = g.node("case", "Case", "case", "case record")
    msgs = result.get("messages") or []
    for i, m in enumerate(msgs[:16]):
        mid = f"msg:{i}"
        subj = str(m.get("subject") or "(no subject)")[:70]
        g.node(mid, f"#{i + 1} {subj}", "message",
               f"Message-ID {m.get('messageId') or '-'}", index=i)
        g.edge(case, mid, "CONTAINS", f"message #{i + 1} of the case")
        # From actor
        name, addr = _addr(m.get("from"))
        if addr:
            aid = g.node("actor:" + addr, name or addr, "actor",
                         f"From: {m.get('from')}", address=addr)
            g.edge(aid, mid, "SENT", f"From header: {m.get('from')}")
            dom = _dom(addr)
            if dom:
                did = g.node("domain:" + dom, dom, "domain", f"From domain {dom}")
                g.edge(aid, did, "USES_DOMAIN", f"address {addr}")
        # Recipients
        for field in ("to", "cc", "bcc"):
            vals = m.get(field) or []
            if isinstance(vals, str):
                vals = re.split(r"[,;]", vals)
            for raw in vals[:12]:
                nm, ad = _addr(raw)
                if not ad:
                    continue
                rid = g.node("actor:" + ad, nm or ad, "actor", f"{field}: {raw}",
                             address=ad)
                g.edge(mid, rid, field.upper(), f"{field} header: {raw}")
                dom = _dom(ad)
                if dom:
                    did = g.node("domain:" + dom, dom, "domain", f"recipient domain {dom}")
                    g.edge(rid, did, "USES_DOMAIN", f"address {ad}")
        # Origin IPs (kèm GeoLite2 local nếu có)
        geo_by_ip = {x.get("ip"): (x.get("geo") or {}) for x in (result.get("ipInfo") or [])}
        for ip in (m.get("originIPs") or [])[:8]:
            geo = geo_by_ip.get(ip) or {}
            iid = g.node("ip:" + ip, ip, "ip", f"Received header of message #{i + 1}",
                         geo={"country": geo.get("country"), "city": geo.get("city"),
                              "asn": geo.get("asn"), "location": geo.get("location")})
            g.edge(mid, iid, "ORIGIN_IP", f"Received: {ip}")
            country = geo.get("country")
            if country:
                lid = g.node("geo:" + str(country), str(country), "geo",
                             f"GeoLite2 local: {country}")
                g.edge("ip:" + ip, lid, "LOCATED_IN", f"GeoLite2: {ip} -> {country}")
    # URLs: attach to the message index that carried them, else case level.
    for u in (result.get("urls") or [])[:40]:
        url = str(u.get("url") or "")
        if not url:
            continue
        uid = g.node("url:" + url, u.get("host") or url, "url",
                     f"URL risk {u.get('risk')}% ({u.get('verdict')})", url=url)
        mi = u.get("m")
        src = f"msg:{mi}" if isinstance(mi, int) and f"msg:{mi}" in g.nodes else case
        g.edge(src, uid, "CONTAINS_URL", f"{url} - {', '.join(u.get('reasons') or [])[:160]}")
    # Attachments
    for a in (result.get("attachments") or [])[:20]:
        h = str(a.get("sha256") or "")
        if not h:
            continue
        aid = g.node("att:" + h, a.get("name") or h[:16], "attachment",
                     f"SHA-256 {h}", sha256=h)
        mi = a.get("m")
        src = f"msg:{mi}" if isinstance(mi, int) and f"msg:{mi}" in g.nodes else case
        g.edge(src, aid, "HAS_ATTACHMENT", f"{a.get('name')} ({a.get('size')} B)")
    # SMTP hops (từ field Received thật)
    for h in ((result.get("routing") or {}).get("hops") or [])[:20]:
        hid = f"hop:{h.get('idx')}"
        g.node(hid, f"hop #{h.get('idx')}", "hop",
               (h.get("raw") or f"{h.get('from')} by {h.get('by')}")[:240],
               ts=h.get("ts"), delayMs=h.get("delayMs"))
        if h.get("ip"):
            g.edge(hid, "ip:" + h["ip"], "HOP_IP", f"Received hop #{h.get('idx')}: {h['ip']}")
    if msgs:
        first_hop = "hop:1"
        if first_hop in g.nodes:
            g.edge("msg:0", first_hop, "RECEIVED_VIA", "topmost Received header of message #1")

    # Quan hệ message↔message (có evidence, từ app/relations.py)
    for rel in (result.get("relations") or {}).get("relations", []) or []:
        src, dst = f"msg:{rel.get('src_msg')}", f"msg:{rel.get('dst_msg')}"
        if src in g.nodes and dst in g.nodes:
            g.edge(src, dst, rel.get("kind") or "RELATED", rel.get("evidence") or "")

    # Drop edges pointing at nodes that were truncated away.
    g.edges = [e for e in g.edges if e["src"] in g.nodes and e["dst"] in g.nodes]
    return {"nodes": list(g.nodes.values())[:MAX_NODES],
            "edges": g.edges[:MAX_EDGES],
            "truncated": len(g.nodes) > MAX_NODES or len(g.edges) >= MAX_EDGES}


def _layout(nodes):
    """Deterministic rings by kind; no physics, so the same case renders the same."""
    rings = [("case", 0, 0), ("message", 1, 150), ("actor", 2, 270),
             ("domain", 3, 370), ("ip", 3, 370), ("hop", 3, 370),
             ("geo", 4, 455), ("url", 4, 455), ("attachment", 4, 455)]
    pos = {}
    for kind, ring, radius in rings:
        group = [n for n in nodes if n["kind"] == kind]
        for i, n in enumerate(group):
            if radius == 0:
                pos[n["id"]] = (600, 400)
                continue
            import math
            a = (2 * math.pi * i / max(1, len(group))) - math.pi / 2
            # split the outer ring between ip/url/attachment to avoid overlap
            pos[n["id"]] = (600 + radius * math.cos(a), 400 + radius * math.sin(a))
    return pos


_COLORS = {"case": "#1f2937", "message": "#2563eb", "actor": "#7c3aed",
           "domain": "#0891b2", "ip": "#dc2626", "hop": "#7c3aed",
           "geo": "#0e7490", "url": "#d97706", "attachment": "#059669"}


def to_svg(graph: dict, lang: str = "en") -> str:
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    pos = _layout(nodes)
    en = (lang or "en") != "vi"
    title = "Evidence entity graph" if en else "Sơ đồ liên kết đối tượng theo chứng cứ"
    note = ("Edges come only from headers, Received IPs, URLs and attachment hashes."
            if en else "Cạnh liên kết chỉ lấy từ header, IP Received, URL và hash tệp đính kèm.")
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 800" role="img" aria-label="{_esc(title)}">',
           '<rect width="1200" height="800" fill="#f8fafc"/>',
           f'<text x="24" y="34" font-family="Arial" font-size="20" font-weight="bold" fill="#111827">{_esc(title)}</text>',
           f'<text x="24" y="56" font-family="Arial" font-size="13" fill="#475569">{_esc(note)}</text>']
    for e in edges:
        if e["src"] not in pos or e["dst"] not in pos:
            continue
        x1, y1 = pos[e["src"]]; x2, y2 = pos[e["dst"]]
        out.append(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="#94a3b8" stroke-width="1.2" opacity="0.75"><title>{_esc(e["rel"] + ": " + e["evidence"])}</title></line>')
    for n in nodes:
        x, y = pos.get(n["id"], (600, 400))
        color = _COLORS.get(n["kind"], "#64748b")
        r = 34 if n["kind"] == "case" else 20 if n["kind"] == "message" else 16
        label = n["label"]
        if len(label) > 24:
            label = label[:23] + "…"
        out.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r}" fill="{color}" stroke="#fff" stroke-width="2"><title>{_esc(n["kind"] + ": " + n["label"] + " — " + n["evidence"])}</title></circle>')
        out.append(f'<text x="{x:.1f}" y="{y + 4:.1f}" text-anchor="middle" font-family="Arial" font-size="{10 if r > 18 else 9}" fill="#fff">{_esc(label[:14])}</text>')
        out.append(f'<text x="{x:.1f}" y="{y + r + 13:.1f}" text-anchor="middle" font-family="Arial" font-size="10" fill="#334155">{_esc(label)}</text>')
    # legend
    lx = 24
    for kind, label in [("case", "Case"), ("message", "Message"), ("actor", "Actor"),
                        ("domain", "Domain"), ("ip", "IP"), ("hop", "Hop"),
                        ("geo", "Geo"), ("url", "URL"), ("attachment", "Attachment")]:
        out.append(f'<circle cx="{lx + 6}" cy="760" r="6" fill="{_COLORS[kind]}"/>')
        out.append(f'<text x="{lx + 17}" y="764" font-family="Arial" font-size="12" fill="#334155">{_esc(label)}</text>')
        lx += 120
    out.append("</svg>")
    return "".join(out)


def to_png(graph: dict, lang: str = "en") -> bytes:
    """PNG cho PDF/report (HTML dùng SVG). Không cần thư viện ngoài."""
    try:
        from PIL import Image, ImageDraw
    except Exception:
        return b""
    import io as _io
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    pos = _layout(nodes)
    img = Image.new("RGB", (1200, 800), "#f8fafc")
    d = ImageDraw.Draw(img)
    for e in edges:
        if e["src"] in pos and e["dst"] in pos:
            x1, y1 = pos[e["src"]]
            x2, y2 = pos[e["dst"]]
            d.line([(x1, y1), (x2, y2)], fill="#94a3b8", width=1)
    for n in nodes:
        x, y = pos.get(n["id"], (600, 400))
        r = 30 if n["kind"] == "case" else 16
        color = _COLORS.get(n["kind"], "#64748b")
        d.ellipse([x - r, y - r, x + r, y + r], fill=color, outline="#ffffff", width=2)
        d.text((x - 20, y - 5), str(n.get("label") or "")[:18], fill="#ffffff")
    out = _io.BytesIO()
    img.save(out, "PNG", optimize=True)
    return out.getvalue()


def summary(result: dict) -> dict:
    g = build(result)
    counts = {}
    for n in g["nodes"]:
        counts[n["kind"]] = counts.get(n["kind"], 0) + 1
    return {"nodes": len(g["nodes"]), "edges": len(g["edges"]),
            "byKind": counts, "truncated": g["truncated"]}
