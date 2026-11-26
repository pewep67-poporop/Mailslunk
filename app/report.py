"""Reports: signed HTML, PDF and CSV (English / Vietnamese).

Every report carries a deterministic SHA-256 signature of the case facts and
a visual seal in the bottom-right corner. The signature is not a secret-key
signature; it is an integrity fingerprint that can be recomputed by anyone who
has the case JSON (the verifier endpoint returns the canonical payload hash).
"""
import csv
import hashlib
import html as _h
import io
import json
import os
import re
import unicodedata
from datetime import datetime, timezone

from . import graph as _graph

try:
    from fpdf import FPDF
except Exception:  # pragma: no cover - fpdf2 is in requirements
    FPDF = None


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def esc(x):
    return _h.escape(str(x if x is not None else ""), quote=True)


def _safe_csv(v):
    s = str(v if v is not None else "")
    if s[:1] in ("=", "+", "-", "@", "\t", "\r"):
        s = "'" + s
    return s


def _conf(x):
    c = x.get("confidence")
    return f"{round(float(c))}%" if c is not None else "-"


def _utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _fmt_ts(v):
    s = str(v or "")
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return s or "-"


def case_signature(row: dict, result: dict) -> str:
    """Deterministic SHA-256 over the case facts (recomputable offline)."""
    findings = []
    for f in (result.get("findings") or []):
        findings.append({"id": f.get("id"), "type": f.get("type"),
                         "sev": f.get("sev"), "evidence": f.get("evidence")})
    payload = {
        "caseId": row.get("id") or (result.get("custody") or {}).get("caseId"),
        "ts": row.get("ts"), "user": row.get("user"), "file": row.get("file"),
        "sha256": row.get("sha256") or (result.get("custody") or {}).get("sha256"),
        "session_fp": result.get("session_fingerprint") or "",
        "signed_at": result.get("signed_at") or "",
        "format": result.get("format"), "count": result.get("count"),
        "score": result.get("score"), "verdict": result.get("verdict"),
        "findings": findings,
        "iocs": (result.get("ioc") or {}).get("iocs") or [],
    }
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def seal_svg(sig: str, when: str = "", lang: str = "en") -> str:
    """Small tamper-evident stamp for the HTML report (bottom-right)."""
    sig = (sig or "")[:64]
    when = when or _utc_now()
    label = "SIGNED" if (lang or "en") != "vi" else "ĐÃ KÝ"
    sub = "SHA-256 integrity" if (lang or "en") != "vi" else "Toàn vẹn SHA-256"
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="190" height="190" viewBox="0 0 190 190" role="img" aria-label="digital seal">
<circle cx="95" cy="95" r="88" fill="#fffdf5" stroke="#8b1e2d" stroke-width="3"/>
<circle cx="95" cy="95" r="78" fill="none" stroke="#8b1e2d" stroke-width="1.5" stroke-dasharray="4 3"/>
<text x="95" y="52" text-anchor="middle" font-family="Arial" font-size="13" font-weight="bold" fill="#8b1e2d">MAILSLEUTH</text>
<text x="95" y="68" text-anchor="middle" font-family="Arial" font-size="10" fill="#8b1e2d">{esc(sub)}</text>
<text x="95" y="92" text-anchor="middle" font-family="Arial" font-size="18" font-weight="bold" fill="#8b1e2d">{esc(label)}</text>
<text x="95" y="110" text-anchor="middle" font-family="monospace" font-size="8.5" fill="#333">{esc(sig[:24])}</text>
<text x="95" y="122" text-anchor="middle" font-family="monospace" font-size="8.5" fill="#333">{esc(sig[24:48])}</text>
<text x="95" y="140" text-anchor="middle" font-family="Arial" font-size="8" fill="#555">{esc(when[:24])}</text>
<text x="95" y="153" text-anchor="middle" font-family="Arial" font-size="7" fill="#777">SHA-256</text>
</svg>"""


# ---------------------------------------------------------------------------
# statistics / grouping
# ---------------------------------------------------------------------------
_CATEGORIES = [
    ("header", ("H-", "header"), "Header", "Header"),
    ("routing", ("R-", "routing"), "Routing", "Đường truyền"),
    ("auth", ("A-", "auth", "spf", "dkim", "dmarc"), "Authentication", "Xác thực"),
    ("url", ("U-", "url"), "URL", "URL"),
    ("attachment", ("T-", "attach", "file"), "Attachment", "Tệp đính kèm"),
    ("ml", ("ML-",), "ML classifier", "Bộ phân loại ML"),
]


def _category(f):
    fid = str(f.get("id") or "")
    ftype = str(f.get("type") or "").lower()
    for key, prefixes, _en, _vi in _CATEGORIES:
        for p in prefixes:
            if fid.startswith(p) or (p in ftype):
                return key
    return "other"


def stats_rows(result: dict, lang: str = "en") -> list:
    """-> [{key, label, value, detail}] used by HTML, PDF and CSV."""
    en = (lang or "en") != "vi"
    findings = result.get("findings") or []
    urls = result.get("urls") or []
    atts = result.get("attachments") or []
    ips = result.get("ipInfo") or []
    dns = result.get("dns") or {}
    counts = {}
    for f in findings:
        k = _category(f)
        counts[k] = counts.get(k, 0) + 1
    loc = sum(1 for x in ips if ((x.get("geo") or {}).get("location") or {}).get("latitude") is not None)
    url_bad = sum(1 for u in urls if u.get("verdict") == "malicious")
    url_warn = sum(1 for u in urls if u.get("verdict") == "suspicious")
    att_bad = sum(1 for a in atts if a.get("verdict") == "malicious")
    att_warn = sum(1 for a in atts if a.get("verdict") == "suspicious")
    auth = result.get("auth") or {}
    rows = [
        {"key": "score", "label": "Safety score" if en else "Điểm an toàn",
         "value": f"{result.get('score', '-')}/100", "detail": result.get("verdict", "")},
        {"key": "messages", "label": "Messages" if en else "Số thư",
         "value": result.get("count", 0), "detail": result.get("format", "")},
        {"key": "findings", "label": "Findings" if en else "Phát hiện",
         "value": len(findings), "detail": ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))},
        {"key": "header", "label": "Header findings" if en else "Phát hiện header",
         "value": counts.get("header", 0), "detail": ""},
        {"key": "routing", "label": "Routing anomalies" if en else "Bất thường đường truyền",
         "value": counts.get("routing", 0), "detail": f"{len((result.get('routing') or {}).get('hops') or [])} hops"},
        {"key": "auth", "label": "Authentication" if en else "Xác thực",
         "value": f"SPF {((auth.get('spf') or {}).get('result') or '-')} / DKIM {((auth.get('dkim') or {}).get('result') or '-')} / DMARC {((auth.get('dmarc') or {}).get('result') or '-')}",
         "detail": f"{counts.get('auth', 0)} findings"},
        {"key": "urls", "label": "URLs" if en else "URL",
         "value": len(urls), "detail": f"malicious {url_bad}, suspicious {url_warn}"},
        {"key": "attachments", "label": "Attachments" if en else "Tệp đính kèm",
         "value": len(atts), "detail": f"malicious {att_bad}, suspicious {att_warn}"},
        {"key": "ips", "label": "Origin IPs" if en else "IP nguồn",
         "value": len(ips), "detail": f"{loc} with coordinates"},
        {"key": "dns", "label": "DNS domains" if en else "Tên miền DNS",
         "value": len(dns), "detail": ""},
        {"key": "ioc", "label": "IOC" if en else "IOC",
         "value": sum((result.get("ioc") or {}).get("counts", {}).values()),
         "detail": json.dumps((result.get("ioc") or {}).get("counts", {}), ensure_ascii=False)},
    ]
    return rows


def url_groups(result: dict, lang: str = "en") -> list:
    """Group URLs by the message/target that carried them."""
    msgs = result.get("messages") or []
    groups = {}
    for u in (result.get("urls") or []):
        m = u.get("m")
        key = f"m{m}" if isinstance(m, int) else "file"
        if key not in groups:
            msg = msgs[m] if isinstance(m, int) and 0 <= m < len(msgs) else {}
            groups[key] = {
                "key": key, "index": m if isinstance(m, int) else None,
                "subject": msg.get("subject") or u.get("target") or "(file level)",
                "from": msg.get("from") or "", "urls": [],
            }
        groups[key]["urls"].append(u)
    return list(groups.values())


def _flatten_dns(result: dict):
    rows = []
    for dom, d in (result.get("dns") or {}).items():
        auth = (d or {}).get("auth") or {}
        recs = (d or {}).get("records") or {}
        spf = auth.get("spf") or {}
        dmarc = auth.get("dmarc") or {}
        dkim = auth.get("dkim") or {}
        rows.append({
            "domain": dom,
            "spf": spf.get("result") or ("found" if spf.get("found") else "-"),
            "dkim": dkim.get("result") or ("found" if dkim.get("found") else "-"),
            "dmarc": dmarc.get("result") or ("found" if dmarc.get("found") else "-"),
            "mx": ", ".join(str(x) for x in (recs.get("mx") or [])[:5]),
            "ns": ", ".join(str(x) for x in (recs.get("ns") or [])[:5]),
        })
    return rows



def _forensic_blocks(result: dict, lang: str, L: dict) -> dict:
    """Các mục bổ sung cho báo cáo forensic (không suy đoán khi thiếu dữ liệu)."""
    rt = result.get("routing") or {}
    timeline = []
    for h in (rt.get("hops") or [])[:40]:
        if h.get("ts"):
            timeline.append([h["ts"], f"Received hop #{h.get('idx')}",
                             f"{h.get('from') or '-'} by {h.get('by') or '-'}",
                             f"{h.get('delayMs')} ms" if h.get("delayMs") is not None else "-",
                             L["observed"]])
    if not timeline:
        timeline = [["-", "-", "No timestamp in Received headers", "-", L["unverified"]]]

    findings = result.get("findings") or []
    rels = (result.get("relations") or {}).get("relations") or []
    auth = result.get("auth") or {}
    not_run = [k.upper() for k in ("spf", "dkim", "dmarc")
               if str((auth.get(k) or {}).get("result") or "").lower() in ("not_run", "none", "")]
    assessments = [
        [L["observed"], f"{len(findings)} finding(s) trích trực tiếp từ header/body/file",
         "; ".join(f.get("id", "") for f in findings[:8]) or "-"],
        [L["inference"], f"{len([r for r in rels if r.get('confidence') == 'inference'])} quan hệ suy luận theo thời gian",
         "; ".join(f"#{r.get('src_msg', 0)+1}->#{r.get('dst_msg', 0)+1}" for r in rels if r.get("confidence") == "inference")[:180] or "-"],
        [L["unverified"], "Xác thực/kết quả thiếu dữ liệu: " + (", ".join(not_run) or "không"),
         "Authentication-Results / snapshot DNS"],
    ]
    for a in (result.get("assessments") or [])[:50]:
        assessments.append([a.get("kind") or "-", a.get("claim") or "-",
                            (a.get("evidence_refs") or a.get("limitation") or "-")])

    responses = [[x[0], x[1]] for x in [
        ("Isolate email", "Cách ly email và đánh dấu tương tự"),
        ("Check similar", "Kiểm tra email tương tự trong hệ thống"),
        ("Independent verify", "Xác minh yêu cầu thanh toán qua kênh độc lập"),
        ("Strengthen auth", "Tăng cường SPF/DKIM/DMARC và alignment"),
        ("Keep logs", "Lưu log/phục vụ điều tra tiếp"),
        ("User guidance", "Hướng dẫn người dùng nhận diện giả mạo"),
    ]]
    for a in (result.get("responses") or [])[:30]:
        responses.append([a.get("action") or "-", a.get("rationale") or "-"])

    exports = (result.get("exports") or [])
    if not exports:
        exports = ["report.pdf", "report.html", "ioc.csv", "relations.csv",
                   "auth_summary.csv", "dns_snapshot.json", "timeline.csv",
                   "manifest.sha256"]
    annex = [[name, "-", "-"] for name in exports]
    return {"timeline": timeline, "assessments": assessments,
            "responses": responses, "annex": annex}

# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------
_L = {
    "en": {
        "title": "MailSleuth Forensic Report", "case": "Case", "analyst": "Analyst",
        "generated": "Generated", "custody": "Evidence and chain of custody",
        "original": "Original file", "sha": "SHA-256", "size": "Size",
        "format": "Format", "platform": "Platform", "evidence": "Evidence copy",
        "summary": "Executive summary", "score": "Safety score", "verdict": "Verdict",
        "count": "Messages", "stats": "Findings by category", "category": "Category",
        "value": "Value", "detail": "Detail", "auth": "SPF / DKIM / DMARC",
        "header": "Header analysis", "routing": "SMTP routing", "findings": "Findings",
        "ips": "Origin IP intelligence", "map": "Local schematic map",
        "urls": "URLs by target", "attachments": "Attachments", "ioc": "IOC",
        "graph": "Evidence entity graph", "signature": "Report signature",
        "sig_note": "SHA-256 over the canonical case facts. Recompute it with GET /api/report/{id}/verify.",
        "none": "None", "from": "From", "subject": "Subject", "risk": "Risk",
        "reasons": "Reasons", "target": "Target", "file": "File", "hash": "Hash",
        "type": "Type", "sev": "Severity", "evidence_col": "Evidence",
        "domain": "Domain", "spf": "SPF", "dkim": "DKIM", "dmarc": "DMARC",
        "mx": "MX", "ns": "NS", "coords": "Coordinates", "country": "Country",
        "city": "City", "asn": "ASN / Org", "ptr": "PTR", "confidence": "Confidence",
        "no_map": "No coordinates available.", "limits": "Limits",
        "toc": "Contents", "method": "Method", "timeline": "Event timeline",
        "classification": "Assessment classification", "response": "Response & prevention",
        "annex": "Annex - exported evidence files", "observed": "Observed",
        "inference": "Inference", "unverified": "Unverified", "session_hash": "Session hash",
        "limits_text": "Forensic offline: no external map, no cloud AI, no reputation/API call, no live DNS. GeoLite2 location is approximate. Header/URL rules are deterministic evidence-backed rules, not a malware verdict.",
    },
    "vi": {
        "title": "Báo cáo pháp chứng MailSleuth", "case": "Vụ việc", "analyst": "Chuyên viên",
        "generated": "Tạo lúc", "custody": "Chứng cứ và chuỗi bảo quản",
        "original": "Tệp gốc", "sha": "SHA-256", "size": "Kích thước",
        "format": "Định dạng", "platform": "Nền tảng", "evidence": "Bản chứng cứ",
        "summary": "Tóm tắt điều tra", "score": "Điểm an toàn", "verdict": "Kết luận",
        "count": "Số thư", "stats": "Thống kê phát hiện theo nhóm", "category": "Nhóm",
        "value": "Giá trị", "detail": "Chi tiết", "auth": "SPF / DKIM / DMARC",
        "header": "Phân tích header", "routing": "Đường truyền SMTP", "findings": "Phát hiện",
        "ips": "Thông tin IP nguồn", "map": "Bản đồ lược đồ nội bộ",
        "urls": "URL theo từng đối tượng", "attachments": "Tệp đính kèm", "ioc": "IOC",
        "graph": "Sơ đồ liên kết đối tượng theo chứng cứ", "signature": "Chữ ký báo cáo",
        "sig_note": "SHA-256 trên dữ liệu vụ việc chuẩn tắc. Có thể tính lại bằng GET /api/report/{id}/verify.",
        "none": "Không có", "from": "Từ", "subject": "Tiêu đề", "risk": "Rủi ro",
        "reasons": "Lý do", "target": "Đối tượng", "file": "Tệp", "hash": "Hash",
        "type": "Loại", "sev": "Mức độ", "evidence_col": "Chứng cứ",
        "domain": "Tên miền", "spf": "SPF", "dkim": "DKIM", "dmarc": "DMARC",
        "mx": "MX", "ns": "NS", "coords": "Tọa độ", "country": "Quốc gia",
        "city": "Thành phố", "asn": "ASN / Tổ chức", "ptr": "PTR", "confidence": "Độ tin cậy",
        "no_map": "Không có tọa độ.", "limits": "Giới hạn",
        "toc": "Mục lục", "method": "Phương pháp", "timeline": "Timeline sự kiện",
        "classification": "Phân loại nhận định", "response": "Ứng phó & phòng ngừa",
        "annex": "Phụ lục - file chứng cứ xuất khẩu", "observed": "Quan sát",
        "inference": "Suy luận", "unverified": "Chưa đủ cơ sở", "session_hash": "Hash phiên",
        "limits_text": "Pháp chứng offline: không map ngoài, không AI đám mây, không reputation/API, không DNS live. Vị trí GeoLite2 là gần đúng. Quy tắc header/URL là rule xác định dựa trên chứng cứ, không phải kết luận malware.",
    },
}


def _T(lang):
    return _L["vi" if (lang or "en") == "vi" else "en"]


def _table(headers, rows, cls=""):
    h = "".join(f"<th>{esc(x)}</th>" for x in headers)
    body = ""
    for row in rows:
        body += "<tr>" + "".join(f"<td>{esc(x)}</td>" for x in row) + "</tr>"
    if not rows:
        body = f'<tr><td colspan="{len(headers)}">-</td></tr>'
    return f'<table class="{cls}"><thead><tr>{h}</tr></thead><tbody>{body}</tbody></table>'


def render_report(row: dict, result: dict, lang: str = "en", integrity: bool = True,
                  map_base64: str = "", sig: str = "") -> str:
    L = _T(lang)
    sig = sig or case_signature(row, result)
    when = _utc_now()
    custody = result.get("custody") or {}
    stats = stats_rows(result, lang)
    auth = result.get("auth") or {}
    hdr = result.get("headerAnalysis") or {}
    rt = result.get("routing") or {}
    urls = result.get("urls") or []
    atts = result.get("attachments") or []
    ips = result.get("ipInfo") or []
    findings = result.get("findings") or []
    ioc = (result.get("ioc") or {}).get("iocs") or []
    # sections
    stat_html = _table([L["category"], L["value"], L["detail"]],
                       [[r["label"], r["value"], r["detail"]] for r in stats], "stats")
    auth_rows = []
    for name in ("spf", "dkim", "dmarc"):
        a = auth.get(name) or {}
        auth_rows.append([name.upper(), a.get("result") or "-",
                          ", ".join(str(x) for x in (a.get("reasons") or a.get("reason") or []) if x)[:180]])
    auth_html = _table(["Mechanism", "Result", "Detail"], auth_rows)
    hdr_rows = [[f.get("id"), f.get("type"), f.get("severity"), f.get("evidence")]
                for f in (hdr.get("checks") or [])[:100]]
    hdr_html = _table(["ID", L["type"], L["sev"], L["evidence_col"]], hdr_rows)
    hop_rows = [[h.get("idx"), h.get("from"), h.get("by"), h.get("with"),
                 h.get("gateway"), h.get("delayMs")] for h in (rt.get("hops") or [])[:60]]
    rt_html = _table(["#", "From", "By", "With", "Gateway", "Delay (ms)"], hop_rows)
    ip_rows = []
    for i, x in enumerate(ips, 1):
        g = x.get("geo") or {}
        loc = g.get("location") or {}
        coords = f"{loc.get('latitude')}, {loc.get('longitude')}" if loc.get("latitude") is not None else "-"
        ip_rows.append([f"{i}. {x.get('ip')}", coords,
                        f"{g.get('country') or ''} / {g.get('city') or ''}".strip(" /") or "-",
                        f"AS{g.get('asn') or ''} {g.get('organization') or ''}".strip() or "-",
                        ", ".join(x.get("ptr") or []) or "-", _conf(x)])
    ip_html = _table(["IP", L["coords"], f"{L['country']} / {L['city']}",
                      L["asn"], L["ptr"], L["confidence"]], ip_rows)
    url_html = ""
    for g in url_groups(result, lang):
        rows = [[u.get("url"), u.get("host"), f"{u.get('risk')}%", u.get("verdict"),
                 "; ".join(u.get("reasons") or [])] for u in g["urls"][:80]]
        url_html += (f'<h4>{esc(L["target"])}: #{g["index"] + 1 if g["index"] is not None else "-"} '
                     f'{esc(g["subject"])} <span class="muted">({esc(g["from"])})</span></h4>'
                     + _table(["URL", "Host", L["risk"], L["verdict"], L["reasons"]], rows))
    att_rows = []
    for a in atts[:150]:
        eng = ", ".join(a.get("scanEngines") or [])
        reasons = "; ".join(a.get("reasons") or [])
        if eng:
            reasons = (f"[scan: {eng}] " + reasons).strip()
        att_rows.append([a.get("name"), f"{a.get('size')} B", a.get("magic"), a.get("sha256"),
                         a.get("verdict"), reasons])
    att_html = _table([L["file"], L["size"], L["type"], L["hash"], L["verdict"], L["reasons"]], att_rows)
    find_rows = [[f.get("id"), f.get("type"), f.get("severity"), f.get("evidence")]
                 for f in findings[:500]]
    find_html = _table(["ID", L["type"], L["sev"], L["evidence_col"]], find_rows)
    ioc_rows = [[x.get("type"), x.get("value"), x.get("confidence"), x.get("source")]
                for x in ioc[:300]]
    ioc_html = _table([L["type"], L["value"], L["confidence"], "Source"], ioc_rows)
    dns_html = _table([L["domain"], "SPF", "DKIM", "DMARC", "MX", "NS"],
                      [[d["domain"], d["spf"], d["dkim"], d["dmarc"], d["mx"], d["ns"]]
                       for d in _flatten_dns(result)])
    graph_svg = ""
    try:
        graph_svg = _graph.to_svg(_graph.build(result), lang)
    except Exception:
        graph_svg = ""
    fb = _forensic_blocks(result, lang, L)
    timeline_html = _table(["Timestamp", "Source", "Event", "Delay", "Confidence"], fb["timeline"])
    class_html = _table([L["classification"], "Detail", "Evidence"], fb["assessments"])
    resp_html = _table(["Action", "Rationale"], fb["responses"])
    annex_html = _table(["File", "SHA-256", "Size"], fb["annex"])
    toc_html = ("<h2>0. " + esc(L["toc"]) + "</h2><ol><li>" +
                "</li><li>".join(esc(x) for x in [
                    L["custody"], L["summary"], L["auth"], L["header"], L["routing"],
                    L["findings"], L["ips"], L["map"], L["urls"], L["attachments"],
                    "DNS", L["ioc"], L["graph"], L["method"], L["timeline"],
                    L["classification"], L["response"], L["annex"], L["signature"], L["limits"],
                ]) + "</li></ol>")
    map_html = (f'<img class="map" src="data:image/png;base64,{map_base64}" alt="{esc(L["map"])}">'
                if map_base64 else f'<p class="muted">{esc(L["no_map"])}</p>')
    meta = [
        [L["case"], row.get("id") or custody.get("caseId")],
        [L["analyst"], row.get("user")],
        [L["generated"], when],
        [L["original"], row.get("file") or custody.get("original")],
        [L["sha"], row.get("sha256") or custody.get("sha256")],
        [L["format"], result.get("format")],
        [L["platform"], result.get("platform") or custody.get("platform") or "auto"],
        [L["size"], f"{custody.get('size', '-')} B"],
        [L["evidence"], custody.get("evidencePath") or "-"],
        [L["score"], f"{result.get('score')}/100"],
        [L["verdict"], result.get("verdict")],
        [L["count"], result.get("count")],
        [L["session_hash"], result.get("session_fingerprint") or "-"],
        ["signed_at", result.get("signed_at") or "-"],
    ]
    meta_html = _table(["Field", "Value"], meta, "meta")
    seal = seal_svg(sig, when, lang)
    return f"""<!doctype html>
<html lang="{esc(lang)}"><head><meta charset="utf-8"><title>{esc(L['title'])} - {esc(row.get('id'))}</title>
<style>
:root{{--ink:#17202a;--muted:#5b6b7a;--line:#c9d4dd;--accent:#8b1e2d;--soft:#f4f7f9}}
*{{box-sizing:border-box}}body{{font:12px/1.45 Arial,Helvetica,sans-serif;color:var(--ink);margin:0;background:#fff}}
.page{{max-width:190mm;margin:0 auto;padding:14mm 10mm 30mm}}
h1{{font-size:22px;margin:0 0 4px;color:var(--accent)}}h2{{font-size:15px;margin:18px 0 6px;border-bottom:2px solid var(--accent);padding-bottom:3px}}
h4{{font-size:12px;margin:12px 0 4px}}.muted{{color:var(--muted)}}.cover{{border:1px solid var(--line);padding:12px;background:var(--soft)}}
table{{border-collapse:collapse;width:100%;margin:4px 0 8px;font-size:10.5px}}th,td{{border:1px solid var(--line);padding:3px 5px;vertical-align:top;word-break:break-word}}
th{{background:#e9eef2;text-align:left}}tr:nth-child(even) td{{background:#fbfcfd}}
.stats td:nth-child(2){{font-weight:bold}}.map{{width:100%;max-height:95mm;object-fit:contain;border:1px solid var(--line)}}
.seal{{position:fixed;right:8mm;bottom:8mm;width:34mm;height:34mm;z-index:9}}
.note{{font-size:10px;color:var(--muted)}}code{{font-family:Consolas,monospace;font-size:9.5px;word-break:break-all}}
@media print{{.page{{max-width:none;padding:0 0 26mm}}.seal{{position:fixed;right:6mm;bottom:6mm}}}}
</style></head><body><div class="page">
<h1>{esc(L['title'])}</h1>
<p class="muted">MailSleuth · {esc(L['generated'])}: {esc(when)} · {esc(L['case'])} {esc(row.get('id'))}</p>
{toc_html}
<h2>1. {esc(L['custody'])}</h2>{meta_html}
<h2>2. {esc(L['summary'])}</h2>{stat_html}
<h2>3. {esc(L['auth'])}</h2>{auth_html}
<h2>4. {esc(L['header'])}</h2>{hdr_html}
<h2>5. {esc(L['routing'])}</h2>{rt_html}
<h2>6. {esc(L['findings'])} ({len(findings)})</h2>{find_html}
<h2>7. {esc(L['ips'])}</h2>{ip_html}
<h2>8. {esc(L['map'])}</h2>{map_html}
<h2>9. {esc(L['urls'])}</h2>{url_html or '<p class="muted">-</p>'}
<h2>10. {esc(L['attachments'])}</h2>{att_html}
<h2>11. DNS</h2>{dns_html}
<h2>12. {esc(L['ioc'])}</h2>{ioc_html}
<h2>13. {esc(L['graph'])}</h2>{graph_svg or '<p class="muted">-</p>'}
<h2>14. {esc(L['method'])}</h2><p class="note">{esc(L['limits_text'])}</p>
<h2>15. {esc(L['timeline'])}</h2>{timeline_html}
<h2>16. {esc(L['classification'])}</h2>{class_html}
<h2>17. {esc(L['response'])}</h2>{resp_html}
<h2>18. {esc(L['annex'])}</h2>{annex_html}
<h2>19. {esc(L['signature'])}</h2>
<p><code>{esc(sig)}</code></p><p class="note">{esc(L['sig_note'])}</p>
<h2>20. {esc(L['limits'])}</h2><p class="note">{esc(L['limits_text'])}</p>
</div><div class="seal">{seal}</div></body></html>"""


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------
def render_csv(row: dict, result: dict, lang: str = "en", kind: str = "summary") -> str:
    en = (lang or "en") != "vi"
    out = io.StringIO()
    w = csv.writer(out, quoting=csv.QUOTE_ALL)
    kind = (kind or "summary").lower()
    if kind == "findings":
        w.writerow(["case_id", "category", "id", "type", "severity", "weight", "message", "evidence"]
                   if en else ["ma_vu", "nhom", "id", "loai", "muc_do", "trong_so", "thu", "chung_cu"])
        for f in (result.get("findings") or []):
            w.writerow([_safe_csv(x) for x in (row.get("id"), _category(f), f.get("id"),
                                               f.get("type"), f.get("severity"), f.get("weight"),
                                               (f.get("m") + 1) if isinstance(f.get("m"), int) else "",
                                               f.get("evidence"))])
    elif kind == "urls":
        w.writerow(["case_id", "target_index", "target_subject", "target_from", "url", "host",
                    "risk", "verdict", "reasons"] if en else
                   ["ma_vu", "chi_so", "tieu_de", "nguoi_gui", "url", "host", "rui_ro", "ket_luan", "ly_do"])
        for g in url_groups(result, lang):
            for u in g["urls"]:
                w.writerow([_safe_csv(x) for x in (row.get("id"), g["index"], g["subject"], g["from"],
                                                   u.get("url"), u.get("host"), u.get("risk"),
                                                   u.get("verdict"), " | ".join(u.get("reasons") or []))])
    elif kind == "ips":
        w.writerow(["case_id", "ip", "country", "city", "asn", "organization", "latitude",
                    "longitude", "ptr", "server", "assessment", "confidence"]
                   if en else ["ma_vu", "ip", "quoc_gia", "thanh_pho", "asn", "to_chuc", "vi_do",
                               "kinh_do", "ptr", "may_chu", "danh_gia", "do_tin_cay"])
        for x in (result.get("ipInfo") or []):
            g = x.get("geo") or {}
            loc = g.get("location") or {}
            w.writerow([_safe_csv(v) for v in (row.get("id"), x.get("ip"), g.get("country"), g.get("city"),
                                               g.get("asn"), g.get("organization"), loc.get("latitude"),
                                               loc.get("longitude"), " | ".join(x.get("ptr") or []),
                                               (x.get("server") or {}).get("key"),
                                               (x.get("assessment") or {}).get("verdict"), _conf(x))])
    elif kind == "dns":
        w.writerow(["case_id", "domain", "spf", "dkim", "dmarc", "mx", "ns"]
                   if en else ["ma_vu", "ten_mien", "spf", "dkim", "dmarc", "mx", "ns"])
        for d in _flatten_dns(result):
            w.writerow([_safe_csv(row.get("id"))] + [_safe_csv(d[k]) for k in ("domain", "spf", "dkim", "dmarc", "mx", "ns")])
    elif kind == "all":
        # one row per finding plus the case header
        w.writerow(["case_id", "file", "sha256", "score", "verdict", "category", "id", "type",
                    "severity", "evidence"] if en else
                   ["ma_vu", "tep", "sha256", "diem", "ket_luan", "nhom", "id", "loai", "muc_do", "chung_cu"])
        for f in (result.get("findings") or []):
            w.writerow([_safe_csv(v) for v in (row.get("id"), row.get("file"), row.get("sha256"),
                                               result.get("score"), result.get("verdict"),
                                               _category(f), f.get("id"), f.get("type"),
                                               f.get("severity"), f.get("evidence"))])
    else:
        w.writerow(["case_id", "file", "sha256", "format", "platform", "count", "score",
                    "verdict", "category", "value", "detail"] if en else
                   ["ma_vu", "tep", "sha256", "dinh_dang", "nen_tang", "so_thu", "diem",
                    "ket_luan", "nhom", "gia_tri", "chi_tiet"])
        for r in stats_rows(result, lang):
            w.writerow([_safe_csv(v) for v in (row.get("id"), row.get("file"), row.get("sha256"),
                                               result.get("format"), result.get("platform"),
                                               result.get("count"), result.get("score"),
                                               result.get("verdict"), r["label"], r["value"], r["detail"])])
    return "\ufeff" + out.getvalue()


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------
def _find_font():
    cands = [
        r"C:\Windows\Fonts\arial.ttf", r"C:\Windows\Fonts\segoeui.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        os.path.join(os.path.dirname(__file__), "assets", "DejaVuSans.ttf"),
    ]
    for p in cands:
        if os.path.isfile(p):
            return p
    return ""


def _find_font_bold():
    cands = [
        r"C:\Windows\Fonts\arialbd.ttf", r"C:\Windows\Fonts\segoeuib.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
    ]
    for p in cands:
        if os.path.isfile(p):
            return p
    return ""


def _ascii(s):
    return unicodedata.normalize("NFKD", str(s or "")).encode("ascii", "ignore").decode("ascii")


class _PDF(FPDF):
    def __init__(self, sig, when, lang, unicode_font):
        super().__init__(format="A4", unit="mm")
        self.sig = sig or ""
        self.when = when or ""
        self.lang = lang or "en"
        self.unicode_font = unicode_font
        self.set_auto_page_break(True, margin=22)
        self.set_margins(14, 14, 14)

    def _t(self, s):
        return str(s if s is not None else "") if self.unicode_font else _ascii(s)

    def header(self):
        self.set_font(self._family, "B", 8)
        self.set_text_color(120, 130, 140)
        self.cell(0, 5, self._t("MailSleuth - " + ("Forensic report" if self.lang != "vi" else "Báo cáo pháp chứng")),
                  new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(0, 0, 0)

    def footer(self):
        self.set_y(-16)
        self.set_draw_color(139, 30, 45)
        self.set_line_width(0.3)
        self.line(14, self.get_y() - 1, 196, self.get_y() - 1)
        self.set_font(self._family, "", 7.5)
        self.set_text_color(90, 100, 110)
        self.cell(0, 5, self._t(f"Page {self.page_no()} / {{nb}}  ·  SHA-256 {self.sig[:32]}"), align="L")
        # seal, bottom-right
        x, y = 164, self.h - 25
        self.set_draw_color(139, 30, 45)
        self.set_line_width(0.5)
        self.ellipse(x, y, 26, 26)
        self.set_line_width(0.2)
        self.ellipse(x + 2, y + 2, 22, 22)
        self.set_font(self._family, "B", 6.2)
        self.set_text_color(139, 30, 45)
        self.set_xy(x, y + 4)
        self.cell(26, 3, self._t("MAILSLEUTH"), align="C")
        self.set_font(self._family, "", 5.4)
        self.set_xy(x, y + 7.2)
        self.cell(26, 3, self._t("SHA-256"), align="C")
        self.set_font(self._family, "B", 6.4)
        self.set_xy(x, y + 11)
        self.cell(26, 3, self._t("SIGNED" if self.lang != "vi" else "ĐÃ KÝ"), align="C")
        self.set_font("helvetica", "", 4.6)
        self.set_xy(x, y + 15)
        self.cell(26, 2.5, self.sig[:16], align="C")
        self.set_xy(x, y + 17.5)
        self.cell(26, 2.5, self.sig[16:32], align="C")
        self.set_text_color(0, 0, 0)

    def section(self, title):
        if self.get_y() > 250:
            self.add_page()
        self.ln(2)
        self.set_font(self._family, "B", 11)
        self.set_fill_color(233, 238, 242)
        self.set_text_color(20, 30, 40)
        self.cell(0, 7, self._t(title), fill=True, new_x="LMARGIN", new_y="NEXT")
        self.ln(1)

    def kv(self, label, value):
        self.set_font(self._family, "B", 8)
        self.cell(34, 4.6, self._t(label), border="B")
        self.set_font(self._family, "", 8)
        self.multi_cell(0, 4.6, self._t(value), border="B", new_x="LMARGIN", new_y="NEXT")

    def table(self, headers, rows, widths=None):
        if not rows:
            rows = [["-"] * len(headers)]
        n = len(headers)
        widths = widths or [max(12, 182 // n)] * n
        self.set_font(self._family, "B", 7)
        self.set_fill_color(225, 232, 238)
        for h, w in zip(headers, widths):
            self.cell(w, 5, self._t(h)[: max(4, int(w * 1.6))], border=1, fill=True)
        self.ln()
        self.set_font(self._family, "", 6.6)
        for row in rows:
            vals = [self._t(x) for x in row]
            # one line per row, clipped to keep the layout stable
            h = 5
            for v, w in zip(vals, widths):
                self.cell(w, h, v[: max(4, int(w * 1.7))], border=1)
            self.ln()
            if self.get_y() > 270:
                self.add_page()
                self.set_font(self._family, "", 6.6)


def render_pdf(row: dict, result: dict, lang: str = "en", sig: str = "", map_png: bytes = b"") -> bytes:
    if FPDF is None:
        raise RuntimeError("fpdf_missing")
    L = _T(lang)
    when = _utc_now()
    sig = sig or case_signature(row, result)
    font = _find_font()
    pdf = _PDF(sig, when, lang, bool(font))
    pdf._family = "Body" if font else "helvetica"
    if font:
        pdf.add_font("Body", "", font)
        bold = _find_font_bold()
        if bold:
            pdf.add_font("Body", "B", bold)
        else:
            pdf.add_font("Body", "B", font)
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_font(pdf._family, "B", 17)
    pdf.set_text_color(139, 30, 45)
    pdf.multi_cell(0, 8, pdf._t(L["title"]), new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.set_font(pdf._family, "", 8)
    pdf.cell(0, 5, pdf._t(f"Case {row.get('id')} · {when} · {row.get('user') or ''}"),
             new_x="LMARGIN", new_y="NEXT")
    pdf.section("1. " + L["custody"])
    custody = result.get("custody") or {}
    for label, value in [
        (L["original"], row.get("file") or custody.get("original")),
        (L["sha"], row.get("sha256") or custody.get("sha256")),
        (L["format"], result.get("format")), (L["platform"], result.get("platform") or "auto"),
        (L["size"], f"{custody.get('size', '-')} B"),
        (L["evidence"], custody.get("evidencePath") or "-"),
        (L["score"], f"{result.get('score')}/100"), (L["verdict"], result.get("verdict")),
        (L["count"], result.get("count")),
    ]:
        pdf.kv(label, value)
    pdf.section("2. " + L["summary"])
    pdf.table([L["category"], L["value"], L["detail"]],
              [[r["label"], r["value"], r["detail"]] for r in stats_rows(result, lang)],
              [58, 45, 79])
    pdf.section("3. " + L["auth"])
    auth = result.get("auth") or {}
    pdf.table(["Mechanism", "Result", "Detail"],
              [[k.upper(), (auth.get(k) or {}).get("result") or "-",
                (auth.get(k) or {}).get("reason") or ""] for k in ("spf", "dkim", "dmarc")],
              [28, 35, 119])
    pdf.section("4. " + L["header"])
    pdf.table(["ID", L["type"], L["sev"], L["evidence_col"]],
              [[f.get("id"), f.get("type"), f.get("severity"), f.get("evidence")]
               for f in ((result.get("headerAnalysis") or {}).get("checks") or [])[:120]],
              [20, 38, 18, 106])
    pdf.section("5. " + L["findings"] + f" ({len(result.get('findings') or [])})")
    pdf.table(["ID", L["type"], L["sev"], L["evidence_col"]],
              [[f.get("id"), f.get("type"), f.get("severity"), f.get("evidence")]
               for f in (result.get("findings") or [])[:250]],
              [20, 40, 18, 104])
    pdf.section("6. " + L["ips"])
    pdf.table(["IP", L["coords"], L["country"], L["asn"], L["confidence"]],
              [[x.get("ip"),
                f"{((x.get('geo') or {}).get('location') or {}).get('latitude', '-')}, "
                f"{((x.get('geo') or {}).get('location') or {}).get('longitude', '-')}",
                (x.get("geo") or {}).get("country") or "-",
                f"AS{(x.get('geo') or {}).get('asn') or ''} {(x.get('geo') or {}).get('organization') or ''}".strip(),
                _conf(x)] for x in (result.get("ipInfo") or [])],
              [35, 45, 35, 45, 22])
    if map_png:
        pdf.section("7. " + L["map"])
        try:
            pdf.image(io.BytesIO(map_png), w=170)
        except Exception:
            pass
    pdf.section("8. " + L["urls"])
    for g in url_groups(result, lang):
        pdf.set_font(pdf._family, "B", 8)
        pdf.multi_cell(0, 4.6, pdf._t(f"#{g['index'] + 1 if g['index'] is not None else '-'} {g['subject']} ({g['from']})"),
                       new_x="LMARGIN", new_y="NEXT")
        pdf.table(["URL", "Host", L["risk"], L["verdict"]],
                  [[u.get("url"), u.get("host"), f"{u.get('risk')}%", u.get("verdict")]
                   for u in g["urls"][:40]], [105, 35, 18, 24])
    pdf.section("9. " + L["attachments"])
    pdf.table([L["file"], L["size"], L["hash"], L["verdict"]],
              [[a.get("name"), f"{a.get('size')} B", a.get("sha256"),
                (a.get("verdict") or "") + ((" [" + ", ".join(a.get("scanEngines") or []) + "]") if a.get("scanEngines") else "")]
               for a in (result.get("attachments") or [])[:100]], [50, 18, 86, 28])
    fb = _forensic_blocks(result, lang, L)
    pdf.section("10. " + L["timeline"])
    pdf.table(["Timestamp", "Source", "Event", "Delay"],
              [[r[0], r[1], r[2], r[3]] for r in fb["timeline"][:40]], [35, 35, 90, 22])
    pdf.section("11. " + L["classification"])
    pdf.table(["Kind", "Detail", "Evidence"],
              [[r[0], r[1], r[2]] for r in fb["assessments"][:60]], [28, 90, 64])
    pdf.section("12. " + L["response"])
    pdf.table(["Action", "Rationale"], fb["responses"][:30], [60, 122])
    pdf.section("13. " + L["annex"])
    pdf.table(["File", "SHA-256", "Size"], fb["annex"][:40], [60, 100, 22])
    pdf.section("14. " + L["signature"])
    pdf.set_font(pdf._family, "", 7)
    pdf.multi_cell(0, 4, sig, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)
    pdf.set_font(pdf._family, "", 7)
    pdf.multi_cell(0, 4, pdf._t(L["sig_note"]), new_x="LMARGIN", new_y="NEXT")
    pdf.section("15. " + L["limits"])
    pdf.set_font(pdf._family, "", 7)
    pdf.multi_cell(0, 4, pdf._t(L["limits_text"]), new_x="LMARGIN", new_y="NEXT")
    return bytes(pdf.output())
