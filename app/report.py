"""Full HTML report (8-col IP) + CSV export + P1 forensics sections."""
import html as _h, csv, io, hashlib, json

def esc(x): return _h.escape(str(x or ""))

def _conf(x):
    c = x.get("confidence")
    return f"{round(float(c))}%" if c is not None else "—"

def _auth_row(label, a, en):
    r = esc(a.get("result") or "—")
    bits = []
    if a.get("policy"): bits.append(f"p={a['policy']}")
    if a.get("domain"): bits.append(str(a["domain"]))
    if a.get("selector"): bits.append(f"selector={a['selector']}")
    if a.get("alignment"): bits.append(f"align SPF:{'ok' if a['alignment'].get('spf') else 'no'}/DKIM:{'ok' if a['alignment'].get('dkim') else 'no'}")
    if a.get("reason"): bits.append(str(a["reason"])[:120])
    sig = ""
    if a.get("signatures"):
        sig = " · " + ", ".join(f"{s.get('domain')}/{s.get('selector')}={s.get('result')}"
                                for s in a["signatures"])
    return f"<tr><td>{esc(label)}</td><td>{r}</td><td>{esc(' · '.join(bits))}{esc(sig)}</td></tr>"

def render_report(row: dict, result: dict, lang: str = "en", integrity: bool = True, map_base64: str = "") -> str:
    en = (lang or "en") != "vi"
    title = "MailSleuth Report" if en else "Báo cáo MailSleuth"
    conf = "Confidence" if en else "Độ tin cậy"
    T = lambda a, b: esc(a if en else b)
    findings = ""
    for f in (result.get("findings") or []):
        findings += f"<li>[{esc(f.get('severity', f.get('sev',''))) }] {esc(f.get('id',''))} {esc(f.get('type',''))} — {esc(f.get('evidence',''))}</li>"
    custody = result.get("custody") or {}
    ip_rows = ""
    for i, x in enumerate(result.get("ipInfo") or []):
        g = x.get("geo") or {}
        loc = g.get("location") or {}
        coords = f"{loc.get('latitude','')}, {loc.get('longitude','')}" if loc.get("latitude") is not None else "—"
        place = f"{g.get('country') or ''} / {g.get('city') or ''}".strip(" /") or "—"
        org = f"AS{g.get('asn') or ''} {g.get('organization') or ''}".strip() or "—"
        srv = x.get("server") or {}
        asm = x.get("assessment") or {}
        ip_rows += (f"<tr><td>{i+1}. {esc(x.get('ip'))}</td><td>{esc(coords)}</td><td>{esc(place)}</td><td>{esc(org)}</td>"
                    f"<td>{esc(', '.join(x.get('ptr') or []))}</td><td>{esc(srv.get('key',''))}</td>"
                    f"<td>{esc(asm.get('verdict',''))}{' — '+esc('; '.join(asm.get('reasons') or [])) if asm.get('reasons') else ''}</td><td>{esc(_conf(x))}</td></tr>")
    # --- P1 forensics sections ---
    auth = result.get("auth") or {}
    auth_html = ""
    if auth:
        auth_rows = (_auth_row("SPF", auth.get("spf") or {}, en) + _auth_row("DKIM", auth.get("dkim") or {}, en)
                     + _auth_row("DMARC", auth.get("dmarc") or {}, en))
        up = auth.get("upstream") or {}
        if up.get("raw"):
            auth_rows += _auth_row(
                "Upstream (Authentication-Results)",
                {"result": up.get("spf") or "—", "domain": up.get("authserv"),
                 "reason": f"dkim={up.get('dkim') or '—'} · dmarc={up.get('dmarc') or '—'}"},
                en)
        auth_html = (f"<h2>{T('3. Authentication (SPF / DKIM / DMARC)', '3. Xác thực (SPF / DKIM / DMARC)')}</h2>"
                     f"<table><thead><tr><th>Mechanism</th><th>Result</th><th>Detail</th></tr></thead>"
                     f"<tbody>{auth_rows}</tbody></table>"
                     f"<p class=\"small\">{T('client IP used', 'IP client dùng')} : {esc(auth.get('clientIp') or '—')} · "
                     f"{T('envelope domain', 'tên miền envelope')}: {esc(auth.get('envDomain') or '—')} · "
                     f"{T('overall', 'tổng thể')}: {esc(auth.get('overall') or '—')}</p>")
    hdr = result.get("headerAnalysis") or {}
    hdr_html = ""
    if hdr:
        hc = hdr.get("checks") or []
        rows = "".join(f"<li>[{esc(f.get('severity',''))}] {esc(f.get('id',''))} {esc(f.get('type',''))} — {esc(f.get('evidence',''))}</li>" for f in hc[:50])
        hdr_html = (f"<h2>{T('4. Header analysis', '4. Phân tích header')}</h2>"
                    f"<p class=\"small\">Received: {esc(hdr.get('receivedCount', 0))} · From={esc(hdr.get('fromDomain') or '—')} · "
                    f"Return-Path={esc(hdr.get('returnPathDomain') or '—')} · Reply-To={esc(hdr.get('replyToDomain') or '—')}</p>"
                    f"<ul>{rows or '<li>—</li>'}</ul>")
    rt = result.get("routing") or {}
    rt_html = ""
    if rt:
        hr = ""
        for h in (rt.get("hops") or [])[:40]:
            hr += (f"<tr><td>#{h.get('idx')}</td><td>{esc(h.get('from') or '—')}{esc(' (' + h['ip'] + ')' if h.get('ip') else '')}</td>"
                   f"<td>{esc(h.get('by') or '—')}</td><td>{esc(h.get('with') or '—')}</td>"
                   f"<td>{esc(h.get('gateway') or '—')}</td><td>{esc((str(h.get('delayMs')) + ' ms') if h.get('delayMs') is not None else '—')}</td></tr>")
        ra = "".join(f"<li>[{esc(f.get('severity',''))}] {esc(f.get('id',''))} {esc(f.get('type',''))} — {esc(f.get('evidence',''))}</li>" for f in (rt.get('anomalies') or [])[:20])
        rt_html = (f"<h2>{T('5. SMTP routing', '5. Đường truyền SMTP')}</h2>"
                   f"<table><thead><tr><th>#</th><th>{T('From', 'Từ')}</th><th>By</th><th>With</th><th>Gateway</th><th>{T('Delay', 'Trễ')}</th></tr></thead>"
                   f"<tbody>{hr or '<tr><td colspan=6>—</td></tr>'}</tbody></table>"
                   f"<p class=\"small\">{T('Total transit', 'Tổng thời gian')}: {esc(rt.get('totalDelayMs', 0))} ms</p>"
                   + (f"<ul>{ra}</ul>" if ra else ""))
    map_html = ""
    if map_base64:
        legend = "".join(f'<li><b>{i+1}.</b> {esc(x.get("ip"))}{" — " + esc(x.get("mapAddr")) if x.get("mapAddr") else ""}</li>' for i, x in enumerate(result.get("ipInfo") or []) if (x.get("geo") or {}).get("location") and (x.get("geo") or {}).get("location").get("latitude") is not None)
        legend_html = f'<ol class="maplist">{legend}</ol>' if legend else ""
        map_html = f'<figure class="casemap"><img src="data:image/png;base64,{map_base64}" style="width:5cm;height:5cm" alt="map"></figure>{legend_html}'
    urls = result.get("urls") or []
    url_html = ""
    if urls:
        rows = "".join(f"<tr><td>{esc(u.get('url',''))[:160]}</td><td>{esc(u.get('host',''))}</td>"
                       f"<td>{esc(u.get('risk'))}% — {esc(u.get('verdict'))}</td><td>{esc('; '.join(u.get('reasons') or []))}</td></tr>"
                       for u in urls[:40])
        url_html = (f"<h2>7. URL analysis</h2>"
                    f"<table><thead><tr><th>URL</th><th>Host</th><th>Risk</th><th>Reasons</th></tr></thead>"
                    f"<tbody>{rows}</tbody></table>")
    atts = result.get("attachments") or []
    att_html = ""
    if atts:
        rows = "".join(f"<tr><td>{esc(a.get('name',''))}</td><td>{esc(a.get('size'))} B</td><td>{esc(a.get('magic',''))}</td>"
                       f"<td><code>{esc(a.get('sha256',''))}</code></td><td>entropy {esc(a.get('entropy'))}</td>"
                       f"<td>{esc(a.get('verdict'))}{' — ' + esc('; '.join(a.get('reasons') or [])) if a.get('reasons') else ''}</td></tr>"
                       for a in atts[:100])
        att_html = (f"<h2>8. Attachment analysis</h2>"
                    f"<table><thead><tr><th>File</th><th>Size</th><th>Real type</th><th>SHA-256</th><th>Entropy</th><th>Verdict</th></tr></thead>"
                    f"<tbody>{rows}</tbody></table>")
    return f"""<!doctype html><html lang="{lang}"><head><meta charset="utf-8"><title>{esc(title)}</title><style>body{{font-family:sans-serif}}table{{border-collapse:collapse}}td,th{{border:1px solid #999;padding:2px 6px}}.small{{font-size:80%}}</style></head><body>
<h1>{esc(title)}</h1>
<p>Case {esc(row.get('id',''))} · {esc(row.get('file',''))} · score {esc(result.get('score'))}/100 · verdict {esc(result.get('verdict',''))}</p>
<h2>1. Custody</h2><p>Original: {esc(custody.get('original',''))} · SHA-256: <code>{esc(custody.get('sha256',''))}</code> · UTC: {esc(custody.get('utc',''))} · integrity: {integrity}</p>
<h2>2. Messages</h2><p>Count: {esc(result.get('count',0))} · authSeen: {esc(result.get('authSeen'))}</p>
{auth_html}{hdr_html}{rt_html}
<h2>6. Findings</h2><ul>{findings or '<li>—</li>'}</ul>
{url_html}{att_html}{map_html}
<h2>9. IP intelligence</h2><table><thead><tr><th>IP</th><th>{esc('Coordinates' if en else 'Tọa độ')}</th><th>{esc('Country / City' if en else 'Quốc gia / Thành phố')}</th><th>ASN / Org</th><th>PTR</th><th>{esc('Server type' if en else 'Loại server')}</th><th>{esc('Assessment' if en else 'Đánh giá')}</th><th>{esc(conf)}</th></tr></thead><tbody>{ip_rows or '<tr><td colspan="8">—</td></tr>'}</tbody></table>
</body></html>"""

def render_csv(row: dict, result: dict, lang: str = "en") -> str:
    out = io.StringIO()
    w = csv.writer(out, quoting=csv.QUOTE_ALL)
    auth = result.get("auth") or {}
    hdr = result.get("headerAnalysis") or {}
    rt = result.get("routing") or {}
    base = [row.get("id",""), row.get("file",""), row.get("sha256",""), result.get("score",""), result.get("verdict",""),
            auth.get("spf",{}).get("result","") if auth else "",
            auth.get("dkim",{}).get("result","") if auth else "",
            auth.get("dmarc",{}).get("result","") if auth else "",
            auth.get("dmarc",{}).get("policy","") if auth else "",
            rt.get("hopCount",""), len(hdr.get("checks") or []),
            len(result.get("findings") or [])]
    w.writerow(["case_id","file","sha256","score","verdict",
                "spf_result","dkim_result","dmarc_result","dmarc_policy",
                "hops_count","header_check_count","finding_count",
                "ip","country","city","asn","organization","latitude","longitude","ptr","server_key","assessment_verdict","confidence_percent"])
    for x in (result.get("ipInfo") or []):
        g = x.get("geo") or {}
        loc = g.get("location") or {}
        w.writerow(base + [x.get("ip",""), g.get("country",""), g.get("city",""), g.get("asn",""), g.get("organization",""),
            loc.get("latitude",""), loc.get("longitude",""), " | ".join(x.get("ptr") or []),
            (x.get("server") or {}).get("key",""), (x.get("assessment") or {}).get("verdict",""),
            round(float(x["confidence"])) if x.get("confidence") is not None else ""])
    # No IP at all -> still emit one row with the case-level columns.
    if not (result.get("ipInfo") or []):
        w.writerow(base + ["","","","","","","","","","","",""])
    return out.getvalue()
