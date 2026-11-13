"""M10 — Feature extraction for the (optional) trained classifier.

The feature vector is built **only** from what the analysis pipeline already
computed (M1–M6). Two rules keep the model trustworthy and leak-free:

1. **No live-DNS results** (SPF/DKIM/DMARC pass/fail) are used as features:
   they depend on the moment of training (an old corpus would be evaluated
   against today's DNS) and they are already high-precision rule signals.
2. **No raw identifiers** (domains, IP addresses, brand names, URLs, file
   names, message text) leave the process in a feature vector: everything is
   reduced to counters, buckets and flags. A feature vector can therefore be
   shared for training without disclosing mail content.

`FEATURE_NAMES` is a fixed, ordered list -> the model file and the server must
agree on it exactly (`tools/verify_model.py` enforces this).
"""

FEATURE_NAMES = [
    # --- M1 header forensics -------------------------------------------------
    "hdr_checks_total", "hdr_checks_high", "hdr_checks_medium",
    "hdr_from_returnpath_mismatch", "hdr_replyto_mismatch",
    "hdr_displayname_spoof", "hdr_date_skew", "hdr_duplicate_header",
    "hdr_missing_header", "hdr_x_originating_ip", "hdr_weight_total",
    "hdr_received_count",
    # --- M2 authentication (presence only - never the live verdict) ---------
    "auth_header_present", "auth_spf_result_seen", "auth_dkim_result_seen",
    "auth_dmarc_result_seen", "auth_spf_align", "auth_dkim_align",
    "auth_dkim_signature_count", "auth_upstream_present",
    # --- M3 routing ----------------------------------------------------------
    "rt_hop_count", "rt_total_delay_bucket", "rt_has_loop", "rt_time_reversed",
    "rt_private_ip_hop", "rt_missing_from", "rt_anomaly_count",
    # --- M4 URLs -------------------------------------------------------------
    "url_count", "url_max_risk", "url_mean_risk", "url_malicious_count",
    "url_suspicious_count", "url_ip_host", "url_punycode", "url_lookalike",
    "url_at_trick", "url_bait_keywords", "url_distinct_hosts",
    # --- M5 attachments ------------------------------------------------------
    "att_count", "att_max_risk", "att_malicious_count", "att_eicar",
    "att_magic_mismatch", "att_double_ext", "att_high_entropy",
    "att_dangerous_ext", "att_zip_bomb", "att_nested_archive",
    "att_quarantined_count", "att_html_attachment",
    # --- content / meta ------------------------------------------------------
    "body_word_count_bucket", "body_has_html", "body_url_count",
    "body_bait_keyword_count", "msg_count_bucket", "format_is_pst",
    "format_is_msg", "headers_present",
]

_HEADER_TYPES = ("from_returnpath_mismatch", "replyto_mismatch", "display_name_spoof",
                 "date_skew", "duplicate_header", "missing_header", "x_originating_ip")
# routing anomaly type -> feature name (see app/routing.py)
_RT_MAP = {"hop_loop": "rt_has_loop", "hop_negative_delay": "rt_time_reversed",
           "private_ip_hop": "rt_private_ip_hop", "hop_missing_from": "rt_missing_from"}


def _bucket(n, edges=(0, 1, 5, 20, 100, 1000)):
    """Map a count to an ordinal bucket (keeps the vector scale-free)."""
    try:
        n = int(n)
    except Exception:
        n = 0
    for i, e in enumerate(edges):
        if n <= e:
            return i
    return len(edges)


def extract_features(result: dict) -> dict:
    """Case result (as stored in `cases.result`) -> {feature: value}."""
    f = {k: 0 for k in FEATURE_NAMES}
    if not isinstance(result, dict):
        return f
    hdr = result.get("headerAnalysis") or {}
    checks = hdr.get("checks") or []
    f["hdr_checks_total"] = len(checks)
    f["hdr_checks_high"] = sum(1 for c in checks if int(c.get("sev") or 0) >= 3)
    f["hdr_checks_medium"] = sum(1 for c in checks if int(c.get("sev") or 0) == 2)
    f["hdr_weight_total"] = sum(int(c.get("weight") or 0) for c in checks)
    for c in checks:
        t = str(c.get("type") or "")
        for h in _HEADER_TYPES:
            if h in t:
                f["hdr_" + h] += 1
    f["hdr_received_count"] = int(hdr.get("receivedCount") or 0)

    auth = result.get("auth") or {}
    f["auth_header_present"] = 1 if auth.get("headerFound") else 0
    f["auth_upstream_present"] = 1 if (auth.get("upstream") or {}).get("raw") else 0
    for k in ("spf", "dkim", "dmarc"):
        r = str((auth.get(k) or {}).get("result") or "")
        if r and r not in ("none", "not_run"):
            f[f"auth_{k}_result_seen"] = 1
    al = auth.get("alignment") or {}
    if al.get("spf") is True:
        f["auth_spf_align"] = 1
    if al.get("dkim") is True:
        f["auth_dkim_align"] = 1
    f["auth_dkim_signature_count"] = len(auth.get("dkimSignatures") or [])

    rt = result.get("routing") or {}
    f["rt_hop_count"] = _bucket(len(rt.get("hops") or []), (0, 2, 4, 8, 20, 1000))
    delay = rt.get("totalDelayMs")
    try:
        f["rt_total_delay_bucket"] = _bucket(int(delay), (0, 1000, 10000, 60000, 3600000, 10 ** 12))
    except Exception:
        f["rt_total_delay_bucket"] = 0
    f["rt_anomaly_count"] = len(rt.get("anomalies") or [])
    for a in (rt.get("anomalies") or []):
        t = str(a.get("type") or "")
        for src, dst in _RT_MAP.items():
            if src in t:
                f[dst] += 1

    urls = result.get("urls") or []
    f["url_count"] = _bucket(len(urls), (0, 1, 3, 10, 50, 1000))
    risks = [int(u.get("risk") or 0) for u in urls]
    f["url_max_risk"] = max(risks) if risks else 0
    f["url_mean_risk"] = int(sum(risks) / len(risks)) if risks else 0
    f["url_malicious_count"] = sum(1 for u in urls if u.get("verdict") == "malicious")
    f["url_suspicious_count"] = sum(1 for u in urls if u.get("verdict") == "suspicious")
    for u in urls:
        for r in (u.get("reasons") or []):
            r = str(r).lower()
            if "raw ip" in r or "ip address" in r:
                f["url_ip_host"] += 1
            if "punycode" in r or "homoglyph" in r or "non-ascii" in r:
                f["url_punycode"] += 1
            if "brand" in r or "lookalike" in r:
                f["url_lookalike"] += 1
            if "@" in r:
                f["url_at_trick"] += 1
            if "keyword" in r or "bait" in r or "urgent" in r or "verify" in r or "invoice" in r:
                f["url_bait_keywords"] += 1
    f["url_distinct_hosts"] = _bucket(len({str(u.get("host") or "") for u in urls if u.get("host")}),
                                     (0, 1, 3, 10, 50, 1000))

    atts = result.get("attachments") or []
    f["att_count"] = _bucket(len(atts), (0, 1, 3, 10, 50, 1000))
    f["att_malicious_count"] = sum(1 for a in atts if a.get("verdict") == "malicious")
    f["att_quarantined_count"] = sum(1 for a in atts if a.get("verdict") not in ("clean", None))
    for a in atts:
        for r in (a.get("reasons") or []):
            r = str(r).lower()
            if "eicar" in r:
                f["att_eicar"] += 1
            if "magic" in r or "mismatch" in r:
                f["att_magic_mismatch"] += 1
            if "double" in r or "extension" in r:
                f["att_double_ext"] += 1
            if "entropy" in r:
                f["att_high_entropy"] += 1
            if "zip" in r and "bomb" in r:
                f["att_zip_bomb"] += 1
            if "nested" in r:
                f["att_nested_archive"] += 1
            if "html" in r:
                f["att_html_attachment"] += 1
        name = str(a.get("name") or "").lower()
        if name.endswith((".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".jar", ".hta")):
            f["att_dangerous_ext"] += 1

    body_words = int(result.get("bodyWordCount") or 0)
    f["body_word_count_bucket"] = _bucket(body_words, (0, 50, 200, 1000, 5000, 10 ** 7))
    f["body_has_html"] = 1 if (result.get("bodyHasHtml") or result.get("urls")) else 0
    f["body_url_count"] = len(urls)
    f["body_bait_keyword_count"] = min(20, f["url_bait_keywords"])
    f["msg_count_bucket"] = _bucket(int(result.get("count") or 0), (0, 1, 5, 20, 100, 10000))
    fmt = str(result.get("format") or "").lower()
    f["format_is_pst"] = 1 if fmt in ("pst", "ost") else 0
    f["format_is_msg"] = 1 if fmt == "msg" else 0
    f["headers_present"] = 1 if (hdr.get("checks") or hdr.get("headers")) else 0
    return f


def feature_vector(result: dict) -> list:
    f = extract_features(result)
    return [float(f.get(name) or 0) for name in FEATURE_NAMES]
