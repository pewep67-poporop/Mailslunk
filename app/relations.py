"""Quan hệ giữa các message trong cùng vụ việc - mọi cạnh có evidence.

Không đoán theo tên người/brand. Chỉ dùng field có thật: Message-ID/In-Reply-To/
References/From/To/Cc/Bcc/URL host/attachment hash/Received IP/Date.
"""
from __future__ import annotations

import re
from collections import defaultdict
from datetime import timezone
from email.utils import parseaddr, parsedate_to_datetime

MAX_PER_GROUP = 8
MAX_RELATIONS = 600


def _addr(value: str) -> str:
    a = parseaddr(str(value or ""))[1].strip().lower()
    if not a and "@" in str(value or ""):
        a = str(value).strip().lower()
    return a.rstrip(">.")


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1] if "@" in addr else ""


def _norm_mid(value: str) -> str:
    return str(value or "").strip().lower().lstrip("<").rstrip(">")


def build(result: dict) -> dict:
    msgs = result.get("messages") or []
    n = len(msgs)
    rels, seen = [], set()

    def add(kind, src, dst, evidence, confidence="observed"):
        if src == dst or not (0 <= src < n and 0 <= dst < n):
            return
        key = (kind, min(src, dst), max(src, dst), evidence)
        if key in seen or len(rels) >= MAX_RELATIONS:
            return
        seen.add(key)
        rels.append({"src_msg": src, "dst_msg": dst, "kind": kind,
                     "evidence": evidence[:300], "confidence": confidence})

    ids = {}
    for i, m in enumerate(msgs):
        mid = _norm_mid(m.get("message_id") or m.get("messageId"))
        if mid:
            ids[mid] = i
    for i, m in enumerate(msgs):
        for field in ("inReplyTo", "references"):
            raw = str(m.get(field) or "")
            for mid in re.findall(r"<[^>]+>", raw):
                j = ids.get(_norm_mid(mid))
                if j is not None:
                    add("THREAD_REPLY" if field == "inReplyTo" else "THREAD_REF",
                        i, j, f"msg#{i + 1} {field}: {mid}")

    groups = defaultdict(list)

    def grouped(kind, key, idx, label):
        if key:
            groups[(kind, key)].append((idx, label))

    for i, m in enumerate(msgs):
        sender = _addr(m.get("from"))
        grouped("SHARES_SENDER", sender, i, f"From: {m.get('from')}")
        for fld in ("to", "cc", "bcc"):
            val = m.get(fld) or []
            if isinstance(val, str):
                val = re.split(r"[,;]", val)
            for raw in val[:8]:
                grouped("SHARES_RECIPIENT", _addr(raw), i, f"{fld}: {raw}")
        for ip in (m.get("originIPs") or [])[:8]:
            grouped("SHARES_ORIGIN_IP", str(ip), i, f"Received: {ip}")

    for u in (result.get("urls") or [])[:200]:
        if u.get("host"):
            grouped("SHARES_URL", u["host"].lower(), u.get("m", -1),
                    f"URL host: {u.get('url')}")

    for a in (result.get("attachments") or [])[:200]:
        if a.get("sha256"):
            grouped("SHARES_ATTACHMENT", a["sha256"], a.get("m", -1),
                    f"attachment: {a.get('name')} SHA-256 {a['sha256']}")

    for (kind, _key), members in groups.items():
        uniq = list(dict.fromkeys(members))[:MAX_PER_GROUP]
        for x in range(len(uniq)):
            for y in range(x + 1, len(uniq)):
                i, ev1 = uniq[x]
                j, ev2 = uniq[y]
                add(kind, i, j, f"#{i + 1}: {ev1} | #{j + 1}: {ev2}")

    # Time-near là suy luận: chỉ khi cả hai có Date hợp lệ.
    dates = {}
    for i, m in enumerate(msgs):
        try:
            dt = parsedate_to_datetime(str(m.get("date") or ""))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            dates[i] = dt
        except Exception:
            pass
    keys = sorted(dates)
    for x in range(len(keys)):
        for y in range(x + 1, len(keys)):
            i, j = keys[x], keys[y]
            diff = abs((dates[i] - dates[j]).total_seconds())
            if diff <= 900:
                add("TIME_NEAR", i, j,
                    f"Date #{i + 1}={msgs[i].get('date')}; #{j + 1}={msgs[j].get('date')} ({int(diff)}s)",
                    confidence="inference")

    return {"relations": rels, "count": len(rels),
            "byKind": {k: sum(1 for r in rels if r["kind"] == k)
                       for k in sorted({r["kind"] for r in rels})}}


def to_csv(relations: list, case_id: str = "") -> str:
    import csv
    import io
    out = io.StringIO()
    w = csv.writer(out, quoting=csv.QUOTE_ALL)
    w.writerow(["case_id", "src_msg", "dst_msg", "kind", "confidence", "evidence"])
    for r in relations:
        w.writerow([case_id, r.get("src_msg") + 1, r.get("dst_msg") + 1,
                    r.get("kind"), r.get("confidence"), r.get("evidence")])
    return out.getvalue()
