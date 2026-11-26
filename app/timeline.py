"""Timeline từ dữ liệu có thật trong email (Date + Received), offline.

Mọi event có source_field + confidence. Không có mốc thì ghi unverified,
không suy đoán thời gian từ tên file hay thứ tự file.
"""
from __future__ import annotations

from datetime import timezone
from email.utils import parsedate_to_datetime


def _norm_dt(value):
    try:
        dt = parsedate_to_datetime(str(value or ""))
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def build(result: dict) -> list:
    events = []

    def add(ts, msg_index, source_field, event, confidence="observed", note=""):
        events.append({"ts": ts or "", "msg_index": msg_index,
                       "source_field": source_field, "event": event[:300],
                       "confidence": confidence, "note": note[:200]})

    for i, m in enumerate(result.get("messages") or []):
        raw_date = str(m.get("date") or "")
        dt = _norm_dt(raw_date)
        if dt:
            add(dt.strftime("%Y-%m-%dT%H:%M:%SZ"), i, "Date",
                f"Message #{i + 1} Date header: {raw_date[:120]}",
                confidence="observed")
        else:
            add("", i, "Date", f"Message #{i + 1} không có Date hợp lệ",
                confidence="unverified", note=raw_date[:120])

    for h in ((result.get("routing") or {}).get("hops") or [])[:60]:
        ts = str(h.get("ts") or "")
        if ts:
            add(ts, h.get("m", -1), "Received",
                f"Received hop #{h.get('idx')}: {h.get('from') or '-'} by {h.get('by') or '-'}",
                confidence="observed",
                note=(f"delay {h.get('delayMs')} ms" if h.get("delayMs") is not None else ""))
        else:
            add("", h.get("m", -1), "Received",
                f"Received hop #{h.get('idx')} không có timestamp",
                confidence="unverified")

    events.sort(key=lambda e: (e["ts"] == "", e["ts"], e["msg_index"]))
    return events
