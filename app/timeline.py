"""Timeline từ dữ liệu có thật trong email (Date + Received), offline.

Mọi event có source_field + confidence. Không có mốc thì ghi unverified,
không suy đoán thời gian từ tên file hay thứ tự file.

Bổ sung: xâu chuỗi các mốc theo THỜI GIAN TỪ ĐẦU ĐẾN CUỐI (UTC),
có STT, delta giữa các mốc, tọa độ GeoIP đã lưu và tổng thời gian trôi.
"""
from __future__ import annotations

from datetime import datetime, timezone
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


def _parse_stored(value):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return _norm_dt(value)


def build(result: dict) -> list:
    events = []

    def add(ts, msg_index, source_field, event, confidence="observed", note="", extra=None):
        e = {"ts": ts or "", "msg_index": msg_index,
             "source_field": source_field, "event": event[:300],
             "confidence": confidence, "note": note[:200]}
        if extra:
            e.update(extra)
        events.append(e)

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

    geo = {}
    for x in (result.get("ipInfo") or []):
        if x.get("ip"):
            g = x.get("geo") or {}
            loc = g.get("location") or {}
            geo[str(x["ip"])] = {
                "country": g.get("country"), "city": g.get("city"),
                "asn": g.get("asn"),
                "lat": loc.get("latitude"), "lon": loc.get("longitude"),
            }

    for h in ((result.get("routing") or {}).get("hops") or [])[:60]:
        ts = str(h.get("ts") or "")
        extra = {}
        ip = str(h.get("ip") or "")
        if ip and ip in geo:
            extra["geo"] = geo[ip]
        if ts:
            add(ts, h.get("m", -1), "Received",
                f"Received hop #{h.get('idx')}: {h.get('from') or '-'} by {h.get('by') or '-'}",
                confidence="observed",
                note=(f"delay {h.get('delayMs')} ms" if h.get("delayMs") is not None else ""),
                extra=extra or None)
        else:
            add("", h.get("m", -1), "Received",
                f"Received hop #{h.get('idx')} không có timestamp",
                confidence="unverified", extra=extra or None)

    # --- Xâu chuỗi theo thời gian từ mốc sớm nhất ---
    events.sort(key=lambda e: (e["ts"] == "", e["ts"], e["msg_index"]))
    prev, total = None, 0.0
    for i, e in enumerate(events, 1):
        e["seq"] = i
        cur = _parse_stored(e.get("ts"))
        if cur is None:
            e["delta_s"] = None
            e["elapsed_s"] = None
            continue
        if prev is not None:
            d = (cur - prev).total_seconds()
            e["delta_s"] = round(d, 3)
            if d >= 0:
                total += d
        else:
            e["delta_s"] = 0.0
        e["elapsed_s"] = round(total, 3)
        prev = cur
    return events


def rechain(events: list) -> list:
    """Gán lại seq/delta_s/elapsed_s cho event CŨ (chưa có các trường này)."""
    if not isinstance(events, list) or not events:
        return events if isinstance(events, list) else []
    events.sort(key=lambda e: (not e.get("ts"), e.get("ts") or "", e.get("msg_index", -1)))
    prev, total = None, 0.0
    for i, e in enumerate(events, 1):
        e["seq"] = i
        cur = _parse_stored(e.get("ts"))
        if cur is None:
            e.setdefault("delta_s", None)
            e.setdefault("elapsed_s", None)
            continue
        if prev is not None:
            d = (cur - prev).total_seconds()
            e["delta_s"] = round(d, 3)
            if d >= 0:
                total += d
        else:
            e["delta_s"] = 0.0
        e["elapsed_s"] = round(total, 3)
        prev = cur
    return events


def chain_summary(events: list) -> dict:
    """Tóm tắt chuỗi thời gian (dùng cho UI/báo cáo)."""
    dated = [e for e in events if e.get("ts")]
    if not dated:
        return {"start": "", "end": "", "events": 0, "span_s": 0, "unverified": len(events)}
    span = 0.0
    if dated[-1].get("elapsed_s") is not None:
        span = float(dated[-1]["elapsed_s"])
    return {"start": dated[0]["ts"], "end": dated[-1]["ts"],
            "events": len(dated), "span_s": round(span, 3),
            "unverified": sum(1 for e in events if not e.get("ts"))}
