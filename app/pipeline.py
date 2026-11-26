"""Mỏng điều phối: nạp dataset → gọi lõi phân tích → trả kết quả/báo cáo.

Không chứa logic chấm điểm hay rule; mọi quyết định nằm ở analysis/ và app/*.py.
Không thực hiện auth/CSRF (do API layer đảm nhiệm).
"""
from __future__ import annotations

import os
from pathlib import Path

ALLOWED = {".eml", ".emlx", ".msg", ".mbox", ".mbx", ".txt", ".mht", ".mhtml"}
MAX_BYTES = int(os.getenv("MSG_FILE_MAX", str(80 * 1024 * 1024)) or 80 * 1024 * 1024)


def iter_dataset(paths):
    """-> iterator of (display_name, source_path). Chỉ đọc local."""
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            for f in sorted(p.rglob("*")):
                if f.is_file() and f.suffix.lower() in ALLOWED:
                    yield str(f.relative_to(p)), str(f)
        elif p.is_file() and p.suffix.lower() in ALLOWED:
            yield p.name, str(p)


def analyze_paths(paths, user: str = "", lang: str = "en",
                  platform: str = "auto", uid: str = "") -> dict:
    """Điều phối hàng loạt file. Trả {"results": [...], "errors": [...]}."""
    from .main import _analyze_one  # lazy: tránh import vòng

    results, errors = [], []
    for name, src in iter_dataset(paths):
        try:
            size = os.path.getsize(src)
            if size > MAX_BYTES:
                errors.append({"file": name, "error": "too_large"})
                continue
            with open(src, "rb") as fh:
                data = fh.read()
            result, err = _analyze_one(name, data, user, None, platform, lang, uid)
            if err:
                errors.append({"file": name, "error": str(err)[:200]})
            else:
                results.append(result)
        except Exception as e:
            errors.append({"file": name, "error": f"{type(e).__name__}: {str(e)[:160]}"})
    return {"results": results, "errors": errors}


def render(result: dict, row: dict, lang: str = "en") -> dict:
    """Xuất báo cáo từ kết quả đã có (không tính lại)."""
    from .report import render_csv, render_pdf, render_report, case_signature

    sig = result.get("signature", {}).get("sha256") or case_signature(row, result)
    return {
        "html": render_report(row, result, lang=lang, sig=sig),
        "pdf": render_pdf(row, result, lang=lang, sig=sig),
        "csv": render_csv(row, result, lang=lang),
    }
