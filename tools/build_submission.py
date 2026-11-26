#!/usr/bin/env python3
"""Đóng gói nộp bài offline cho 1 case (PDF/HTML/CSV + phụ lục + slide + ZIP).

Ví dụ: python tools/build_submission.py <case_id> ./submission_<case_id>
"""
import csv
import hashlib
import io
import json
import shutil
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.db import connect  # noqa: E402
from app.report import render_report, render_pdf, render_csv  # noqa: E402
from app.relations import to_csv as relations_csv  # noqa: E402
from app.ioc import to_csv as ioc_csv, to_stix as ioc_stix  # noqa: E402
from app import graph  # noqa: E402

LANG = "vi"


def _slide(result: dict, row: dict) -> str:
    verdict = result.get("verdict", "-")
    score = result.get("score", "-")
    findings = result.get("findings") or []
    rels = (result.get("relations") or {}).get("relations") or []
    items = [
        ("Quy trình", "Thu thập & bảo toàn → phân tích offline → timeline → báo cáo → kiến nghị"),
        ("Phát hiện", f"Verdict {verdict}, điểm {score}/100, {len(findings)} findings, {len(rels)} quan hệ"),
        ("Giới hạn", "Không DNS live, không API/reputation; GeoLite2 gần đúng; phần thiếu ghi rõ"),
        ("Kiến nghị", "Cách ly email, xác minh kênh độc lập, tăng cường SPF/DKIM/DMARC, lưu log"),
    ]
    body = "\n".join(f"<section><h2>{k}</h2><p>{v}</p></section>" for k, v in items)
    return ("<!doctype html><html lang='vi'><head><meta charset='utf-8'><title>Slide</title>"
            "<style>section{page-break-after:always;font:18px Arial;padding:40px}</style></head><body>"
            f"<h1>Báo cáo điều tra Email Forensics - {row.get('id')}</h1>{body}</body></html>")


def build(case_id: str, dest: Path) -> Path:
    con = connect()
    row = con.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    con.close()
    if not row:
        raise SystemExit("case_not_found")
    result = json.loads(row["result"] or "{}")
    dest.mkdir(parents=True, exist_ok=True)

    (dest / "report.html").write_text(render_report(dict(row), result, lang=LANG), encoding="utf-8")
    pdf = render_pdf(dict(row), result, lang=LANG)
    if pdf:
        (dest / "report.pdf").write_bytes(pdf)
    (dest / "report.csv").write_text(render_csv(dict(row), result, lang=LANG), encoding="utf-8")
    (dest / "ioc.csv").write_text(ioc_csv((result.get("ioc") or {}).get("iocs") or [], dict(row)), encoding="utf-8")
    (dest / "stix.json").write_text(json.dumps(ioc_stix((result.get("ioc") or {}).get("iocs") or [], dict(row)),
                                              indent=2, ensure_ascii=False), encoding="utf-8")
    (dest / "relations.csv").write_text(relations_csv((result.get("relations") or {}).get("relations") or [], case_id),
                                        encoding="utf-8")
    g = graph.build(result)
    (dest / "graph.svg").write_text(graph.to_svg(g, LANG), encoding="utf-8")
    png = graph.to_png(g, LANG)
    if png:
        (dest / "graph.png").write_bytes(png)
    (dest / "slide.html").write_text(_slide(result, dict(row)), encoding="utf-8")

    tl = result.get("timeline") or []
    with (dest / "timeline.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["case_id", "ts", "source", "event", "confidence"])
        for t in tl:
            w.writerow([case_id] + list(t)[:4])

    hashes = []
    for f in sorted(dest.iterdir()):
        if f.is_file() and f.name != "manifest.sha256":
            hashes.append(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.name}")
    (dest / "manifest.sha256").write_text("\n".join(hashes) + "\n", encoding="utf-8")
    (dest / "README.txt").write_text(
        f"Gói nộp bài offline - case {case_id}\n"
        f"Tạo lúc: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}\n"
        "Đối chiếu manifest.sha256 trước khi nộp. Slide HTML in được ra PDF.", encoding="utf-8")

    zip_path = dest.parent / f"{dest.name}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted(dest.iterdir()):
            if f.is_file():
                z.write(f, f.name)
    print(zip_path)
    return zip_path


if __name__ == "__main__":
    if len(sys.argv) < 3:
        raise SystemExit("usage: build_submission.py <case_id> <out_dir>")
    build(sys.argv[1], Path(sys.argv[2]))
