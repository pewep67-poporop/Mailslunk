#!/usr/bin/env python3
"""Gói bàn giao cho Autopsy/FTK Imager (offline, chỉ đọc).

Các phần không trích được bằng thư viện Python (PST/OST, OLE sâu, carving)
sẽ được điều tra viên mở bằng Autopsy/FTK. Tool này chỉ đóng gói chứng cứ
gốc + manifest SHA-256 + hướng dẫn, không tự chạy GUI.

Ví dụ: python tools/autopsy_handoff.py <case_id> ./handoff/autopsy_<case_id>
"""
import hashlib
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.db import connect, data_dir  # noqa: E402


def main(case_id: str, dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    con = connect()
    row = con.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    con.close()
    if not row:
        raise SystemExit("case_not_found")

    ev = data_dir() / "evidence" / f"{case_id}.bin"
    if ev.is_file():
        shutil.copyfile(ev, dest / "evidence_original.bin")
    (dest / "case.json").write_text(row["result"] or "{}", encoding="utf-8")

    readme = [
        "# Bàn giao Autopsy / FTK Imager",
        f"case_id: {case_id}",
        f"generated_at: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "",
        "1. Đối chiếu SHA-256 trong manifest.sha256 trước khi mở.",
        "2. Mở evidence_original.bin bằng Autopsy/FTK Imager (read-only).",
        "3. Dùng cho: PST/OST, OLE/embedded object sâu, deleted items/carving,",
        "   archive phức tạp, payload cần sandbox tách biệt.",
        "4. Ghi kết quả trích ngược vào bảng kê chứng cứ (evidence_inventory)",
        "   kèm msg_index và hash để hệ thống re-sign.",
        "5. Không gửi dữ liệu ra mạng; không chạy file độc hại trên máy thật.",
    ]
    (dest / "README.md").write_text("\n".join(readme), encoding="utf-8")
    lines = []
    for f in sorted(dest.iterdir()):
        if f.is_file() and f.name != "manifest.sha256":
            lines.append(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.name}")
    (dest / "manifest.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(dest)
    return dest


if __name__ == "__main__":
    if len(sys.argv) < 3:
        raise SystemExit("usage: autopsy_handoff.py <case_id> <out_dir>")
    main(sys.argv[1], Path(sys.argv[2]))
