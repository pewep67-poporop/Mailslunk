#!/usr/bin/env python3
"""Xuất gói bàn giao SPF/DKIM/DMARC/DNS cho tool phân tích local khác.

Không gọi API. Mọi file trong gói được ghi hash vào manifest.sha256.

Ví dụ:
  python tools/auth_dns_export.py <case_id> ./handoff/<case_id>
"""
import csv
import hashlib
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.db import connect, data_dir  # noqa: E402
from app import dns_local            # noqa: E402


def _write(path: Path, text: str):
    path.write_text(text, encoding="utf-8")


def export(case_id: str, dest: Path) -> Path:
    con = connect()
    row = con.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    con.close()
    if not row:
        raise SystemExit("case_not_found")
    result = json.loads(row["result"] or "{}")
    dest.mkdir(parents=True, exist_ok=True)

    auth = result.get("auth") or {}
    _write(dest / "auth_summary.json", json.dumps(auth, indent=2, ensure_ascii=False))
    with (dest / "auth_summary.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["mechanism", "result", "reason", "source"])
        for k in ("spf", "dkim", "dmarc"):
            a = auth.get(k) or {}
            w.writerow([k.upper(), a.get("result") or "-",
                        a.get("reason") or "-", "header-results"])
    _write(dest / "dns_snapshot.json", json.dumps(dns_local.snapshot(), indent=2, ensure_ascii=False))
    _write(dest / "dns_status.json", json.dumps(dns_local.source_info(), indent=2, ensure_ascii=False))

    with (dest / "dns_evidence.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["case_id", "msg_index", "type", "value", "source"])
        for i, ip in enumerate(result.get("originIPs") or []):
            w.writerow([case_id, i, "origin_ip", ip, "Received"])
        for i, x in enumerate(result.get("ipInfo") or []):
            g = x.get("geo") or {}
            loc = g.get("location") or {}
            w.writerow([case_id, i, "geo",
                        f"{loc.get('latitude')},{loc.get('longitude')}", "GeoLite2 local"])
            w.writerow([case_id, i, "ptr", ";".join(x.get("ptr") or []), "local-snapshot"])

    ev = data_dir() / "evidence" / f"{case_id}.bin"
    if ev.is_file():
        shutil.copyfile(ev, dest / "evidence_raw.bin")

    lines = ["# Gói bàn giao xác thực/DNS (offline)",
             f"case_id: {case_id}",
             f"generated_at: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
             "",
             "Không gọi API. Dùng tool local (vd: spfquery, opendkim-testkey, dig@127.0.0.1)",
             "và đối chiếu hash trong manifest.sha256 trước khi phân tích.", ""]
    for k in ("spf_record.txt", "dmarc_record.txt"):
        recs = []
        if k.startswith("spf"):
            recs = (dns_local.snapshot()["records"].get(auth.get("fromDomain", "").lower()) or {}).get("TXT", [])
        else:
            dom = auth.get("fromDomain", "").lower()
            recs = (dns_local.snapshot()["records"].get(f"_dmarc.{dom}") or {}).get("TXT", [])
        _write(dest / k, "\n".join(recs))
        lines.append(f"- {k}: {len(recs)} record(s)")
    _write(dest / "README.md", "\n".join(lines))

    hashes = []
    for f in sorted(dest.iterdir()):
        if f.name == "manifest.sha256" or not f.is_file():
            continue
        h = hashlib.sha256(f.read_bytes()).hexdigest()
        hashes.append(f"{h}  {f.name}")
    _write(dest / "manifest.sha256", "\n".join(hashes) + "\n")
    print(dest)
    return dest


if __name__ == "__main__":
    if len(sys.argv) < 3:
        raise SystemExit("usage: auth_dns_export.py <case_id> <out_dir>")
    export(sys.argv[1], Path(sys.argv[2]))
