#!/usr/bin/env python3
"""So khớp SHA-256 của dataset gốc với manifest (CSV/JSON). Offline, chỉ đọc.

Manifest CSV: path,sha256,size   (có header)
Manifest JSON: {"files":[{"path":..., "sha256":..., "size":...}]}

Kết quả: bảng console + report CSV/JSON; exit 0 nếu tất cả OK, exit 1 nếu có sai.

Ví dụ:
  python tools/verify_dataset.py --manifest dataset_manifest.csv \
      --root "D:/Digital Forensics/dataset" --out ./verify_result
"""
import argparse
import csv
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

CHUNK = 1024 * 1024


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def load_manifest(path: Path) -> list:
    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        items = data.get("files", data if isinstance(data, list) else [])
        return [{"path": str(x.get("path") or ""),
                 "sha256": str(x.get("sha256") or "").lower(),
                 "size": x.get("size")} for x in items if isinstance(x, dict)]
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.DictReader(fh))
    out = []
    for r in rows:
        low = {k.lower(): v for k, v in r.items() if k}
        p = low.get("path") or low.get("file") or ""
        if p:
            out.append({"path": p, "sha256": str(low.get("sha256") or "").lower(),
                        "size": low.get("size")})
    return out


def verify(items: list, root: Path) -> list:
    results = []
    for it in items:
        rel = it["path"]
        p = Path(rel)
        if not p.is_absolute():
            p = root / rel
        row = {"path": rel, "expected": it["sha256"], "actual": "",
               "size_ok": "", "status": "", "note": ""}
        try:
            if not p.is_file():
                row["status"] = "MISSING"
            else:
                row["actual"] = sha256_file(p)
                row["status"] = "OK" if row["actual"] == it["sha256"] else "MISMATCH"
                if it.get("size") not in (None, ""):
                    row["size_ok"] = str(p.stat().st_size == int(it["size"]))
        except Exception as e:
            row["status"] = "ERROR"
            row["note"] = f"{type(e).__name__}: {str(e)[:120]}"
        results.append(row)
    return results


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--root", default=".")
    ap.add_argument("--out", default="")
    a = ap.parse_args(argv)

    items = load_manifest(Path(a.manifest))
    if not items:
        print("manifest_empty", file=sys.stderr)
        return 2
    results = verify(items, Path(a.root))
    bad = [r for r in results if r["status"] != "OK"]

    print(f"{'STATUS':10} {'PATH':55} EXPECTED / ACTUAL")
    for r in results:
        print(f"{r['status']:10} {r['path'][:55]:55} {r['expected'][:16]} / {r['actual'][:16]}")
    print(f"{len(results) - len(bad)}/{len(results)} OK")

    if a.out:
        out = Path(a.out)
        out.mkdir(parents=True, exist_ok=True)
        with (out / "verify_result.csv").open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=["path", "expected", "actual", "size_ok", "status", "note"])
            w.writeheader()
            w.writerows(results)
        (out / "verify_result.json").write_text(json.dumps({
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "results": results, "ok": not bad}, indent=2, ensure_ascii=False), encoding="utf-8")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
