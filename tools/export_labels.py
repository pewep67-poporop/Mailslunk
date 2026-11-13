#!/usr/bin/env python3
"""Export internally labelled cases (History) as training samples.

Only cases whose verdict was confirmed by an analyst are exported. The label
source is written into every row (`source="internal"`) so the training report
can distinguish internal labels from public-corpus labels, and heuristic-only
cases are exported with label=-1 (unusable for training, useful for review).

    python tools/export_labels.py --out datasets/features.jsonl
    python tools/export_labels.py --out datasets/features.jsonl --heuristic
"""
import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ.setdefault("LIVE_DNS", "0")

from app.db import connect, data_dir   # noqa: E402
from app.ml_features import extract_features  # noqa: E402
from app.main import feature_source    # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="Export labelled cases for training")
    ap.add_argument("--out", default="datasets/features.jsonl")
    ap.add_argument("--user", default="", help="only this analyst")
    ap.add_argument("--heuristic", action="store_true",
                    help="also export rule-only verdicts (label=-1)")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    con = connect()
    q = "SELECT id, ts, user, file, result FROM cases"
    params = []
    if args.user:
        q += " WHERE user=?"
        params.append(args.user)
    q += " ORDER BY ts DESC"
    if args.limit:
        q += " LIMIT ?"
        params.append(args.limit)
    rows = con.execute(q, params).fetchall()
    con.close()

    kept = 0
    with open(out_path, "a", encoding="utf-8") as fh:
        for r in rows:
            try:
                result = json.loads(r["result"] or "{}")
            except Exception:
                continue
            verdict = str(result.get("verdict") or "")
            label = 1 if verdict == "malicious_or_phishing" else (0 if verdict == "clean" else -1)
            if label == -1 and not args.heuristic:
                continue
            ev = data_dir() / "evidence" / f"{r['id']}.bin"
            if not ev.exists():
                continue
            try:
                raw = ev.read_bytes()
                src = feature_source(r["file"] or f"{r['id']}.eml", raw)
                feats = extract_features(src)
            except Exception:
                continue
            row = {"id": f"internal/{r['id']}", "label": label, "source": "internal",
                   "features": feats}
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
            kept += 1
    print(f"→ {kept} mẫu nội bộ ghi vào {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
