#!/usr/bin/env python3
"""Turn a labelled corpus into training samples (features.jsonl).

Reads raw messages (.eml / .mbox) from a directory, runs the *same* analysis
modules the server uses, and writes one JSON object per message:

    {"id": "<corpus>/<file>", "label": 1|0, "source": "<corpus>", "features": {...}}

Labels come from
  * a labels.csv next to the corpus ("filename,label") — 1 = phishing, 0 = benign
  * or the directory layout  <corpus>/phishing/…  and  <corpus>/benign/…

No mail content leaves this machine: only the numeric feature vector is written.
"""
import argparse
import csv
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ.setdefault("LIVE_DNS", "0")   # offline features -> stable distribution

from app.main import feature_source          # noqa: E402
from app.ml_features import extract_features  # noqa: E402


def load_labels(csv_path: Path) -> dict:
    out = {}
    if not csv_path.exists():
        return out
    with open(csv_path, encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            name = str(row.get("filename") or row.get("file") or row.get("name") or "").strip()
            lbl = str(row.get("label") or "").strip().lower()
            if not name:
                continue
            if lbl in ("1", "phishing", "malicious", "spam"):
                out[name] = 1
            elif lbl in ("0", "benign", "clean", "ham", "legit"):
                out[name] = 0
    return out


def iter_messages(corpus: Path):
    """-> (path, label|None, group) — group = the sub-folder the label came from."""
    labels = load_labels(corpus / "labels.csv")
    for p in sorted(corpus.rglob("*")):
        if not p.is_file():
            continue
        if p.suffix.lower() not in (".eml", ".mbox", ".msg", ".txt"):
            continue
        rel = str(p.relative_to(corpus))
        lbl = labels.get(p.name)
        group = corpus.name
        if lbl is None:
            lbl = labels.get(rel)
        if lbl is None:
            parts = [x.lower() for x in p.parts]
            if "phishing" in parts or "malicious" in parts or "spam" in parts:
                lbl = 1
            elif "benign" in parts or "ham" in parts or "legit" in parts or "clean" in parts:
                lbl = 0
        if lbl is not None:
            # the label came from the folder layout -> that folder is the group
            parent = p.parent.relative_to(corpus).parts
            if parent:
                group = f"{corpus.name}/{'/'.join(parent)}"
        yield p, lbl, group


def main() -> int:
    ap = argparse.ArgumentParser(description="Build ML training samples")
    ap.add_argument("--corpus", required=True, help="directory with the labelled corpus")
    ap.add_argument("--out", default="datasets/features.jsonl")
    ap.add_argument("--limit", type=int, default=0, help="max messages per corpus")
    ap.add_argument("--source", default="", help="source name (default: corpus dir name)")
    ap.add_argument("--skip-unlabelled", action="store_true")
    args = ap.parse_args()

    corpus = Path(args.corpus)
    if not corpus.is_dir():
        print("!! corpus không tồn tại:", corpus)
        return 2
    source = args.source or corpus.name
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    n = 0
    kept = 0
    with open(out_path, "a", encoding="utf-8") as fh:
        for p, lbl, group in iter_messages(corpus):
            n += 1
            if args.limit and kept >= args.limit:
                break
            if lbl is None:
                if args.skip_unlabelled:
                    continue
                lbl = -1                     # unknown -> not usable for training
            try:
                raw = p.read_bytes()
                src = feature_source(p.name, raw)
                feats = extract_features(src)
            except Exception as e:
                print(f"  ! bỏ qua {p.name}: {type(e).__name__}")
                continue
            row = {"id": f"{source}/{p.relative_to(corpus)}", "label": int(lbl),
                   "source": group, "features": feats}
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
            kept += 1
            if kept % 500 == 0:
                print(f"  ... {kept} mẫu")
    print(f"→ {kept} mẫu ghi vào {out_path} (quét {n} tệp, nguồn={source})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
