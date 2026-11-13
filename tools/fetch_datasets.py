#!/usr/bin/env python3
"""Download public email corpora for training (with provenance + licence log).

Only sources that are reachable without an account are supported by default;
each download is recorded in `datasets/SOURCES.json` (url, sha256, licence,
sample count) so the model card can cite it.

    python tools/fetch_datasets.py --list
    python tools/fetch_datasets.py --source spamassassin --out datasets/raw
    python tools/fetch_datasets.py --source spamassassin --out datasets/raw --apply
"""
import argparse
import hashlib
import json
import os
import sys
import tarfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SOURCES = {
    "spamassassin": {
        "url": "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2",
        "license": "Apache-2.0 (SpamAssassin public corpus)",
        "kind": "ham", "note": "thư hợp lệ, raw .eml có header",
        "url2": "https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2",
        "kind2": "spam",
    },
    "meajor": {
        "url": "https://zenodo.org/records/18471483/files/meajor_cleaned_preprocessed.parquet.gzip",
        "license": "CC-BY-4.0 (DOI 10.5281/zenodo.18471483)",
        "kind": "mixed", "note": "108.685 mẫu, preprocessed (text + label), KHÔNG có header",
    },
    "phishing-zenodo": {
        "url": "https://zenodo.org/records/17314806/files/Balanced_Dataset.csv",
        "license": "CC-BY-4.0 (DOI 10.5281/zenodo.17314806)",
        "kind": "mixed", "note": "gộp 9 corpus, CSV, có header? cần kiểm tra",
    },
}


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(url: str, dest: Path, timeout: int = 180) -> bool:
    import requests
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        with requests.get(url, stream=True, timeout=timeout,
                          headers={"User-Agent": "mailsleuth-dataset-fetch/1.0"}) as r:
            if not r.ok:
                print(f"  ! HTTP {r.status_code} cho {url}")
                return False
            total = 0
            with open(dest, "wb") as fh:
                for chunk in r.iter_content(1 << 20):
                    if chunk:
                        fh.write(chunk)
                        total += len(chunk)
            print(f"  → {dest.name} ({total/1e6:.1f} MB)")
            return True
    except Exception as e:
        print(f"  ! lỗi tải {url}: {type(e).__name__}: {e}")
        return False


def extract_archives(path: Path, out: Path) -> int:
    n = 0
    for p in sorted(path.parent.glob(path.name.replace(".tar.bz2", "").replace(".tar.gz", "") + "*")):
        pass
    for p in sorted(path.parent.iterdir()):
        if p.is_dir() or p.suffix not in (".bz2", ".gz"):
            continue
        try:
            with tarfile.open(p, "r:*") as tf:
                tf.extractall(out)
            n += 1
        except Exception as e:
            print(f"  ! giải nén {p.name} lỗi: {e}")
    return n


def main() -> int:
    ap = argparse.ArgumentParser(description="Fetch public email corpora")
    ap.add_argument("--source", default="", help="source name (default: all)")
    ap.add_argument("--out", default="datasets/raw")
    ap.add_argument("--apply", action="store_true", help="really download (default: dry-run)")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    if args.list:
        for name, s in SOURCES.items():
            print(f"{name:16} {s['license']}\n{'':16} {s['url']}")
            if s.get("url2"):
                print(f"{'':16} {s['url2']}")
        return 0

    out = Path(args.out)
    names = [args.source] if args.source else list(SOURCES)
    for name in names:
        s = SOURCES.get(name)
        if not s:
            print("nguồn không hợp lệ:", name)
            return 2
        print(f"[{name}] {s['license']}")
        for key in ("url", "url2"):
            url = s.get(key)
            if not url:
                continue
            fn = url.rsplit("/", 1)[-1]
            dest = out / fn
            if dest.exists():
                print(f"  = đã có {fn} (bỏ qua)")
                continue
            if not args.apply:
                print(f"  (dry-run) sẽ tải {url}")
                continue
            if fetch(url, dest):
                print(f"    sha256 {sha256(dest)[:16]}…")
                _record(out, name, url, dest, s)
        if args.apply and name == "spamassassin":
            extract_archives(out / "20030228_easy_ham.tar.bz2", out)
            extract_archives(out / "20030228_spam.tar.bz2", out)
    if args.apply:
        print(f"\n→ dữ liệu ở {out} (nguồn & giấy phép: {out/'SOURCES.json'})")
    return 0


def _record(out: Path, name: str, url: str, dest: Path, meta: dict):
    rec = out / "SOURCES.json"
    data = {}
    if rec.exists():
        try:
            data = json.loads(rec.read_text(encoding="utf-8"))
        except Exception:
            data = {}
    data.setdefault(name, []).append({
        "url": url, "file": dest.name, "sha256": sha256(dest),
        "license": meta.get("license"), "kind": meta.get("kind"),
        "note": meta.get("note"), "downloadedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })
    rec.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
