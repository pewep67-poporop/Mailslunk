#!/usr/bin/env python3
"""MailSleuth — purge forensic traces (data hygiene).

Everything the server writes to disk can contain mail content:
    DATA_DIR/evidence/<case>.bin     raw uploaded mail (read-only copy)
    DATA_DIR/quarantine/<sha>_<name> malware samples kept for triage
    DATA_DIR/messages/<case>/        extracted body text + sanitised HTML
    DATA_DIR/uploads/*.bin           upload staging files (should never survive)
    /tmp/ms-pst-*, /tmp/ms-mbox-*    parser scratch dirs
    __pycache__                     code caches (no content, but noise)

This tool removes them by age (retention) or explicitly, writes an audit
record of what it deleted and refuses to touch anything outside DATA_DIR.

Usage
    python tools/purge.py --dry-run                 # report only
    python tools/purge.py --apply --days 30        # delete traces older than 30 days
    python tools/purge.py --apply --case <id>      # one case (evidence+body)
    python tools/purge.py --apply --staging        # leftover upload staging files
    python tools/purge.py --apply --all            # everything (ask --yes)
"""
import argparse
import json
import os
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.db import data_dir, connect, log  # noqa: E402


def _size(p: Path) -> int:
    try:
        if p.is_file():
            return p.stat().st_size
        return sum(f.stat().st_size for f in p.rglob("*") if f.is_file())
    except OSError:
        return 0


def _older_than(p: Path, days: int) -> bool:
    try:
        return (time.time() - p.stat().st_mtime) > days * 86400
    except OSError:
        return False


def _safe(path: Path) -> bool:
    """Never delete outside DATA_DIR (and only regular files / dirs)."""
    try:
        base = data_dir().resolve()
        tgt = path.resolve()
        if tgt == base:
            return False
        return base in tgt.parents or tgt.parent == base
    except OSError:
        return False


def collect(days: int, case_id: str = "", staging: bool = False, all_: bool = False) -> list:
    """-> list of (path, kind)"""
    out = []
    d = data_dir()
    # 1. evidence
    for p in sorted((d / "evidence").glob("*")):
        if not p.is_file():
            continue
        if case_id and not p.name.startswith(case_id):
            continue
        if (days or all_) and (all_ or _older_than(p, days)):
            out.append((p, "evidence"))
    # 2. quarantine
    for p in sorted((d / "quarantine").glob("*")):
        if not p.is_file():
            continue
        if case_id and case_id not in p.name:
            continue
        if (days or all_) and (all_ or _older_than(p, days)):
            out.append((p, "quarantine"))
    # 3. message bodies
    mdir = d / "messages"
    if mdir.is_dir():
        for case in sorted(mdir.iterdir()):
            if not case.is_dir():
                continue
            if case_id and case.name != case_id:
                continue
            if (days or all_) and (all_ or _older_than(case, days)):
                out.append((case, "messages"))
    # 4. upload staging leftovers (always: they must never survive)
    up = d / "uploads"
    if up.is_dir():
        for p in sorted(up.glob("*")):
            if p.is_file() and (staging or all_ or _older_than(p, 0)):
                out.append((p, "uploads"))
    # 5. parser scratch dirs in the system temp folder
    tmp = Path(os.getenv("TEMP") or os.getenv("TMPDIR") or "/tmp")
    for pat in ("ms-pst-*", "ms-mbox-*"):
        for p in tmp.glob(pat):
            if p.is_dir() and (staging or all_ or _older_than(p, 0)):
                out.append((p, "scratch"))
    return out


def apply_deletions(items: list, dry: bool) -> dict:
    removed = {"files": 0, "dirs": 0, "bytes": 0, "items": []}
    for p, kind in items:
        if not _safe(p):
            continue
        size = _size(p)
        if not dry:
            try:
                if p.is_dir():
                    shutil.rmtree(p, ignore_errors=True)
                    removed["dirs"] += 1
                else:
                    p.unlink()
                    removed["files"] += 1
            except OSError as e:
                continue
        removed["bytes"] += size
        removed["items"].append({"path": str(p), "kind": kind, "bytes": size})
    return removed


def main() -> int:
    ap = argparse.ArgumentParser(description="Purge forensic traces")
    ap.add_argument("--days", type=int, default=0, help="delete traces older than N days")
    ap.add_argument("--case", default="", help="delete one case id")
    ap.add_argument("--staging", action="store_true", help="only leftover upload/scratch files")
    ap.add_argument("--all", action="store_true", help="delete every trace")
    ap.add_argument("--dry-run", action="store_true", help="report only (default)")
    ap.add_argument("--apply", action="store_true", help="really delete")
    ap.add_argument("--yes", action="store_true", help="confirm --all")
    args = ap.parse_args()
    dry = not args.apply
    if args.all and not args.yes:
        print("!! --all needs --yes (it deletes every stored trace)")
        return 2

    items = collect(args.days, args.case, args.staging, args.all)
    if not items:
        print("Không có dấu vết nào để xoá." if dry else "Nothing to purge.")
        return 0
    total = sum(_size(p) for p, _ in items)
    print(("DRY-RUN: " if dry else "DELETE: ") + f"{len(items)} mục, {total/1e6:.2f} MB")
    for p, kind in items[:40]:
        print(f"  {kind:11} {p}")
    if len(items) > 40:
        print(f"  ... và {len(items)-40} mục nữa")
    res = apply_deletions(items, dry)
    # audit record (what happened, never the content)
    report = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "dryRun": dry, "files": res["files"], "dirs": res["dirs"],
              "bytes": res["bytes"], "items": res["items"][:500]}
    try:
        out_dir = data_dir() / "purge-logs"
        out_dir.mkdir(parents=True, exist_ok=True)
        name = out_dir / (report["ts"].replace(":", "-") + ".json")
        name.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
        try:
            log("system", "purge", f"dry={dry} files={res['files']} dirs={res['dirs']} bytes={res['bytes']}")
        except Exception:
            pass
    except Exception:
        pass
    print(f"→ {'đã lập kế hoạch xoá' if dry else 'đã xoá'}: {res['files']} tệp, {res['dirs']} thư mục, {res['bytes']/1e6:.2f} MB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
