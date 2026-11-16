#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PST/OST -> EML extractor for Mailsleuth (pypff/libpff).

Runs under Linux/WSL Python. It deliberately writes one RFC822-ish .eml per
message so the existing Mailsleuth per-message pipeline (headers, SPF/DKIM/
DMARC, URLs, attachments, scoring) can run unchanged.

Usage:
    python3 pst_extract.py INPUT.pst OUTPUT_DIR [--max-msgs N] [--max-bytes N]
                           [--stats PATH]

On Windows the script delegates itself to WSL (paths are translated to
/mnt/<drive>/...). On Linux it re-execs once with PYTHONPATH/LD_LIBRARY_PATH
pointing at a user-local libpff/pypff installation (no root needed).
All diagnostics go to stderr; stdout is reserved for one JSON summary line.
"""
import argparse
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import time


DEFAULT_ROOTS = [
    "/mnt/d/Digital Forensics/DE/pst_tools/root",
    "/mnt/c/Digital Forensics/DE/pst_tools/root",
]
PST_MAGIC = b"!BDN"


def _win_to_wsl_path(p: str) -> str:
    m = re.match(r"^([A-Za-z]):[\\/](.*)$", p or "")
    if m:
        return "/mnt/%s/%s" % (m.group(1).lower(), m.group(2).replace("\\", "/"))
    return (p or "").replace("\\", "/")


def _emit_error(code: str, detail: str = "") -> None:
    print(json.dumps({"error": code, "detail": detail[:300]}), flush=True)


def _maybe_delegate_windows():
    """When launched by Windows Python, re-exec the script inside WSL."""
    if os.name != "nt" or os.getenv("PST_SKIP_WSL_DELEGATE") == "1":
        return
    wsl = shutil.which("wsl.exe") or shutil.which("wsl")
    if not wsl:
        _emit_error("wsl_unavailable", "wsl.exe not found on PATH")
        raise SystemExit(3)
    try:
        probe = subprocess.run([wsl, "-e", "true"], stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=15)
        if probe.returncode != 0:
            raise RuntimeError("WSL returned %d" % probe.returncode)
    except Exception as exc:
        _emit_error("wsl_unavailable", str(exc))
        raise SystemExit(3)
    script = _win_to_wsl_path(os.path.abspath(__file__))
    args = [_win_to_wsl_path(a) if re.match(r"^[A-Za-z]:[\\/]", a) else a
            for a in sys.argv[1:]]
    try:
        # Do NOT exec: a broken WSL can crash with 0xC0000005 and swallow our
        # structured error. subprocess keeps this Python process alive.
        proc = subprocess.run([wsl, "-e", "python3", script] + args,
                              stdin=subprocess.DEVNULL, stderr=subprocess.PIPE)
        if proc.returncode != 0:
            detail = (proc.stderr or b"").decode("utf-8", "replace").strip()
            _emit_error("wsl_failed", detail or "wsl exited %d" % proc.returncode)
            raise SystemExit(3)
        raise SystemExit(0)
    except SystemExit:
        raise
    except Exception as exc:
        _emit_error("wsl_unavailable", str(exc))
        raise SystemExit(3)


def _ensure_libs():
    # Native installation (or an injected test module) needs no bootstrap.
    try:
        if importlib.util.find_spec("pypff") is not None:
            return
    except Exception:
        pass
    roots = [os.environ.get("PST_PYFF_ROOT", "")] + DEFAULT_ROOTS
    for root in roots:
        if not root or not os.path.isdir(root):
            continue
        sp = os.path.join(root, "usr", "lib", "python3", "dist-packages")
        ld = os.path.join(root, "usr", "lib", "x86_64-linux-gnu")
        if not os.path.isdir(sp):
            continue
        cur_path = os.environ.get("PYTHONPATH", "").split(os.pathsep)
        cur_ld = os.environ.get("LD_LIBRARY_PATH", "").split(os.pathsep)
        if sp in cur_path and ld in cur_ld:
            return
        env = os.environ.copy()
        env["PYTHONPATH"] = os.pathsep.join([sp] + [p for p in cur_path if p])
        env["LD_LIBRARY_PATH"] = os.pathsep.join([ld] + [p for p in cur_ld if p])
        os.execve(sys.executable, [sys.executable] + sys.argv, env)
    _emit_error("pypff_not_found", "set PST_PYFF_ROOT to a libpff/pypff root")
    raise SystemExit(4)


def _b(v):
    if v is None:
        return b""
    if isinstance(v, bytes):
        return v
    return str(v).encode("utf-8", "replace")


def _natt(msg):
    """Best-effort attachment count: libpff fails on some items with headers."""
    try:
        return int(msg.get_number_of_attachments() or 0)
    except Exception:
        return 0


def _hdr(hdrs: bytes, name: str) -> str:
    m = re.search(rb"(?im)^" + name.encode() + rb"\s*:\s*(.{0,200})", hdrs or b"")
    return m.group(1).decode("utf-8", "replace").strip() if m else ""


def msg_to_eml(msg, idx: int, folder_path: str) -> bytes:
    """Build a self-contained EML from one libpff message."""
    hdrs = _b(msg.get_transport_headers())
    hdrs = hdrs.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    if not hdrs.strip():
        # Deleted/orphan item without transport headers: synthesise minimal ones.
        from email.utils import format_datetime
        import datetime
        d = _date_of(msg)
        try:
            dt = datetime.datetime.strptime(d[:19], "%Y-%m-%d %H:%M:%S")
            date_s = format_datetime(dt.replace(tzinfo=datetime.timezone.utc))
        except Exception:
            date_s = "Thu, 01 Jan 1970 00:00:00 +0000"
        hdrs = ("From: %s <%s>\r\nTo: (unknown)\r\nSubject: %s\r\nDate: %s\r\n"
                "Message-ID: <pypff-%d@pst.local>\r\n" % (
                    _b(msg.get_sender_name()).decode("utf-8", "replace") or "unknown",
                    "unknown@pst.local",
                    _b(msg.get_subject()).decode("utf-8", "replace") or "(no subject)",
                    date_s,
                    idx,
                )).encode("utf-8", "replace")
    text = _b(msg.get_plain_text_body()).rstrip(b"\x00")
    html = _b(msg.get_html_body()).rstrip(b"\x00")

    # Enrich with provenance so the analyst can trace every extracted message.
    extra = ("X-PST-Folder: %s\r\nX-PST-Message-Index: %d\r\n"
             "X-PST-Attachment-Count: %d\r\n" % (
                 folder_path.replace("\r", " ").replace("\n", " ")[:200],
                 idx, _natt(msg)))
    hdrs = hdrs + extra.encode("utf-8", "replace")

    lowered = hdrs.lower()
    if b"content-type:" in lowered:
        body = text if text.strip() else html
        return hdrs.rstrip(b"\n") + b"\r\n\r\n" + body
    if text.strip() and html.strip():
        boundary = "----pypff-%d" % idx
        head = (b"MIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=\""
                + boundary.encode() + b"\"\r\n")
        body = (b"--" + boundary.encode() + b"\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
                + text + b"\r\n--" + boundary.encode()
                + b"\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" + html
                + b"\r\n--" + boundary.encode() + b"--\r\n")
        return head + hdrs.rstrip(b"\n") + b"\r\n\r\n" + body
    ctype = b"text/html; charset=utf-8" if html.strip() else b"text/plain; charset=utf-8"
    body = html if html.strip() else text
    return (hdrs.rstrip(b"\n") + b"\r\nContent-Type: " + ctype + b"\r\n\r\n" + body)


def _date_of(msg):
    try:
        v = msg.get_delivery_time()
        return v.decode("utf-8", "replace") if isinstance(v, bytes) else str(v or "")
    except Exception:
        return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("output")
    ap.add_argument("--max-msgs", type=int, default=1000)
    ap.add_argument("--max-bytes", type=int, default=200 * 1024 * 1024)
    ap.add_argument("--stats", default="")
    args = ap.parse_args()

    t0 = time.time()
    try:
        with open(args.input, "rb") as fh:
            if fh.read(4) != PST_MAGIC:
                _emit_error("bad_signature", "not a PST/OST (expected !BDN)")
                raise SystemExit(2)
    except OSError as exc:
        _emit_error("input_unreadable", str(exc))
        raise SystemExit(2)
    import pypff  # noqa: E402  (only after lib bootstrap)
    try:
        pst = pypff.file()
        pst.open(args.input)
    except Exception as exc:
        _emit_error("pst_open_failed", str(exc))
        raise SystemExit(4)
    try:
        os.makedirs(args.output, exist_ok=True)
    except OSError as exc:
        _emit_error("output_unwritable", str(exc))
        raise SystemExit(4)
    folder_counts, dates, files = {}, [], []
    state = {"n": 0, "trunc": False, "att": 0, "bytes": 0, "cap_bytes": args.max_bytes}

    def walk(folder, path):
        if state["trunc"]:
            return
        name = _b(folder.get_name()).decode("utf-8", "replace") or "(root)"
        here = (path + "/" + name).strip("/")
        try:
            nmsg = folder.get_number_of_sub_messages() or 0
        except Exception:
            nmsg = 0
        if os.environ.get("PST_DEBUG"):
            sys.stderr.write("WALK %s nmsg=%d state=%s\n" % (here, nmsg, state["n"]))
        for i in range(nmsg):
            if state["n"] >= args.max_msgs or state["bytes"] >= state["cap_bytes"]:
                state["trunc"] = True
                return
            try:
                m = folder.get_sub_message(i)
                data = msg_to_eml(m, state["n"] + 1, here)
                natt = _natt(m)
                d = _date_of(m)
            except Exception as exc:
                if os.environ.get("PST_DEBUG"):
                    sys.stderr.write("  MSG %d skipped: %s\n" % (i, exc))
                continue
            state["n"] += 1
            state["bytes"] += len(data)
            state["att"] += natt
            fn = "%05d.eml" % state["n"]
            try:
                with open(os.path.join(args.output, fn), "wb") as fh:
                    fh.write(data)
            except OSError:
                continue
            files.append(fn)
            folder_counts[here] = folder_counts.get(here, 0) + 1
            if d:
                dates.append(d)
        try:
            nsub = folder.get_number_of_sub_folders() or 0
        except Exception:
            nsub = 0
        for j in range(nsub):
            try:
                walk(folder.get_sub_folder(j), here)
            except Exception as exc:
                sys.stderr.write("pst_extract: subfolder #%d of %s skipped: %s\n" % (j, here, exc))

    root = pst.get_root_folder()
    walk(root, "")
    pst.close()

    stats = {
        "source": os.path.basename(args.input),
        "messages": state["n"],
        "folders": len(folder_counts),
        "folder_counts": folder_counts,
        "attachments": state["att"],
        "eml_bytes": state["bytes"],
        "truncated": state["trunc"],
        "date_min": min(dates) if dates else None,
        "date_max": max(dates) if dates else None,
        "files": files,
        "elapsed_s": round(time.time() - t0, 2),
    }
    if args.stats:
        with open(args.stats, "w", encoding="utf-8") as fh:
            json.dump(stats, fh, ensure_ascii=False, indent=2)
    print(json.dumps({k: stats[k] for k in (
        "source", "messages", "folders", "attachments", "truncated", "elapsed_s")}))


if __name__ == "__main__":
    _maybe_delegate_windows()
    _ensure_libs()
    main()
