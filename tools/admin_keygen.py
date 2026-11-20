#!/usr/bin/env python3
"""Create the administrator credential verifier (offline).

The admin password is never stored. This script derives a 384-bit key with
PBKDF2-HMAC-SHA256 (600,000 rounds) from:

    password  +  SHA-256("mailsleuth-admin-v1|<username>|<CCCD digits>")

Only the salt (a hash of the CCCD, never the CCCD itself), the iteration count
and a SHA-256 verifier of the derived key are written to the database. The
derived key is written once to the file given by --key-out; it can be used as
an alternative login secret if the password is lost.

Examples
--------
    python tools/admin_keygen.py --user admin --cccd 001203004567 \
        --write-db --key-out D:\\keys\\admin.key

    # change the password later (keeps the same CCCD-derived salt)
    python tools/admin_keygen.py --user admin --password \
        --write-db --key-out D:\\keys\\admin.key

The script never prints the password or the key. Run it on the server host,
not on a shared workstation.
"""
import argparse
import getpass
import json
import os
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _ask_password() -> str:
    p1 = getpass.getpass("Admin password (min 10 chars): ")
    p2 = getpass.getpass("Repeat password: ")
    if p1 != p2:
        raise SystemExit("passwords do not match")
    return p1


def main() -> int:
    ap = argparse.ArgumentParser(description="Create/rotate the MailSleuth admin verifier")
    ap.add_argument("--user", default="admin", help="admin username (default: admin)")
    ap.add_argument("--cccd", default="", help="9-12 digit CCCD used as the salt input")
    ap.add_argument("--password", action="store_true", help="prompt for a new password (default when --write-db is used)")
    ap.add_argument("--password-stdin", action="store_true", help="read the password from stdin (automation only)")
    ap.add_argument("--write-db", action="store_true", help="write the verifier to DATA_DIR/app.db")
    ap.add_argument("--db", default="", help="explicit path to app.db (implies --write-db)")
    ap.add_argument("--key-out", default="", help="write the derived recovery key to this file (0600)")
    ap.add_argument("--show-key", action="store_true", help="print the key to stdout (not recommended)")
    ap.add_argument("--iter", type=int, default=0, help="PBKDF2 iterations (default 600000)")
    args = ap.parse_args()

    if args.db:
        os.environ["DATA_DIR"] = str(Path(args.db).resolve().parent)
        args.write_db = True

    from app import auth as A

    # Reuse the existing salt when the account is already enrolled, so a
    # password rotation does not need the CCCD again.
    existing = None
    if args.write_db:
        from app.db import connect, init_db
        init_db()
        con = connect()
        existing = con.execute("SELECT * FROM users WHERE name=? COLLATE NOCASE", (args.user,)).fetchone()
        con.close()
    blob_existing = {}
    if existing is not None and existing["admin_kdf"]:
        try:
            blob_existing = json.loads(existing["admin_kdf"])
        except Exception:
            blob_existing = {}

    password = _ask_password() if (args.password or (args.write_db and not args.password_stdin)) else ""
    if args.password_stdin:
        password = sys.stdin.readline().rstrip("\r\n")
    if not password:
        raise SystemExit("a password is required (use --password or --write-db)")

    if blob_existing and not args.cccd:
        # Rotate with the stored salt.
        try:
            blob = A.admin_rekey(blob_existing, password)
        except ValueError as e:
            raise SystemExit(str(e))
        key = A.ADMIN_KEY_PREFIX + __import__("base64").urlsafe_b64encode(
            A.admin_derive(password, __import__("base64").b64decode(blob["salt"]),
                           int(blob.get("iter") or A.ADMIN_KDF_ITER))).decode("ascii").rstrip("=")
    else:
        if not args.cccd:
            raise SystemExit("--cccd is required for a first-time enrollment")
        try:
            blob, key = A.admin_blob(args.user, password, args.cccd,
                                     args.iter or A.ADMIN_KDF_ITER)
        except ValueError as e:
            raise SystemExit(str(e))

    if args.key_out:
        out = Path(args.key_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            "MailSleuth administrator recovery key\n"
            f"user: {args.user}\n"
            f"created: {datetime.now(timezone.utc).isoformat()}\n"
            "This file is a secret. Keep it offline; delete it after storing it in a safe.\n\n"
            f"{key}\n", encoding="utf-8")
        try:
            os.chmod(out, 0o600)
        except Exception:
            pass
        print(f"key written to {out} (mode 0600 where supported)")
    if args.show_key:
        print(key)

    if args.write_db:
        from app.db import connect
        con = connect()
        if existing is None:
            h = __import__("bcrypt").hashpw(secrets.token_hex(32).encode(),
                                            __import__("bcrypt").gensalt(rounds=12)).decode()
            con.execute("INSERT INTO users(name,hash,role,created,uid,admin_kdf) VALUES(?,?,?,?,?,?)",
                        (args.user, h, "admin", datetime.now(timezone.utc).isoformat(),
                         A.new_uid(), json.dumps(blob)))
        else:
            con.execute("UPDATE users SET role='admin', admin_kdf=?, disabled=0 WHERE id=?",
                        (json.dumps(blob), existing["id"]))
        con.commit()
        con.close()
        print(f"verifier stored for '{args.user}' (PBKDF2-SHA256, {blob['iter']} rounds)")
    else:
        print("verifier not stored (dry run); add --write-db to update the database)")
    print("Login with the password; the key file is an offline recovery secret.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
