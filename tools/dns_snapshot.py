#!/usr/bin/env python3
"""Tạo snapshot DNS local từ zone file (dnspython) hoặc JSON có sẵn.

Không thực hiện truy vấn mạng. Output: data/dns_snapshot.json dùng bởi app/dns_local.py.

Ví dụ:
  python tools/dns_snapshot.py --zone snapshot.zone --origin example.com \
      --out data/dns_snapshot.json
"""
import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import dns.name
import dns.rdatatype
import dns.zone


def zone_to_records(path: str, origin: str) -> dict:
    z = dns.zone.from_file(path, origin=dns.name.from_text(origin), relativize=False)
    records = {}
    for name, rdataset in z.iterate_rdatasets():
        n = name.to_text().lower().rstrip(".")
        rdt = dns.rdatatype.to_text(rdataset.rdtype)
        values = []
        for rdata in rdataset:
            if hasattr(rdata, "strings"):
                values.append("".join(p.decode("utf-8", "ignore") for p in rdata.strings))
            else:
                values.append(rdata.to_text().rstrip("."))
        records.setdefault(n, {}).setdefault(rdt, []).extend(values)
    return records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zone", action="append", default=[])
    ap.add_argument("--origin", action="append", default=[])
    ap.add_argument("--json", action="append", default=[])
    ap.add_argument("--out", default="data/dns_snapshot.json")
    a = ap.parse_args()

    records, sources = {}, []
    for i, zone in enumerate(a.zone):
        origin = a.origin[i] if i < len(a.origin) else (a.origin[0] if a.origin else "")
        if not origin:
            raise SystemExit("--origin is required for each --zone")
        data = Path(zone).read_bytes()
        recs = zone_to_records(zone, origin)
        for n, types in recs.items():
            records.setdefault(n, {}).update(types)
        sources.append({"file": str(zone), "origin": origin,
                        "sha256": hashlib.sha256(data).hexdigest()})

    for jf in a.json:
        data = Path(jf).read_bytes()
        loaded = json.loads(data.decode("utf-8"))
        for n, types in (loaded.get("records") or {}).items():
            records.setdefault(n.lower().rstrip("."), {}).update(types)
        sources.append({"file": str(jf),
                        "sha256": hashlib.sha256(data).hexdigest()})

    out = {"generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "sources": sources, "records": records}
    dest = Path(a.out)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"snapshot written: {dest} ({len(records)} names)")


if __name__ == "__main__":
    main()
