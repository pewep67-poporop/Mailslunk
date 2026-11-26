"""P3 test: DNS/snapshot offline (không resolver mạng)."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
TMP = Path(tempfile.mkdtemp(prefix="ms_p3_"))
SNAP = TMP / "dns_snapshot.json"
SNAP.write_text(json.dumps({"generated_at": "2026-01-01T00:00:00Z", "sources": [],
    "records": {
        "example.com": {"A": ["93.184.216.34"], "MX": ["10 mail.example.com."],
                        "TXT": ["v=spf1 ip4:203.0.113.5 -all"]},
        "_dmarc.example.com": {"TXT": ["v=DMARC1; p=reject"]},
        "s1._domainkey.example.com": {"TXT": ["v=DKIM1; k=rsa; p=TESTKEY"]},
        "34.216.184.93.in-addr.arpa": {"PTR": ["mail.example.com."]}
    }}), encoding="utf-8")
os.environ["DNS_SNAPSHOT"] = str(SNAP)

from app import dns_local  # noqa: E402


class DnsLocalTest(unittest.TestCase):
    def test_source(self):
        self.assertTrue(dns_local.source_info()["available"])

    def test_lookup_auth(self):
        out = dns_local.lookup_auth("example.com")
        self.assertTrue(out["auth"]["spf"]["found"])
        self.assertEqual(out["auth"]["dmarc"]["policy"], "reject")
        self.assertEqual(out["source"], "local-snapshot")

    def test_dnsfunc(self):
        self.assertIn("v=spf1", dns_local.dnsfunc("example.com", "TXT"))

    def test_ptr(self):
        out = dns_local.reverse_ptr("93.184.216.34")
        self.assertEqual(out["names"], ["mail.example.com."])

    def test_missing(self):
        recs, errs = dns_local._resolve("none.test", "TXT")
        self.assertEqual(recs, [])
        self.assertEqual(errs[0]["code"], "not_run")


if __name__ == "__main__":
    unittest.main(verbosity=2)
