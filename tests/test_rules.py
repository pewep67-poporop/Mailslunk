"""Unit tests cho lớp rule offline (P1) - không dùng mạng."""
import io
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="ms_p1_"))

from analysis import rules                      # noqa: E402
from app.urls import analyze_url                 # noqa: E402
from app.threatscan import scan_attachment       # noqa: E402


class UrlRulesTest(unittest.TestCase):
    def test_rules_load(self):
        self.assertIn("url", rules.load())
        self.assertIn("executable_ext", rules.url_rules())

    def test_raw_ip(self):
        r = analyze_url("http://203.0.113.5/login.php")
        self.assertEqual(r["host"], "203.0.113.5")
        self.assertIn("host is a raw IP address", r["reasons"])
        self.assertEqual(r["verdict"], "malicious")

    def test_executable_download(self):
        r = analyze_url("https://example.com/files/setup.exe")
        self.assertTrue(any("executable download" in x for x in r["reasons"]))

    def test_punycode(self):
        r = analyze_url("https://xn--80ak6aa92e.com/")
        self.assertTrue(any("punycode" in x for x in r["reasons"]))

    def test_clean(self):
        r = analyze_url("https://example.com/docs/readme.html")
        self.assertEqual(r["verdict"], "clean")
        self.assertEqual(r["reasons"], [])

    def test_no_brand_guess(self):
        # Không được tự đoán thương hiệu/host giống brand.
        r = analyze_url("https://paypa1-secure.example.com/invoice")
        self.assertEqual(r["verdict"], "clean")


class ThreatScanTest(unittest.TestCase):
    def test_clean_text(self):
        out = scan_attachment("note.txt", b"hello world, plain text", "abc")
        self.assertEqual(out["findings"], [])

    def test_pdf_active_keys(self):
        data = b"%PDF-1.4\n/JavaScript /OpenAction /JS <<>>\n"
        out = scan_attachment("doc.pdf", data, "def")
        self.assertTrue(any("PDF active" in f["reason"] for f in out["findings"]))

    def test_html_form_action(self):
        data = b"<html><body><form action='https://evil.test/x'></form><script>x</script></body></html>"
        out = scan_attachment("page.html", data, "ghi")
        self.assertTrue(any("form posts to remote" in f["reason"] for f in out["findings"]))

    def test_zip_traversal(self):
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w") as z:
            z.writestr("../../etc/passwd", "x" * 100)
        out = scan_attachment("a.zip", bio.getvalue(), "jkl")
        self.assertTrue(any("traversal" in f["reason"] for f in out["findings"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
