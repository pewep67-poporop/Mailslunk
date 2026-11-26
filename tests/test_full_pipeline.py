"""Kiểm chứng toàn bộ luồng: phân tích → trích xuất → xuất báo cáo/dữ liệu."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
TMP = Path(tempfile.mkdtemp(prefix="ms_full_"))
os.environ["DATA_DIR"] = str(TMP)
os.environ["DNS_SNAPSHOT"] = str(TMP / "dns.json")
(TMP / "dns.json").write_text(json.dumps({"generated_at": "2026-01-01T00:00:00Z",
    "sources": [], "records": {"example.com": {"TXT": ["v=spf1 -all"]}}}), encoding="utf-8")

from app.db import init_db, connect          # noqa: E402
init_db()

from app.pipeline import analyze_paths        # noqa: E402
from app.report import render_report, render_pdf, render_csv, case_signature  # noqa: E402
from app.main import _report_parts, _safe_name, _global_index, cases  # noqa: E402
from app.ioc import to_csv as ioc_csv, to_stix  # noqa: E402
from app.urlintel import to_csv as url_csv      # noqa: E402
from app.relations import to_csv as rel_csv     # noqa: E402
from app.global_graph import to_csv as g_csv    # noqa: E402
from app.threatscan import scan_attachment      # noqa: E402

EML = (b'From: a@example.com\r\nTo: b@example.com\r\nSubject: Invoice\r\n'
       b'Date: Mon, 10 Nov 2025 08:00:00 +0000\r\nMessage-ID: <1@example.com>\r\n'
       b'MIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nhello\r\n')
f = TMP / "a.eml"
f.write_bytes(EML)
OUT = analyze_paths([str(f)], user="t", lang="vi", uid="0" * 32)
RESULT = OUT["results"][0]
ROW = {"id": RESULT["custody"]["caseId"], "ts": RESULT["custody"]["utc"],
       "user": "t", "file": "a.eml", "sha256": RESULT["custody"]["sha256"],
       "sig": RESULT["signature"]["sha256"]}


class FullPipelineTest(unittest.TestCase):
    def test_analysis(self):
        self.assertEqual(OUT["errors"], [])
        self.assertTrue(RESULT.get("findings") or RESULT.get("score") is not None)
        self.assertIn("timeline_events", RESULT)
        self.assertTrue(RESULT["signature"]["sha256"])

    def test_report_outputs(self):
        b64, blob, geos = _report_parts(ROW, RESULT, "vi")
        self.assertGreater(len(render_report(ROW, RESULT, lang="vi", sig=ROW["sig"])), 5000)
        self.assertTrue(render_pdf(ROW, RESULT, lang="vi", sig=ROW["sig"]).startswith(b"%PDF"))
        self.assertGreater(len(render_csv(ROW, RESULT, lang="vi")), 100)
        self.assertEqual(len(case_signature(ROW, RESULT)), 64)

    def test_extraction_exports(self):
        self.assertIn("case_id", ioc_csv((RESULT.get("ioc") or {}).get("iocs") or [], ROW))
        self.assertEqual(to_stix([], ROW)["type"], "bundle")
        self.assertIn("url", url_csv([], "vi"))
        self.assertIn("evidence", rel_csv([], ROW["id"]))
        self.assertIn("evidence", g_csv([]))
        self.assertEqual(scan_attachment("a.txt", b"hello", "abc")["findings"], [])

    def test_safe_name_and_index(self):
        self.assertEqual(_safe_name("a/b?c"), "a_b_c")
        idx = _global_index()
        self.assertGreater(idx["messages"]["messages"] if False else len(idx["messages"]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
