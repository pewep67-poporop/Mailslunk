"""P7 test: báo cáo forensic mở rộng + chữ ký phiên."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="ms_p7_")

from app.report import render_report, render_pdf, render_csv, case_signature  # noqa: E402
from app.main import _report_parts  # noqa: E402

ROW = {"id": "case1", "ts": "2026-01-01 00:00:00 UTC", "user": "tester",
       "file": "a.eml", "sha256": "a" * 64}
RESULT = {
    "custody": {"caseId": "case1", "sha256": "a" * 64},
    "verdict": "suspicious", "score": 70, "count": 1, "format": "eml",
    "platform": "auto", "findings": [{"id": "H-001", "type": "test", "sev": 2}],
    "urls": [], "attachments": [], "ipInfo": [], "dns": {}, "ioc": {},
    "auth": {"spf": {"result": "not_run"}, "dkim": {"result": "pass"}, "dmarc": {"result": "fail"}},
    "headerAnalysis": {"checks": [], "receivedCount": 1},
    "routing": {"hops": [{"idx": 1, "ts": "2026-01-01T00:00:00Z", "from": "h", "by": "m"}], "anomalies": [], "totalDelayMs": 0},
    "relations": {"relations": [{"src_msg": 0, "dst_msg": 0, "kind": "SHARES_SENDER",
                                 "confidence": "observed", "evidence": "From a@x"}]},
    "session_fingerprint": "b" * 64, "signed_at": "2026-01-01 00:00:01 UTC",
}


class ReportTest(unittest.TestCase):
    def test_html_sections(self):
        html = render_report(ROW, RESULT, lang="vi")
        for needle in ("Mục lục", "Timeline sự kiện", "Phân loại nhận định",
                       "Ứng phó", "Phụ lục", "Hash phiên", "b" * 20):
            self.assertIn(needle, html, needle)

    def test_pdf(self):
        data = render_pdf(ROW, RESULT, lang="en")
        self.assertTrue(data.startswith(b"%PDF"))
        self.assertGreater(len(data), 1000)

    def test_report_parts_and_csv(self):
        b64, blob, geos = _report_parts(ROW, RESULT, "en")
        self.assertEqual(b64, "")
        self.assertEqual(blob, b"")
        self.assertGreater(len(render_csv(ROW, RESULT, lang="en")), 50)

    def test_signature_session_bound(self):
        plain = case_signature(ROW, dict(RESULT, session_fingerprint="", signed_at=""))
        bound = case_signature(ROW, RESULT)
        self.assertNotEqual(plain, bound)


if __name__ == "__main__":
    unittest.main(verbosity=2)
