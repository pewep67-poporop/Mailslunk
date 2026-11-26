"""P2 smoke: điều phối nạp file và xuất báo cáo (offline)."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
TMP = tempfile.mkdtemp(prefix="ms_p2_")
os.environ["DATA_DIR"] = TMP

from app.db import init_db                            # noqa: E402
from app.pipeline import iter_dataset, analyze_paths  # noqa: E402
from app.report import render_report                  # noqa: E402

init_db()

EML = (b'From: a@example.com\r\nTo: b@example.com\r\nSubject: test\r\n'
       b'Date: Mon, 10 Nov 2026 10:00:00 +0000\r\nMessage-ID: <1@example.com>\r\n'
       b'MIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nhello\n')


class PipelineTest(unittest.TestCase):
    def test_iter_dataset(self):
        f = Path(TMP) / "a.eml"
        f.write_bytes(EML)
        items = list(iter_dataset([str(f)]))
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0][0], "a.eml")

    def test_analyze_and_render(self):
        f = Path(TMP) / "b.eml"
        f.write_bytes(EML)
        out = analyze_paths([str(f)], user="tester", lang="vi", uid="0" * 32)
        self.assertEqual(len(out["errors"]), 0, out["errors"])
        self.assertEqual(len(out["results"]), 1)
        r = out["results"][0]
        row = {"id": r["custody"]["caseId"], "ts": "2026-01-01 00:00:00 UTC",
               "user": "tester", "file": "b.eml", "sha256": r["custody"]["sha256"]}
        html = render_report(row, r, lang="vi")
        self.assertIn("<html", html)
        self.assertIn(r["custody"]["caseId"], html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
