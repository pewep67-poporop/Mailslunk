"""Timeline từ mốc thời gian quá khứ trong email."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="ms_tl_")

from app.timeline import build            # noqa: E402
from app.report import render_report      # noqa: E402

ROW = {"id": "tl1", "ts": "2026-01-01", "user": "u", "file": "a.eml", "sha256": "a" * 64}
RESULT = {
    "custody": {"caseId": "tl1", "sha256": "a" * 64},
    "verdict": "clean", "score": 100, "count": 1, "format": "eml", "platform": "auto",
    "findings": [], "urls": [], "attachments": [], "ipInfo": [], "dns": {}, "ioc": {},
    "auth": {}, "headerAnalysis": {"checks": [], "receivedCount": 1},
    "messages": [{"date": "Mon, 10 Nov 2025 08:30:00 +0700", "from": "a@x.test"}],
    "routing": {"hops": [{"idx": 1, "ts": "2025-11-10T01:31:00+00:00",
                          "from": "h1", "by": "mx"}], "anomalies": [], "totalDelayMs": 0},
    "relations": {},
}


class TimelineTest(unittest.TestCase):
    def test_past_date_extracted(self):
        events = build(RESULT)
        self.assertTrue(any(e["source_field"] == "Date" and "2025-11-10" in e["ts"] for e in events))
        self.assertTrue(any(e["source_field"] == "Received" for e in events))
        self.assertTrue(all(e["confidence"] in ("observed", "unverified") for e in events))

    def test_chain(self):
        RESULT["timeline_events"] = build(RESULT)
        from app.timeline import chain_summary
        s = chain_summary(RESULT["timeline_events"])
        self.assertEqual(s["events"], 2)
        self.assertTrue(s["start"])
        ev = RESULT["timeline_events"][0]
        self.assertEqual(ev["seq"], 1)
        self.assertIn("delta_s", ev)
        self.assertIn("elapsed_s", ev)

    def test_report_shows_past_date(self):
        RESULT["timeline_events"] = build(RESULT)
        html = render_report(ROW, RESULT, lang="en")
        self.assertIn("2025-11-10", html)
        self.assertIn("Date", html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
