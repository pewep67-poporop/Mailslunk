"""P8/P9 test: gói Autopsy + gói nộp bài offline."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
TMP = Path(tempfile.mkdtemp(prefix="ms_p9_"))
os.environ["DATA_DIR"] = str(TMP)

from app.db import connect, init_db  # noqa: E402

init_db()
CID = "submission1"
RESULT = {"custody": {"caseId": CID, "sha256": "a" * 64}, "verdict": "suspicious",
          "score": 70, "count": 1, "format": "eml", "platform": "auto", "findings": [],
          "urls": [], "attachments": [], "ipInfo": [], "dns": {}, "ioc": {},
          "auth": {}, "headerAnalysis": {"checks": [], "receivedCount": 0},
          "routing": {"hops": [], "anomalies": [], "totalDelayMs": 0}, "relations": {}}
con = connect()
con.execute("INSERT OR REPLACE INTO cases(id,ts,user,file,sha256,result,sig,uid) VALUES(?,?,?,?,?,?,?,?)",
            (CID, "2026-01-01", "tester", "a.eml", "a" * 64,
             json.dumps(RESULT), "sig", "0" * 32))
con.commit()
con.close()


class SubmissionTest(unittest.TestCase):
    def test_autopsy(self):
        out = TMP / "autopsy"
        env = dict(os.environ)
        env["DATA_DIR"] = str(TMP)
        r = subprocess.run([sys.executable, str(ROOT / "tools" / "autopsy_handoff.py"),
                            CID, str(out)], capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue((out / "manifest.sha256").is_file())
        self.assertTrue((out / "README.md").is_file())

    def test_submission_zip(self):
        out = TMP / "sub"
        env = dict(os.environ)
        env["DATA_DIR"] = str(TMP)
        r = subprocess.run([sys.executable, str(ROOT / "tools" / "build_submission.py"),
                            CID, str(out)], capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue((out / "report.html").is_file())
        self.assertTrue((out / "report.pdf").is_file())
        self.assertTrue((out / "slide.html").is_file())
        self.assertTrue((TMP / "sub.zip").is_file())


if __name__ == "__main__":
    unittest.main(verbosity=2)
