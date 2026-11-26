"""P6 test: schema pháp chứng + re-sign theo phiên."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="ms_p6_")

from app.db import connect, init_db           # noqa: E402
from app.main import _resign_case              # noqa: E402
from app.report import case_signature          # noqa: E402

init_db()
TABLES = ["case_meta", "evidence_inventory", "custody_events", "timeline_events",
          "assessments", "response_actions", "screenshots", "team_assignment"]


class ForensicApiTest(unittest.TestCase):
    def setUp(self):
        self.cid = "testcase123"
        self.uid = "0" * 32
        con = connect()
        con.execute("INSERT OR REPLACE INTO cases(id,ts,user,file,sha256,result,sig,uid) VALUES(?,?,?,?,?,?,?,?)",
                    (self.cid, "2026-01-01", "tester", "a.eml", "a" * 64, "{}", "", self.uid))
        con.commit()
        con.close()

    def test_tables(self):
        con = connect()
        names = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        con.close()
        for t in TABLES:
            self.assertIn(t, names)

    def test_insert_and_resign(self):
        con = connect()
        con.execute("INSERT INTO custody_events(case_id,uid,ts,actor,action,source) VALUES(?,?,?,?,?,?)",
                    (self.cid, self.uid, "2026-01-01T00:00:00Z", "tester", "acquired", "dataset"))
        con.commit()
        con.close()
        result = {"custody": {"caseId": self.cid, "sha256": "a" * 64},
                  "verdict": "suspicious", "score": 70, "findings": []}
        plain = case_signature({"id": self.cid, "sha256": "a" * 64}, result)
        out = _resign_case({"sid": "session-secret", "uid": self.uid}, self.cid, result)
        self.assertEqual(len(out["session_fingerprint"]), 64)
        self.assertTrue(out["signed_at"])
        self.assertNotEqual(out["signature"]["sha256"], plain)
        con = connect()
        row = con.execute("SELECT sig,result FROM cases WHERE id=?", (self.cid,)).fetchone()
        con.close()
        self.assertEqual(row["sig"], out["signature"]["sha256"])
        self.assertIn("session_fingerprint", row["result"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
