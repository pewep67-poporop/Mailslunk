"""Dashboard đếm thật từ DB, không bị cap 500 như /api/cases."""
import asyncio
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="ms_count_")

from app import main as M          # noqa: E402
from app.db import connect, init_db  # noqa: E402

init_db()
con = connect()
for i in range(600):
    result = json.dumps({"count": 1, "verdict": "suspicious" if i else "malicious_or_phishing"})
    con.execute("INSERT OR REPLACE INTO cases(id,ts,user,file,sha256,result,sig,uid) VALUES(?,?,?,?,?,?,?,?)",
                (f"c{i:04d}", "2026-01-01", "u", f"{i}.eml", "a" * 64, result, "sig", "0" * 32))
con.commit()
con.close()

M.require_auth = lambda request: {"role": "admin", "user": "u", "uid": "0" * 32}


class CountTest(unittest.TestCase):
    def test_count_endpoint(self):
        scope = {"type": "http", "method": "GET", "path": "/api/cases/count",
                 "headers": [], "query_string": b""}
        req = M.Request(scope)
        out = asyncio.run(M.cases_count(req))
        self.assertEqual(out["cases"], 600)
        self.assertEqual(out["messages"], 600)
        self.assertEqual(out["bad"], 1)
        self.assertEqual(out["warn"], 599)


if __name__ == "__main__":
    unittest.main(verbosity=2)
