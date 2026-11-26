"""Index API: bảng thư đầy đủ Message-ID/From/To + phân nhóm."""
import asyncio
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="ms_gidx_")

from app import main as M          # noqa: E402
from app.global_graph import load_index  # noqa: E402

M.require_auth = lambda request: {"role": "admin", "user": "u", "uid": "0" * 32}
ROWS = [{"id": "c1", "result": {"verdict": "suspicious", "score": 60, "messages": [
    {"subject": "S", "from": "a@x.test", "to": ["b@x.test"],
     "date": "Mon, 10 Nov 2025 08:00:00 +0000", "message_id": "<m1@x.test>",
     "originIPs": ["203.0.113.5"]}]}}]
M._GLOBAL_CACHE["index"] = load_index(ROWS)
M._GLOBAL_CACHE["ts"] = 9999999999.0


class IndexTest(unittest.TestCase):
    def test_index(self):
        from starlette.requests import Request
        req = Request({"type": "http", "method": "GET", "path": "/api/graph/index",
                       "headers": [], "query_string": b""})
        out = asyncio.run(M.global_index(req, q="", kind="", offset=0, limit=50))
        self.assertEqual(out["total"], 1)
        self.assertEqual(out["items"][0]["message_id"], "<m1@x.test>")
        self.assertEqual(out["items"][0]["from"], "a@x.test")
        self.assertEqual(out["items"][0]["to"], ["b@x.test"])
        self.assertIn("actors", out["groups"])

    def test_filter(self):
        from starlette.requests import Request
        req = Request({"type": "http", "method": "GET", "path": "/api/graph/index",
                       "headers": [], "query_string": b""})
        out = asyncio.run(M.global_index(req, q="203.0.113.5", kind="ip", offset=0, limit=50))
        self.assertEqual(out["total"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
