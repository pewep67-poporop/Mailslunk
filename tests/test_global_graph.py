"""Global evidence graph: ai gửi cho ai, từ đâu tới, có evidence."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="ms_gg_")

from app.global_graph import load_index, neighborhood, overview, to_csv  # noqa: E402

ROWS = [
    {"id": "case1", "result": {"verdict": "suspicious", "score": 60, "messages": [
        {"subject": "Invoice", "from": "Alice <alice@example.test>", "to": ["bob@example.test"],
         "date": "Mon, 10 Nov 2025 08:00:00 +0000", "originIPs": ["203.0.113.5"]},
    ], "urls": [{"host": "evil.test"}], "attachments": [{"sha256": "a" * 64}]}},
    {"id": "case2", "result": {"verdict": "clean", "score": 100, "messages": [
        {"subject": "Re", "from": "bob@example.test", "to": ["alice@example.test"],
         "date": "Tue, 11 Nov 2025 08:00:00 +0000", "originIPs": ["203.0.113.5"]},
    ], "urls": [{"host": "evil.test"}], "attachments": [{"sha256": "a" * 64}]}},
]


class GlobalGraphTest(unittest.TestCase):
    def setUp(self):
        self.idx = load_index(ROWS)

    def test_index(self):
        self.assertEqual(len(self.idx["messages"]), 2)
        self.assertIn("alice@example.test", self.idx["actors"])
        self.assertIn("203.0.113.5", self.idx["ips"])
        self.assertIn("evil.test", self.idx["urls"])

    def test_neighborhood_actor(self):
        g = neighborhood(self.idx, "actor:alice@example.test")
        rels = {e["rel"] for e in g["edges"]}
        self.assertIn("SENT", rels)
        self.assertIn("TO", rels)
        self.assertIn("SENT_TO", rels)
        pair = [e for e in g["edges"] if e["rel"] == "SENT_TO"][0]
        self.assertIn("bob@example.test", pair["evidence"])
        self.assertTrue(all(e.get("evidence") for e in g["edges"]))

    def test_neighborhood_ip(self):
        g = neighborhood(self.idx, "ip:203.0.113.5")
        self.assertIn("ORIGIN_IP", {e["rel"] for e in g["edges"]})

    def test_overview(self):
        g = overview(self.idx)
        self.assertTrue(g["nodes"])
        self.assertIn("SENT_TO", {e["rel"] for e in g["edges"]})
        self.assertIn("src", to_csv(g["edges"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
