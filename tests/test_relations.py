"""P5 test: quan hệ message↔message có evidence."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.relations import build, to_csv   # noqa: E402
from app import graph                     # noqa: E402


RESULT = {
    "messages": [
        {"from": "A <a@example.com>", "to": "b@example.com", "date": "Mon, 10 Nov 2026 10:00:00 +0000",
         "message_id": "<1@example.com>", "originIPs": ["203.0.113.5"]},
        {"from": "A <a@example.com>", "to": "b@example.com", "date": "Mon, 10 Nov 2026 10:05:00 +0000",
         "message_id": "<2@example.com>", "inReplyTo": "<1@example.com>", "originIPs": ["203.0.113.5"]},
    ],
    "urls": [{"url": "https://evil.test/x", "host": "evil.test", "m": 0}],
    "attachments": [{"name": "a.bin", "sha256": "a" * 64, "m": 1}],
    "ipInfo": [{"ip": "203.0.113.5", "geo": {"country": "Vietnam", "location": {"latitude": 21, "longitude": 105}}}],
    "routing": {"hops": [{"idx": 1, "from": "mail.example.com", "by": "mx.test",
                          "ip": "203.0.113.5", "ts": "2026-11-10T10:00:00+00:00", "delayMs": 0}]},
    "relations": {},
}


class RelationTest(unittest.TestCase):
    def setUp(self):
        self.out = build(RESULT)

    def test_thread(self):
        kinds = {r["kind"] for r in self.out["relations"]}
        self.assertIn("THREAD_REPLY", kinds)

    def test_shared(self):
        kinds = {r["kind"] for r in self.out["relations"]}
        self.assertIn("SHARES_SENDER", kinds)
        self.assertIn("SHARES_RECIPIENT", kinds)
        self.assertIn("SHARES_ORIGIN_IP", kinds)

    def test_evidence(self):
        for r in self.out["relations"]:
            self.assertTrue(r["evidence"])
            self.assertIn(r["confidence"], ("observed", "inference"))

    def test_csv(self):
        self.assertIn("src_msg", to_csv(self.out["relations"], "case1"))

    def test_graph(self):
        RESULT["relations"] = self.out
        g = graph.build(RESULT)
        kinds = {n["kind"] for n in g["nodes"]}
        self.assertIn("hop", kinds)
        self.assertIn("geo", kinds)
        png = graph.to_png(g)
        self.assertTrue(png.startswith(b"\x89PNG"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
