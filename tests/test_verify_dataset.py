"""P4 test: đối chiếu SHA-256 dataset gốc."""
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class VerifyDatasetTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ms_p4_"))
        self.f = self.tmp / "a.eml"
        self.f.write_bytes(b"From: a@x.test\r\n\r\nhello\r\n")
        self.sha = hashlib.sha256(self.f.read_bytes()).hexdigest()

    def _manifest(self, sha, name="manifest.json"):
        p = self.tmp / name
        p.write_text(json.dumps({"files": [{"path": self.f.name,
                                            "sha256": sha,
                                            "size": self.f.stat().st_size}]}), encoding="utf-8")
        return p

    def test_ok(self):
        m = self._manifest(self.sha)
        r = subprocess.run([sys.executable, str(ROOT / "tools" / "verify_dataset.py"),
                            "--manifest", str(m), "--root", str(self.tmp),
                            "--out", str(self.tmp / "out")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("1/1 OK", r.stdout)
        self.assertTrue((self.tmp / "out" / "verify_result.json").is_file())

    def test_mismatch(self):
        m = self._manifest("0" * 64, "bad.json")
        r = subprocess.run([sys.executable, str(ROOT / "tools" / "verify_dataset.py"),
                            "--manifest", str(m), "--root", str(self.tmp)],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("MISMATCH", r.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
