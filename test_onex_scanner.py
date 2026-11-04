import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from onex.core.edge_scanner import load_onex_repo_ips  # noqa: E402


def make_root(lines):
    tmp = tempfile.TemporaryDirectory()
    base = Path(tmp.name)
    (base / "onex_repo").mkdir()
    (base / "onex_repo" / "ips.txt").write_text("\n".join(lines), encoding="utf-8")
    return tmp, base


class OnexRepoIpsTest(unittest.TestCase):
    def test_keeps_only_unique_ipv4(self):
        tmp, base = make_root(["1.1.1.1", "1.1.1.1", "example.ir", "2001:db8::1", "8.8.8.8", ""])
        self.addCleanup(tmp.cleanup)
        got = [h for h, _ in load_onex_repo_ips(base, 10, "full")]
        self.assertEqual(got, ["1.1.1.1", "8.8.8.8"])

    def test_sample_is_capped_and_unique(self):
        tmp, base = make_root([f"10.0.{i // 256}.{i % 256}" for i in range(1000)])
        self.addCleanup(tmp.cleanup)
        got = load_onex_repo_ips(base, 50, "sample")
        self.assertEqual(len(got), 50)
        self.assertEqual(len({h for h, _ in got}), 50)
        self.assertTrue(all(p == 443 for _, p in got))

    def test_full_is_deterministic(self):
        tmp, base = make_root([f"10.0.{i // 256}.{i % 256}" for i in range(1000)])
        self.addCleanup(tmp.cleanup)
        a = load_onex_repo_ips(base, 20, "full")
        b = load_onex_repo_ips(base, 20, "full")
        self.assertEqual(a, b)
        self.assertEqual(len(a), 20)

    def test_missing_file_returns_empty(self):
        self.assertEqual(load_onex_repo_ips(Path("/nonexistent-onex-root"), 10), [])


if __name__ == "__main__":
    unittest.main()
