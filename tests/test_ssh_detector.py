import os
import sys
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
from ssh_detector import parse  # noqa: E402


class TestSSHDetector(unittest.TestCase):
    def test_sample_log(self):
        with open(os.path.join(HERE, "sample_auth.log")) as f:
            failed, users, accepted = parse(f)
        self.assertEqual(failed["203.0.113.5"], 6)
        self.assertEqual(failed["192.0.2.44"], 5)
        self.assertIn("admin", users["203.0.113.5"])
        self.assertIn("bob", accepted["192.0.2.44"])


if __name__ == "__main__":
    unittest.main()
