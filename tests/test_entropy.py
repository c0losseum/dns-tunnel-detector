import math
import unittest
from pathlib import Path
import sys

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from dns_detector.core.entropy import (
    calculate_entropy,
    calculate_metric_entropy,
    analyze_character_distribution,
)


class TestEntropyCalculations(unittest.TestCase):
    def test_empty_string(self):
        self.assertEqual(calculate_entropy(""), 0.0)
        self.assertEqual(calculate_metric_entropy(""), 0.0)

    def test_uniform_string(self):
        # A string with identical characters has 0 entropy
        self.assertEqual(calculate_entropy("aaaaaaa"), 0.0)

    def test_two_equal_characters(self):
        # Equal distribution of two characters has entropy of log2(2) = 1.0
        self.assertAlmostEqual(calculate_entropy("abababab"), 1.0, places=5)

    def test_high_entropy_random_payload(self):
        # High randomness hex string
        hex_data = "4a7b2c9e1d8f3a5b6c0e2f4a8b1c3d5e"
        ent = calculate_entropy(hex_data)
        self.assertGreater(ent, 3.5)

    def test_benign_subdomain_entropy(self):
        # Common English/benign subdomains have low entropy
        mail_ent = calculate_entropy("mail")
        login_ent = calculate_entropy("login")
        self.assertLess(mail_ent, 3.0)
        self.assertLess(login_ent, 3.0)

    def test_character_distribution(self):
        dist = analyze_character_distribution("abcdef012345")
        self.assertEqual(dist["length"], 12)
        self.assertEqual(dist["hex_ratio"], 1.0)
        self.assertAlmostEqual(dist["digit_ratio"], 6 / 12)

    def test_consecutive_consonants(self):
        dist = analyze_character_distribution("bcdfghjkl")
        self.assertEqual(dist["max_consecutive_consonants"], 9)
        self.assertEqual(dist["vowel_ratio"], 0.0)


if __name__ == "__main__":
    unittest.main()
