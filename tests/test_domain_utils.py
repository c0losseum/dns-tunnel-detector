import unittest
from pathlib import Path
import sys

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from dns_detector.core.domain_utils import split_domain


class TestDomainUtils(unittest.TestCase):
    def test_standard_com_domain(self):
        parts = split_domain("sub.example.com")
        self.assertEqual(parts.subdomain, "sub")
        self.assertEqual(parts.domain, "example")
        self.assertEqual(parts.suffix, "com")
        self.assertEqual(parts.registered_domain, "example.com")

    def test_multi_part_suffix_uk(self):
        parts = split_domain("stage1.payload.c2corp.co.uk")
        self.assertEqual(parts.subdomain, "stage1.payload")
        self.assertEqual(parts.domain, "c2corp")
        self.assertEqual(parts.suffix, "co.uk")
        self.assertEqual(parts.registered_domain, "c2corp.co.uk")

    def test_multi_part_suffix_id(self):
        parts = split_domain("exfil.secret.university.ac.id")
        self.assertEqual(parts.subdomain, "exfil.secret")
        self.assertEqual(parts.domain, "university")
        self.assertEqual(parts.suffix, "ac.id")
        self.assertEqual(parts.registered_domain, "university.ac.id")

    def test_root_domain_no_subdomain(self):
        parts = split_domain("google.com")
        self.assertEqual(parts.subdomain, "")
        self.assertEqual(parts.domain, "google")
        self.assertEqual(parts.suffix, "com")
        self.assertEqual(parts.registered_domain, "google.com")

    def test_ip_address_handling(self):
        parts = split_domain("192.168.1.1")
        self.assertEqual(parts.subdomain, "")
        self.assertEqual(parts.registered_domain, "192.168.1.1")


if __name__ == "__main__":
    unittest.main()
