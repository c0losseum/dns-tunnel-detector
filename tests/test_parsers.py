import tempfile
import unittest
from pathlib import Path
import sys

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from dns_detector.parsers.csv_parser import CSVLogParser
from dns_detector.parsers.json_parser import JSONLogParser
from dns_detector.parsers.zeek_parser import ZeekDNSLogParser
from dns_detector.parsers.bind_parser import BINDLogParser


class TestParsers(unittest.TestCase):
    def test_csv_parser(self):
        content = (
            "timestamp,client_ip,query,qtype\n"
            "2026-11-15 10:00:00,192.168.1.10,example.com,A\n"
            "2026-11-15 10:00:01,192.168.1.20,malicious.payload.net,TXT\n"
        )
        with tempfile.NamedTemporaryFile("w+", suffix=".csv", delete=False) as f:
            f.write(content)
            tmp_path = Path(f.name)

        try:
            parser = CSVLogParser(tmp_path)
            records = list(parser.parse())
            self.assertEqual(len(records), 2)
            self.assertEqual(records[0].query_name, "example.com")
            self.assertEqual(records[0].client_ip, "192.168.1.10")
            self.assertEqual(records[1].qtype, "TXT")
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_json_lines_parser(self):
        content = (
            '{"timestamp": 1700000000, "client_ip": "10.0.0.5", "query_name": "cdn.test.org", "qtype": "A"}\n'
            '{"event_type": "dns", "src_ip": "10.0.0.9", "dns": {"rrname": "secret.tunnel.io", "rrtype": "TXT"}}\n'
        )
        with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False) as f:
            f.write(content)
            tmp_path = Path(f.name)

        try:
            parser = JSONLogParser(tmp_path)
            records = list(parser.parse())
            self.assertEqual(len(records), 2)
            self.assertEqual(records[0].query_name, "cdn.test.org")
            self.assertEqual(records[1].query_name, "secret.tunnel.io")
            self.assertEqual(records[1].qtype, "TXT")
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_zeek_parser(self):
        content = (
            "#separator \\x09\n"
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id\tquery\tqtype_name\n"
            "1700000000.123\tC12345\t192.168.1.55\t53123\t8.8.8.8\t53\tudp\t1001\tbeacon.c2.org\tA\n"
        )
        with tempfile.NamedTemporaryFile("w+", suffix=".log", delete=False) as f:
            f.write(content)
            tmp_path = Path(f.name)

        try:
            parser = ZeekDNSLogParser(tmp_path)
            records = list(parser.parse())
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].query_name, "beacon.c2.org")
            self.assertEqual(records[0].client_ip, "192.168.1.55")
            self.assertEqual(records[0].qtype, "A")
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_bind_parser(self):
        content = (
            "15-Nov-2026 14:02:10.123 client @0x7f8 192.168.1.50#49201 (secretdata.tunnel.exfil.org): "
            "query: secretdata.tunnel.exfil.org IN TXT +E (192.168.1.1)\n"
        )
        with tempfile.NamedTemporaryFile("w+", suffix=".log", delete=False) as f:
            f.write(content)
            tmp_path = Path(f.name)

        try:
            parser = BINDLogParser(tmp_path)
            records = list(parser.parse())
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].query_name, "secretdata.tunnel.exfil.org")
            self.assertEqual(records[0].client_ip, "192.168.1.50")
            self.assertEqual(records[0].qtype, "TXT")
        finally:
            tmp_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
