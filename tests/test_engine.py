import unittest
from pathlib import Path
import sys

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from dns_detector.core.engine import DetectionEngine, EngineConfig
from dns_detector.models.query import DNSQuery
from dns_detector.models.alert import AlertSeverity


class TestDetectionEngine(unittest.TestCase):
    def setUp(self):
        self.engine = DetectionEngine()

    def test_benign_queries_not_alerted(self):
        benign_queries = [
            DNSQuery(query_name="www.google.com", qtype="A"),
            DNSQuery(query_name="api.github.com", qtype="A"),
            DNSQuery(query_name="mail.proton.me", qtype="MX"),
            DNSQuery(query_name="update.microsoft.com", qtype="A"),
        ]
        for q in benign_queries:
            alert = self.engine.analyze(q)
            self.assertIsNone(alert, f"Benign query falsely alerted: {q.query_name}")

    def test_tunneling_hex_payload(self):
        # 60 characters hex payload typical of Iodine / Cobalt Strike
        hex_tunnel = (
            "4a7b2c9e1d8f3a5b6c0e2f4a8b1c3d5e7f9a0b2c4d6e8f0a2b4c6d8e.tunnel.badactor.org"
        )
        query = DNSQuery(query_name=hex_tunnel, qtype="A", client_ip="10.0.0.45")
        alert = self.engine.analyze(query)

        self.assertIsNotNone(alert, "Hex tunneling payload was not detected")
        self.assertIn(alert.severity, (AlertSeverity.HIGH, AlertSeverity.CRITICAL))
        self.assertGreaterEqual(alert.risk_score, 70.0)
        self.assertTrue(any("HEX_ENCODED" in r for r in alert.triggered_rules))

    def test_txt_tunneling_channel(self):
        # Base64-like payload sent to TXT record
        txt_query = (
            "vKj81nLm9pQs3tUvWxYz0123456789AbCdEfGhIjKlMnOp.c2.tunnelattacker.net"
        )
        query = DNSQuery(query_name=txt_query, qtype="TXT", client_ip="10.0.0.50")
        alert = self.engine.analyze(query)

        self.assertIsNotNone(alert, "TXT tunneling channel was not detected")
        self.assertGreaterEqual(alert.risk_score, 60.0)
        self.assertTrue(any("TXT_TUNNEL_CHANNEL" in r for r in alert.triggered_rules))

    def test_whitelist_suppression(self):
        engine = DetectionEngine(config=EngineConfig(whitelist={"legitcorp.com"}))
        # Even with high entropy subdomain, whitelisted apex domains shouldn't trigger
        query = DNSQuery(
            query_name="a98f12c34d56e78b90fa.legitcorp.com", qtype="A"
        )
        alert = engine.analyze(query)
        self.assertIsNone(alert, "Whitelisted apex domain was not suppressed")

    def test_domain_cardinality_escalation(self):
        # Multiple distinct high-entropy queries to the same apex domain should elevate score
        engine = DetectionEngine()
        apex = "exfil-c2.org"
        last_alert = None
        for i in range(30):
            qname = f"chunk{i:03d}f89e1a2b3c4d5e6f7a8b9c0d.{apex}"
            alert = engine.analyze(DNSQuery(query_name=qname, qtype="A"))
            if alert:
                last_alert = alert

        self.assertIsNotNone(last_alert)
        self.assertTrue(
            any("CARDINALITY" in r for r in last_alert.triggered_rules),
            "Cardinality rule was not triggered after 30 unique subdomains",
        )


if __name__ == "__main__":
    unittest.main()
