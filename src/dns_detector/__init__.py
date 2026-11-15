"""
DNS Tunneling & Exfiltration Detector (dnseye)
A high-performance security tool to detect DNS covert channels, data exfiltration,
and tunneling activity using entropy profiling and lexical heuristic analysis.
"""

__title__ = "dns-tunnel-detector"
__version__ = "1.0.0"
__author__ = "Cybersecurity Researcher"
__license__ = "MIT"

from dns_detector.core.engine import DetectionEngine
from dns_detector.core.entropy import calculate_entropy, calculate_metric_entropy
from dns_detector.models.query import DNSQuery
from dns_detector.models.alert import DNSAlert, AlertSeverity

__all__ = [
    "DetectionEngine",
    "calculate_entropy",
    "calculate_metric_entropy",
    "DNSQuery",
    "DNSAlert",
    "AlertSeverity",
]
