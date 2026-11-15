from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from dns_detector.models.query import DNSQuery


class AlertSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def color(self) -> str:
        """ANSI color code for terminal output."""
        return {
            AlertSeverity.INFO: "\033[94m",       # Blue
            AlertSeverity.LOW: "\033[92m",        # Green
            AlertSeverity.MEDIUM: "\033[93m",     # Yellow
            AlertSeverity.HIGH: "\033[38;5;208m", # Orange
            AlertSeverity.CRITICAL: "\033[91m",   # Bright Red
        }.get(self, "\033[0m")

    @property
    def badge(self) -> str:
        return f"[{self.value}]"


@dataclass
class DNSAlert:
    """Security alert raised when suspicious DNS tunneling or exfiltration is detected."""

    query: DNSQuery
    severity: AlertSeverity
    risk_score: float
    base_domain: str
    subdomain: str
    entropy: float
    metric_entropy: float
    subdomain_length: int
    triggered_rules: List[str] = field(default_factory=list)
    indicators: Dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "query_name": self.query.query_name,
            "qtype": self.query.qtype,
            "client_ip": self.query.client_ip,
            "severity": self.severity.value,
            "risk_score": round(self.risk_score, 2),
            "base_domain": self.base_domain,
            "subdomain": self.subdomain,
            "entropy": round(self.entropy, 4),
            "metric_entropy": round(self.metric_entropy, 4),
            "subdomain_length": self.subdomain_length,
            "triggered_rules": self.triggered_rules,
            "indicators": self.indicators,
            "recommendation": self.recommendation,
        }

    def format_summary(self) -> str:
        rules = ", ".join(self.triggered_rules) if self.triggered_rules else "None"
        client = f" | Client: {self.query.client_ip}" if self.query.client_ip else ""
        return (
            f"[{self.severity.value}] Score: {self.risk_score:.1f}/100 | "
            f"Domain: {self.query.query_name} ({self.query.qtype}){client} | "
            f"Entropy: {self.entropy:.3f} | SubLen: {self.subdomain_length} | "
            f"Rules: [{rules}]"
        )
