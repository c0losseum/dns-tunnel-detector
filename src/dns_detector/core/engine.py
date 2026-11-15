from __future__ import annotations

import collections
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

from dns_detector.core.domain_utils import split_domain
from dns_detector.core.metrics import extract_metrics, QueryMetrics
from dns_detector.models.alert import DNSAlert, AlertSeverity
from dns_detector.models.query import DNSQuery


DEFAULT_WHITELIST = {
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "apple.com",
    "icloud.com",
    "microsoft.com",
    "windowsupdate.com",
    "azure.com",
    "live.com",
    "office.com",
    "cloudflare.com",
    "cloudflare-dns.com",
    "akamaiedge.net",
    "akadns.net",
    "fastly.net",
    "github.com",
    "githubusercontent.com",
    "aws.amazon.com",
    "amazon.com",
    "digicert.com",
    "letsencrypt.org",
    "quad9.net",
    "opendns.com",
}


@dataclass
class EngineConfig:
    """Configurable heuristics thresholds for detection."""

    entropy_threshold: float = 3.6
    critical_entropy_threshold: float = 4.3
    subdomain_length_threshold: int = 28
    max_label_length_threshold: int = 24
    fqdn_length_threshold: int = 65
    label_count_threshold: int = 4
    min_score_to_alert: float = 45.0
    whitelist: Set[str] = field(default_factory=lambda: set(DEFAULT_WHITELIST))


class DetectionEngine:
    """
    Multi-factor DNS Tunneling and Exfiltration Detection Engine.
    Correlates entropy, lexical anomalies, label dimensions, query types,
    and apex-domain cardinality to score DNS requests.
    """

    def __init__(self, config: Optional[EngineConfig] = None) -> None:
        self.config = config or EngineConfig()
        # Track unique subdomains per registered apex domain
        self.domain_cardinality: Dict[str, Set[str]] = collections.defaultdict(set)
        # Statistics
        self.total_inspected: int = 0
        self.total_alerts: int = 0
        self.alerts_by_severity: Dict[str, int] = collections.defaultdict(int)
        self.domain_alert_counts: Dict[str, int] = collections.defaultdict(int)
        self.client_alert_counts: Dict[str, int] = collections.defaultdict(int)
        self.estimated_exfil_bytes: int = 0

    def add_to_whitelist(self, domain: str) -> None:
        self.config.whitelist.add(domain.strip().lower())

    def is_whitelisted(self, apex_domain: str) -> bool:
        apex_lower = apex_domain.lower()
        if apex_lower in self.config.whitelist:
            return True
        for trusted in self.config.whitelist:
            if apex_lower == trusted or apex_lower.endswith("." + trusted):
                return True
        return False

    def analyze(self, query: DNSQuery) -> Optional[DNSAlert]:
        """
        Analyzes a single DNS query and returns a DNSAlert if suspicious,
        otherwise None.
        """
        self.total_inspected += 1
        metrics = extract_metrics(query)
        apex_domain = metrics.domain_parts.registered_domain or query.query_name

        # Whitelist suppression
        if self.is_whitelisted(apex_domain):
            return None

        # Track apex domain cardinality
        if metrics.subdomain:
            self.domain_cardinality[apex_domain].add(metrics.subdomain)

        unique_subdomains_count = len(self.domain_cardinality[apex_domain])

        # Compute composite risk score
        score, triggered_rules, indicators = self._evaluate_rules(
            metrics, unique_subdomains_count
        )

        if score < self.config.min_score_to_alert:
            return None

        severity = self._determine_severity(score)
        recommendation = self._generate_recommendation(
            severity, apex_domain, query.client_ip, triggered_rules
        )

        alert = DNSAlert(
            query=query,
            severity=severity,
            risk_score=min(score, 100.0),
            base_domain=apex_domain,
            subdomain=metrics.subdomain,
            entropy=metrics.entropy,
            metric_entropy=metrics.metric_entropy,
            subdomain_length=metrics.subdomain_length,
            triggered_rules=triggered_rules,
            indicators=indicators,
            recommendation=recommendation,
            timestamp=query.timestamp or datetime.utcnow(),
        )

        # Update stats
        self.total_alerts += 1
        self.alerts_by_severity[severity.value] += 1
        self.domain_alert_counts[apex_domain] += 1
        if query.client_ip:
            self.client_alert_counts[query.client_ip] += 1
        # Approximate raw exfiltration bytes encoded in subdomain
        self.estimated_exfil_bytes += metrics.subdomain_length

        return alert

    def _evaluate_rules(
        self, metrics: QueryMetrics, unique_subdomains: int
    ) -> Tuple[float, List[str], Dict[str, any]]:
        score = 0.0
        rules: List[str] = []
        indicators: Dict[str, any] = {}

        sub_len = metrics.subdomain_length
        payload_len = len(metrics.subdomain.replace(".", ""))
        entropy = metrics.entropy
        max_label = metrics.max_label_length

        # 1. Entropy Scoring (Up to 32 pts)
        if payload_len >= 10:
            if entropy >= self.config.critical_entropy_threshold:
                score += 32.0
                rules.append(f"CRITICAL_ENTROPY ({entropy:.2f})")
            elif entropy >= self.config.entropy_threshold:
                score += 22.0
                rules.append(f"HIGH_ENTROPY ({entropy:.2f})")
            elif entropy >= 3.2 and sub_len >= 24:
                score += 10.0
                rules.append(f"ELEVATED_ENTROPY ({entropy:.2f})")

        # 2. Subdomain & Label Dimensions (Up to 30 pts)
        if max_label >= 50:
            score += 26.0
            rules.append(f"EXTREME_LABEL_LEN ({max_label} chars)")
        elif max_label >= self.config.max_label_length_threshold:
            score += 16.0
            rules.append(f"LONG_LABEL_LEN ({max_label} chars)")

        if sub_len >= 55:
            score += 18.0
            rules.append(f"EXCESSIVE_SUBDOMAIN_LEN ({sub_len} chars)")
        elif sub_len >= self.config.subdomain_length_threshold:
            score += 10.0
            rules.append(f"LONG_SUBDOMAIN_LEN ({sub_len} chars)")

        if metrics.label_count >= self.config.label_count_threshold and sub_len >= 30:
            score += 8.0
            rules.append(f"DEEP_SUBDOMAIN_NESTING ({metrics.label_count} labels)")

        # 3. Lexical & Encoding Signatures (Up to 24 pts)
        cd = metrics.char_distribution
        if metrics.is_hex_like:
            score += 18.0
            rules.append(f"HEX_ENCODED_PAYLOAD (ratio: {cd['hex_ratio']:.2f})")
        elif metrics.is_base64_like:
            score += 15.0
            rules.append("BASE64_PAYLOAD_SIGNATURE")
        elif metrics.is_base32_like:
            score += 15.0
            rules.append("BASE32_PAYLOAD_SIGNATURE")

        if sub_len >= 18:
            if cd["consonant_ratio"] >= 0.75:
                score += 10.0
                rules.append(f"CONSONANT_DENSITY ({cd['consonant_ratio']:.2f})")
            if cd["max_consecutive_consonants"] >= 7:
                score += 8.0
                rules.append(f"CONSECUTIVE_CONSONANTS ({cd['max_consecutive_consonants']})")
            if cd["digit_ratio"] >= 0.40:
                score += 8.0
                rules.append(f"NUMERIC_DENSITY ({cd['digit_ratio']:.2f})")

        # 4. Query Type Heuristics (Up to 15 pts)
        qtype = metrics.query.qtype
        if qtype == "TXT" and sub_len >= 20:
            score += 15.0
            rules.append("TXT_TUNNEL_CHANNEL")
        elif qtype in ("NULL", "CNAME") and sub_len >= 25:
            score += 12.0
            rules.append(f"{qtype}_OVERSIZED_QUERY")
        elif qtype in ("A", "AAAA") and sub_len >= 40 and entropy >= 3.6:
            score += 8.0
            rules.append(f"{qtype}_EXFIL_PAYLOAD")

        # 5. Volume & Apex-Domain Cardinality (Up to 20 pts)
        if unique_subdomains >= 25:
            score += 20.0
            rules.append(f"HIGH_DOMAIN_CARDINALITY ({unique_subdomains} unique subs)")
        elif unique_subdomains >= 10:
            score += 10.0
            rules.append(f"ELEVATED_DOMAIN_CARDINALITY ({unique_subdomains} unique subs)")

        indicators["entropy"] = round(entropy, 4)
        indicators["metric_entropy"] = round(metrics.metric_entropy, 4)
        indicators["subdomain_length"] = sub_len
        indicators["max_label_length"] = max_label
        indicators["label_count"] = metrics.label_count
        indicators["hex_ratio"] = round(cd["hex_ratio"], 3)
        indicators["digit_ratio"] = round(cd["digit_ratio"], 3)
        indicators["unique_subdomains_seen"] = unique_subdomains

        return score, rules, indicators

    def _determine_severity(self, score: float) -> AlertSeverity:
        if score >= 85.0:
            return AlertSeverity.CRITICAL
        elif score >= 70.0:
            return AlertSeverity.HIGH
        elif score >= 45.0:
            return AlertSeverity.MEDIUM
        elif score >= 25.0:
            return AlertSeverity.LOW
        return AlertSeverity.INFO

    def _generate_recommendation(
        self, severity: AlertSeverity, domain: str, client_ip: Optional[str], rules: List[str]
    ) -> str:
        ip_str = f"on host {client_ip}" if client_ip else "on internal endpoints"
        if severity == AlertSeverity.CRITICAL:
            return (
                f"CRITICAL: Immediate incident response required. Isolate {ip_str}. "
                f"Block domain '{domain}' on DNS firewall/RPZ. Dump network memory and inspect "
                f"active sockets for C2 frameworks (dnscat2, Cobalt Strike, Iodine)."
            )
        elif severity == AlertSeverity.HIGH:
            return (
                f"HIGH: Investigate process spawning DNS queries {ip_str}. "
                f"Add '{domain}' to DNS monitoring blacklist and audit host egress logs."
            )
        elif severity == AlertSeverity.MEDIUM:
            return (
                f"MEDIUM: Monitor query frequency to '{domain}'. Verify if domain belongs to "
                f"a legitimate CDN or telemetry service."
            )
        return f"LOW: Log event for baseline correlation."

    def get_summary(self) -> Dict[str, any]:
        return {
            "total_queries_inspected": self.total_inspected,
            "total_alerts": self.total_alerts,
            "alerts_by_severity": dict(self.alerts_by_severity),
            "top_suspicious_domains": sorted(
                self.domain_alert_counts.items(), key=lambda x: x[1], reverse=True
            )[:10],
            "top_suspicious_clients": sorted(
                self.client_alert_counts.items(), key=lambda x: x[1], reverse=True
            )[:10],
            "estimated_exfiltrated_bytes": self.estimated_exfil_bytes,
        }
