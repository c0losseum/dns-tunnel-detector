from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional
from dns_detector.core.entropy import (
    calculate_entropy,
    calculate_metric_entropy,
    analyze_character_distribution,
)
from dns_detector.core.domain_utils import split_domain, DomainParts
from dns_detector.models.query import DNSQuery


@dataclass
class QueryMetrics:
    """Calculated metric features for a given DNS query."""

    query: DNSQuery
    domain_parts: DomainParts
    subdomain: str
    subdomain_length: int
    fqdn_length: int
    label_count: int
    max_label_length: int
    entropy: float
    metric_entropy: float
    char_distribution: Dict[str, float]
    is_base64_like: bool
    is_hex_like: bool
    is_base32_like: bool


# Regular expressions for encoded payload signatures
_BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/=_-]{16,}$")
_HEX_PATTERN = re.compile(r"^[0-9a-fA-F]{16,}$")
_BASE32_PATTERN = re.compile(r"^[A-Z2-7=]{16,}$", re.IGNORECASE)


def extract_metrics(query: DNSQuery) -> QueryMetrics:
    """Extracts all structural, statistical, and lexical metrics from a DNS query."""
    parts = split_domain(query.query_name)
    subdomain = parts.subdomain
    # Strip dots inside the subdomain for entropy & char distribution of the actual payload
    subdomain_payload = subdomain.replace(".", "")

    entropy = calculate_entropy(subdomain_payload)
    metric_entropy = calculate_metric_entropy(subdomain_payload)
    char_dist = analyze_character_distribution(subdomain_payload)

    # Encoding pattern tests on the longest label
    longest_label = max(query.labels) if query.labels else ""
    is_base64 = bool(_BASE64_PATTERN.match(longest_label))
    is_hex = bool(_HEX_PATTERN.match(longest_label)) or (
        char_dist["hex_ratio"] >= 0.85 and len(subdomain_payload) >= 12
    )
    is_base32 = bool(_BASE32_PATTERN.match(longest_label)) and len(longest_label) >= 16

    return QueryMetrics(
        query=query,
        domain_parts=parts,
        subdomain=subdomain,
        subdomain_length=len(subdomain),
        fqdn_length=query.fqdn_length,
        label_count=query.label_count,
        max_label_length=query.max_label_length,
        entropy=entropy,
        metric_entropy=metric_entropy,
        char_distribution=char_dist,
        is_base64_like=is_base64,
        is_hex_like=is_hex,
        is_base32_like=is_base32,
    )
