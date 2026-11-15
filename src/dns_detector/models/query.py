from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class DNSQuery:
    """Represents a normalized DNS query record."""

    query_name: str
    qtype: str = "A"
    timestamp: Optional[datetime] = None
    client_ip: Optional[str] = None
    server_ip: Optional[str] = None
    rcode: Optional[str] = "NOERROR"
    raw_record: Optional[str] = field(default=None, repr=False)

    def __post_init__(self) -> None:
        # Standardize query name: lowercase, strip trailing dot and whitespace
        self.query_name = self.query_name.strip().rstrip(".").lower()
        self.qtype = self.qtype.strip().upper() if self.qtype else "A"

    @property
    def labels(self) -> list[str]:
        """Returns the domain components split by dot."""
        if not self.query_name:
            return []
        return [label for label in self.query_name.split(".") if label]

    @property
    def fqdn_length(self) -> int:
        """Total length of the Fully Qualified Domain Name."""
        return len(self.query_name)

    @property
    def label_count(self) -> int:
        """Count of labels in the domain."""
        return len(self.labels)

    @property
    def max_label_length(self) -> int:
        """Maximum length of any single label in the query."""
        if not self.labels:
            return 0
        return max(len(lbl) for lbl in self.labels)

    def to_dict(self) -> dict:
        return {
            "query_name": self.query_name,
            "qtype": self.qtype,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "client_ip": self.client_ip,
            "server_ip": self.server_ip,
            "rcode": self.rcode,
            "fqdn_length": self.fqdn_length,
            "label_count": self.label_count,
            "max_label_length": self.max_label_length,
        }
