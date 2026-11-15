from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Generator, Optional, Union
from dns_detector.models.query import DNSQuery
from dns_detector.parsers.base import BaseParser


class BINDLogParser(BaseParser):
    """
    Parses ISC BIND9 / named query log files.
    """

    # Format 1: 15-Nov-2026 14:02:10.123 client @0x... 192.168.1.50#49201 (sub.domain.com): query: sub.domain.com IN TXT +E (192.168.1.1)
    _REGEX_BIND1 = re.compile(
        r"^(?P<date>\d{2}-\w{3}-\d{4}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
        r"client\s+(?:@\S+\s+)?(?P<client_ip>[^#\s]+)#\d+.*?"
        r":\s*query:\s+(?P<query>\S+)\s+(?P<class>\S+)\s+(?P<qtype>\S+)",
        re.IGNORECASE,
    )

    # Format 2: Nov 15 14:02:10 named[1234]: client 192.168.1.50#54321: query: sub.domain.com IN A +
    _REGEX_BIND2 = re.compile(
        r"^(?P<date>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+named\[\d+\]:\s*"
        r"client\s+(?P<client_ip>[^#\s]+)#\d+.*?"
        r":\s*query:\s+(?P<query>\S+)\s+(?P<class>\S+)\s+(?P<qtype>\S+)",
        re.IGNORECASE,
    )

    def parse(self) -> Generator[DNSQuery, None, None]:
        if not self.filepath.exists():
            raise FileNotFoundError(f"BIND log file not found: {self.filepath}")

        with open(self.filepath, mode="r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                m = self._REGEX_BIND1.match(line) or self._REGEX_BIND2.match(line)
                if not m:
                    continue

                gd = m.groupdict()
                qname = gd.get("query", "").strip()
                if not qname:
                    continue

                qtype = gd.get("qtype", "A").strip().upper()
                client_ip = gd.get("client_ip", "").strip()
                raw_date = gd.get("date", "").strip()

                ts_val = self._parse_date(raw_date)

                yield DNSQuery(
                    query_name=qname,
                    qtype=qtype,
                    timestamp=ts_val,
                    client_ip=client_ip or None,
                    raw_record=line,
                )

    def _parse_date(self, date_str: str) -> Optional[datetime]:
        for fmt in (
            "%d-%b-%Y %H:%M:%S.%f",
            "%d-%b-%Y %H:%M:%S",
            "%b %d %H:%M:%S",
        ):
            try:
                dt = datetime.strptime(date_str, fmt)
                if dt.year == 1900:
                    dt = dt.replace(year=datetime.utcnow().year)
                return dt
            except ValueError:
                continue
        return None
