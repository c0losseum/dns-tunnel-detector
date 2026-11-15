from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Generator, List, Optional, Union
from dns_detector.models.query import DNSQuery
from dns_detector.parsers.base import BaseParser


class ZeekDNSLogParser(BaseParser):
    """
    Parses native TSV-formatted Zeek/Bro 'dns.log' files.
    Dynamically identifies column positions via '#fields' directive.
    """

    def parse(self) -> Generator[DNSQuery, None, None]:
        if not self.filepath.exists():
            raise FileNotFoundError(f"Zeek log file not found: {self.filepath}")

        fields: List[str] = []
        separator = "\t"

        with open(self.filepath, mode="r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\r\n")
                if not line:
                    continue

                # Header directives
                if line.startswith("#separator"):
                    # e.g. #separator \x09
                    parts = line.split()
                    if len(parts) >= 2 and "\\x09" in parts[1]:
                        separator = "\t"
                    continue

                if line.startswith("#fields"):
                    fields = line.split()[1:]
                    continue

                if line.startswith("#"):
                    # Other comment or metadata line
                    continue

                if not fields:
                    continue

                values = line.split(separator)
                if len(values) < len(fields):
                    continue

                row = dict(zip(fields, values))
                query_name = row.get("query", "-")
                if not query_name or query_name == "-":
                    continue

                qtype = row.get("qtype_name") or row.get("qtype", "A")
                if qtype == "-":
                    qtype = "A"

                orig_h = row.get("id.orig_h")
                client_ip = orig_h if orig_h != "-" else None

                resp_h = row.get("id.resp_h")
                server_ip = resp_h if resp_h != "-" else None

                rcode = row.get("rcode_name") or row.get("rcode", "NOERROR")
                if rcode == "-":
                    rcode = "NOERROR"

                ts_val = None
                raw_ts = row.get("ts", "-")
                if raw_ts != "-":
                    try:
                        ts_val = datetime.utcfromtimestamp(float(raw_ts))
                    except ValueError:
                        pass

                yield DNSQuery(
                    query_name=query_name,
                    qtype=qtype,
                    timestamp=ts_val,
                    client_ip=client_ip,
                    server_ip=server_ip,
                    rcode=rcode,
                    raw_record=line,
                )
