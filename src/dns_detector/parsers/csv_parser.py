from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path
from typing import Generator, Optional, Union
from dns_detector.models.query import DNSQuery
from dns_detector.parsers.base import BaseParser


class CSVLogParser(BaseParser):
    """
    Parses CSV and TSV DNS query logs with intelligent column header auto-detection.
    """

    QUERY_COL_CANDIDATES = ["query", "query_name", "domain", "qname", "name", "host", "fqdn"]
    QTYPE_COL_CANDIDATES = ["qtype", "type", "record_type", "rrtype", "query_type"]
    CLIENT_IP_CANDIDATES = ["client_ip", "client", "src_ip", "src", "source_ip", "id.orig_h"]
    SERVER_IP_CANDIDATES = ["server_ip", "server", "dst_ip", "dst", "dest_ip", "id.resp_h"]
    TIMESTAMP_CANDIDATES = ["timestamp", "time", "ts", "datetime", "date"]
    RCODE_CANDIDATES = ["rcode", "response_code", "status", "rcode_name"]

    def __init__(self, filepath: Union[str, Path], delimiter: Optional[str] = None) -> None:
        super().__init__(filepath)
        self.delimiter = delimiter

    def parse(self) -> Generator[DNSQuery, None, None]:
        if not self.filepath.exists():
            raise FileNotFoundError(f"Log file not found: {self.filepath}")

        with open(self.filepath, mode="r", encoding="utf-8", errors="replace") as f:
            # Sniff delimiter if not specified
            sample = f.read(4096)
            f.seek(0)
            delimiter = self.delimiter
            if not delimiter:
                try:
                    sniffer = csv.Sniffer()
                    dialect = sniffer.sniff(sample)
                    delimiter = dialect.delimiter
                except Exception:
                    delimiter = ","

            reader = csv.DictReader(f, delimiter=delimiter)
            if not reader.fieldnames:
                return

            field_map = self._map_fields(reader.fieldnames)
            query_col = field_map["query"]
            if not query_col:
                raise ValueError(
                    f"Could not automatically detect query domain column in {self.filepath}. "
                    f"Available columns: {reader.fieldnames}"
                )

            for line_no, row in enumerate(reader, start=1):
                raw_query = row.get(query_col, "").strip()
                if not raw_query or raw_query == "-":
                    continue

                qtype = (
                    row.get(field_map["qtype"], "A").strip()
                    if field_map["qtype"]
                    else "A"
                )
                client_ip = (
                    row.get(field_map["client_ip"], "").strip()
                    if field_map["client_ip"]
                    else None
                )
                server_ip = (
                    row.get(field_map["server_ip"], "").strip()
                    if field_map["server_ip"]
                    else None
                )
                rcode = (
                    row.get(field_map["rcode"], "NOERROR").strip()
                    if field_map["rcode"]
                    else "NOERROR"
                )

                timestamp_val = None
                if field_map["timestamp"] and row.get(field_map["timestamp"]):
                    timestamp_val = self._parse_timestamp(row[field_map["timestamp"]])

                yield DNSQuery(
                    query_name=raw_query,
                    qtype=qtype or "A",
                    timestamp=timestamp_val,
                    client_ip=client_ip,
                    server_ip=server_ip,
                    rcode=rcode,
                    raw_record=str(row),
                )

    def _map_fields(self, fieldnames: list[str]) -> dict[str, Optional[str]]:
        lower_map = {fn.strip().lower(): fn for fn in fieldnames}
        res: dict[str, Optional[str]] = {}

        def find_match(candidates: list[str]) -> Optional[str]:
            for cand in candidates:
                if cand in lower_map:
                    return lower_map[cand]
            return None

        res["query"] = find_match(self.QUERY_COL_CANDIDATES)
        res["qtype"] = find_match(self.QTYPE_COL_CANDIDATES)
        res["client_ip"] = find_match(self.CLIENT_IP_CANDIDATES)
        res["server_ip"] = find_match(self.SERVER_IP_CANDIDATES)
        res["timestamp"] = find_match(self.TIMESTAMP_CANDIDATES)
        res["rcode"] = find_match(self.RCODE_CANDIDATES)
        return res

    def _parse_timestamp(self, ts_str: str) -> Optional[datetime]:
        ts_str = ts_str.strip()
        try:
            # Check for epoch timestamp (float or int)
            epoch = float(ts_str)
            return datetime.utcfromtimestamp(epoch)
        except ValueError:
            pass

        # Try ISO formats
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
            "%d/%b/%Y:%H:%M:%S",
        ):
            try:
                return datetime.strptime(ts_str, fmt)
            except ValueError:
                continue
        return None
