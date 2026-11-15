from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Generator, Optional, Union, Any, Dict
from dns_detector.models.query import DNSQuery
from dns_detector.parsers.base import BaseParser


class JSONLogParser(BaseParser):
    """
    Parses JSON array and Line-delimited JSON (NDJSON/JSONL) DNS logs,
    such as Suricata EVE DNS, Zeek JSON logs, or SIEM exports.
    """

    def parse(self) -> Generator[DNSQuery, None, None]:
        if not self.filepath.exists():
            raise FileNotFoundError(f"Log file not found: {self.filepath}")

        with open(self.filepath, mode="r", encoding="utf-8", errors="replace") as f:
            first_char = f.read(1)
            f.seek(0)

            # JSON Array format
            if first_char == "[":
                try:
                    data = json.load(f)
                    if isinstance(data, list):
                        for item in data:
                            if isinstance(item, dict):
                                record = self._extract_record(item)
                                if record:
                                    yield record
                        return
                except json.JSONDecodeError:
                    f.seek(0)

            # Line-delimited JSON (NDJSON)
            for line_no, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        record = self._extract_record(obj)
                        if record:
                            yield record
                except json.JSONDecodeError:
                    continue

    def _extract_record(self, obj: Dict[str, Any]) -> Optional[DNSQuery]:
        # Suricata EVE format
        if obj.get("event_type") == "dns" and "dns" in obj:
            dns_info = obj["dns"]
            qname = dns_info.get("rrname") or dns_info.get("query", [{}])[0].get("rrname", "")
            qtype = dns_info.get("rrtype") or dns_info.get("type", "A")
            return DNSQuery(
                query_name=qname,
                qtype=qtype,
                timestamp=self._parse_ts(obj.get("timestamp")),
                client_ip=obj.get("src_ip"),
                server_ip=obj.get("dest_ip"),
                rcode=dns_info.get("rcode", "NOERROR"),
                raw_record=json.dumps(obj),
            )

        # Zeek JSON format
        if "query" in obj or "id.orig_h" in obj:
            qname = obj.get("query")
            if not qname or qname == "-":
                return None
            return DNSQuery(
                query_name=qname,
                qtype=obj.get("qtype_name") or obj.get("qtype", "A"),
                timestamp=self._parse_ts(obj.get("ts")),
                client_ip=obj.get("id.orig_h") or obj.get("src_ip"),
                server_ip=obj.get("id.resp_h") or obj.get("dest_ip"),
                rcode=obj.get("rcode_name") or obj.get("rcode", "NOERROR"),
                raw_record=json.dumps(obj),
            )

        # Generic JSON formats
        qname = None
        for key in ["query_name", "query", "domain", "qname", "name", "host", "fqdn"]:
            if key in obj and isinstance(obj[key], str) and obj[key].strip():
                qname = obj[key].strip()
                break

        if not qname:
            return None

        qtype = "A"
        for key in ["qtype", "type", "record_type", "rrtype"]:
            if key in obj and obj[key]:
                qtype = str(obj[key])
                break

        client_ip = None
        for key in ["client_ip", "client", "src_ip", "src", "source_ip"]:
            if key in obj and obj[key]:
                client_ip = str(obj[key])
                break

        server_ip = None
        for key in ["server_ip", "server", "dest_ip", "dst", "dst_ip"]:
            if key in obj and obj[key]:
                server_ip = str(obj[key])
                break

        rcode = "NOERROR"
        for key in ["rcode", "response_code", "status"]:
            if key in obj and obj[key]:
                rcode = str(obj[key])
                break

        ts_val = None
        for key in ["timestamp", "time", "ts", "datetime"]:
            if key in obj and obj[key]:
                ts_val = self._parse_ts(obj[key])
                break

        return DNSQuery(
            query_name=qname,
            qtype=qtype,
            timestamp=ts_val,
            client_ip=client_ip,
            server_ip=server_ip,
            rcode=rcode,
            raw_record=json.dumps(obj),
        )

    def _parse_ts(self, ts: Any) -> Optional[datetime]:
        if ts is None:
            return None
        if isinstance(ts, (int, float)):
            try:
                return datetime.utcfromtimestamp(ts)
            except Exception:
                return None
        if isinstance(ts, str):
            ts = ts.strip()
            try:
                return datetime.utcfromtimestamp(float(ts))
            except ValueError:
                pass
            for fmt in (
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%d %H:%M:%S",
            ):
                try:
                    return datetime.strptime(ts, fmt)
                except ValueError:
                    continue
        return None
