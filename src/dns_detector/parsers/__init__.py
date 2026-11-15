from __future__ import annotations

from pathlib import Path
from typing import Optional, Union

from dns_detector.parsers.base import BaseParser
from dns_detector.parsers.csv_parser import CSVLogParser
from dns_detector.parsers.json_parser import JSONLogParser
from dns_detector.parsers.zeek_parser import ZeekDNSLogParser
from dns_detector.parsers.bind_parser import BINDLogParser
from dns_detector.parsers.pcap_parser import PCAPParser

__all__ = [
    "BaseParser",
    "CSVLogParser",
    "JSONLogParser",
    "ZeekDNSLogParser",
    "BINDLogParser",
    "PCAPParser",
    "get_parser_for_file",
]


def get_parser_for_file(
    filepath: Union[str, Path], format_hint: Optional[str] = None
) -> BaseParser:
    """
    Returns an appropriate parser instance for the specified file.
    If format_hint is omitted, determines format by extension and content sniffing.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    hint = (format_hint or "").lower()

    if hint == "csv":
        return CSVLogParser(path, delimiter=",")
    elif hint == "tsv":
        return CSVLogParser(path, delimiter="\t")
    elif hint in ("json", "ndjson", "jsonl"):
        return JSONLogParser(path)
    elif hint in ("zeek", "bro"):
        return ZeekDNSLogParser(path)
    elif hint in ("bind", "named"):
        return BINDLogParser(path)
    elif hint in ("pcap", "cap", "pcapng"):
        return PCAPParser(path)

    # Auto-detection based on file extension
    ext = path.suffix.lower()
    if ext == ".csv":
        return CSVLogParser(path, delimiter=",")
    elif ext in (".json", ".jsonl", ".ndjson"):
        return JSONLogParser(path)
    elif ext in (".pcap", ".cap", ".pcapng"):
        return PCAPParser(path)
    elif ext == ".log":
        # Sniff first lines to differentiate Zeek, BIND, or CSV
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            first_lines = [f.readline() for _ in range(5)]
            content = "".join(first_lines)

            if "#separator" in content or "#fields" in content:
                return ZeekDNSLogParser(path)
            elif "client @" in content or "named[" in content:
                return BINDLogParser(path)
            elif "{" in content:
                return JSONLogParser(path)
            else:
                return CSVLogParser(path)

    # Default fallback to CSV/TSV
    return CSVLogParser(path)
