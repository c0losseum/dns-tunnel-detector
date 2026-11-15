from __future__ import annotations

import struct
from datetime import datetime
from pathlib import Path
from typing import Generator, Optional, Union
from dns_detector.models.query import DNSQuery
from dns_detector.parsers.base import BaseParser

try:
    import scapy.all as scapy
    _HAS_SCAPY = True
except ImportError:
    _HAS_SCAPY = False


# DNS QTYPE mapping
QTYPE_MAP = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    10: "NULL",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}


class PCAPParser(BaseParser):
    """
    Parses PCAP network capture files for DNS queries.
    Uses Scapy if installed; otherwise uses a built-in pure-Python PCAP parser
    for UDP port 53 traffic.
    """

    def parse(self) -> Generator[DNSQuery, None, None]:
        if not self.filepath.exists():
            raise FileNotFoundError(f"PCAP file not found: {self.filepath}")

        if _HAS_SCAPY:
            yield from self._parse_scapy()
        else:
            yield from self._parse_pure_python()

    def _parse_scapy(self) -> Generator[DNSQuery, None, None]:
        packets = scapy.PcapReader(str(self.filepath))
        for pkt in packets:
            if pkt.haslayer(scapy.DNS) and pkt.haslayer(scapy.DNSQR):
                dnsqr = pkt[scapy.DNSQR]
                raw_qname = dnsqr.qname.decode("utf-8", errors="ignore").rstrip(".")
                qtype_code = dnsqr.qtype
                qtype_str = QTYPE_MAP.get(qtype_code, str(qtype_code))

                client_ip = None
                server_ip = None
                if pkt.haslayer(scapy.IP):
                    client_ip = pkt[scapy.IP].src
                    server_ip = pkt[scapy.IP].dst
                elif pkt.haslayer(scapy.IPv6):
                    client_ip = pkt[scapy.IPv6].src
                    server_ip = pkt[scapy.IPv6].dst

                ts_val = (
                    datetime.utcfromtimestamp(float(pkt.time)) if pkt.time else None
                )

                yield DNSQuery(
                    query_name=raw_qname,
                    qtype=qtype_str,
                    timestamp=ts_val,
                    client_ip=client_ip,
                    server_ip=server_ip,
                    raw_record=str(pkt.summary()),
                )

    def _parse_pure_python(self) -> Generator[DNSQuery, None, None]:
        """Built-in parser for standard libpcap files (Ethernet + IPv4 + UDP 53)."""
        with open(self.filepath, "rb") as f:
            global_header = f.read(24)
            if len(global_header) < 24:
                return

            magic = global_header[:4]
            if magic == b"\xa1\xb2\xc3\xd4":
                endian = ">"
            elif magic == b"\xd4\xc3\xb2\xa1":
                endian = "<"
            else:
                # Not a classic libpcap file or PCAPNG
                return

            while True:
                pkt_hdr = f.read(16)
                if len(pkt_hdr) < 16:
                    break

                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                    f"{endian}IIII", pkt_hdr
                )
                pkt_data = f.read(incl_len)
                if len(pkt_data) < incl_len:
                    break

                # Ethernet Header: 14 bytes (Dest MAC 6, Src MAC 6, EthType 2)
                if len(pkt_data) < 14 + 20 + 8 + 12:
                    continue

                eth_type = struct.unpack("!H", pkt_data[12:14])[0]
                if eth_type != 0x0800:  # IPv4 only for basic fallback parser
                    continue

                # IPv4 Header
                ip_data = pkt_data[14:]
                ihl = (ip_data[0] & 0x0F) * 4
                protocol = ip_data[9]
                if protocol != 17:  # UDP only
                    continue

                src_ip = ".".join(str(b) for b in ip_data[12:16])
                dst_ip = ".".join(str(b) for b in ip_data[16:20])

                # UDP Header: 8 bytes
                udp_data = ip_data[ihl:]
                if len(udp_data) < 8:
                    continue

                src_port, dst_port, udp_len, udp_chk = struct.unpack(
                    "!HHHH", udp_data[:8]
                )
                if dst_port != 53 and src_port != 53:
                    continue

                # DNS Header: 12 bytes
                dns_data = udp_data[8:]
                if len(dns_data) < 12:
                    continue

                flags = struct.unpack("!H", dns_data[2:4])[0]
                is_query = (flags & 0x8000) == 0
                qd_count = struct.unpack("!H", dns_data[4:6])[0]

                if not is_query or qd_count < 1:
                    continue

                # Parse Question Section
                offset = 12
                labels = []
                while offset < len(dns_data):
                    length = dns_data[offset]
                    offset += 1
                    if length == 0:
                        break
                    if length > 63 or offset + length > len(dns_data):
                        labels = []
                        break
                    labels.append(
                        dns_data[offset : offset + length].decode("ascii", errors="ignore")
                    )
                    offset += length

                if not labels or offset + 4 > len(dns_data):
                    continue

                qtype_code, qclass = struct.unpack("!HH", dns_data[offset : offset + 4])
                query_name = ".".join(labels)
                qtype_str = QTYPE_MAP.get(qtype_code, str(qtype_code))
                ts_val = datetime.utcfromtimestamp(ts_sec + ts_usec / 1_000_000.0)

                yield DNSQuery(
                    query_name=query_name,
                    qtype=qtype_str,
                    timestamp=ts_val,
                    client_ip=src_ip,
                    server_ip=dst_ip,
                    raw_record=f"UDP 53 query {query_name} ({qtype_str})",
                )
