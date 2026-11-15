from __future__ import annotations

import sys
from datetime import datetime
from typing import Callable, Optional
from dns_detector.core.engine import DetectionEngine
from dns_detector.models.alert import DNSAlert
from dns_detector.models.query import DNSQuery
from dns_detector.parsers.pcap_parser import QTYPE_MAP

try:
    import scapy.all as scapy
    _HAS_SCAPY = True
except ImportError:
    _HAS_SCAPY = False


class LiveDNSSniffer:
    """Captures live DNS packets on network interfaces and analyzes them in real-time."""

    def __init__(
        self,
        engine: DetectionEngine,
        interface: Optional[str] = None,
        bpf_filter: str = "udp port 53",
        alert_callback: Optional[Callable[[DNSAlert], None]] = None,
    ) -> None:
        self.engine = engine
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.alert_callback = alert_callback

    def start(self) -> None:
        if not _HAS_SCAPY:
            print(
                "\033[91m[-] Scapy is required for live network sniffing.\033[0m\n"
                "    Please install it using: \033[1mpip install scapy\033[0m\n"
                "    Note: Live packet sniffing may require Administrator / root privileges."
            )
            sys.exit(1)

        print(
            f"\033[92m[*] Starting real-time DNS sniffing on interface: "
            f"{self.interface or 'Default'} (Filter: '{self.bpf_filter}')\033[0m"
        )
        print("[*] Press Ctrl+C to stop...\n")

        try:
            scapy.sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._process_packet,
                store=0,
            )
        except KeyboardInterrupt:
            print("\n[*] Live sniffing stopped by user.")

    def _process_packet(self, pkt: any) -> None:
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

            query = DNSQuery(
                query_name=raw_qname,
                qtype=qtype_str,
                timestamp=datetime.utcnow(),
                client_ip=client_ip,
                server_ip=server_ip,
            )

            alert = self.engine.analyze(query)
            if alert:
                if self.alert_callback:
                    self.alert_callback(alert)
                else:
                    print(alert.format_summary())
