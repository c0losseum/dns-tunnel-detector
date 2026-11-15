from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from dns_detector import __version__
from dns_detector.core.engine import DetectionEngine, EngineConfig
from dns_detector.core.entropy import (
    calculate_entropy,
    calculate_metric_entropy,
    analyze_character_distribution,
)
from dns_detector.models.query import DNSQuery
from dns_detector.models.alert import DNSAlert
from dns_detector.parsers import get_parser_for_file
from dns_detector.reporting.console import ConsoleReporter
from dns_detector.reporting.exporter import ReportExporter
from dns_detector.live.sniffer import LiveDNSSniffer


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dns-detector",
        description="DNS Tunneling & Data Exfiltration Detection Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-v", "--version", action="version", version=f"%(prog)s {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", help="Operational mode")

    # Mode 1: Analyze log or PCAP file
    analyze_p = subparsers.add_parser(
        "analyze", help="Analyze DNS log files (CSV, TSV, JSON, Zeek, BIND) or PCAP"
    )
    analyze_p.add_argument(
        "-f", "--file", required=True, help="Path to input DNS log or PCAP capture file"
    )
    analyze_p.add_argument(
        "--format",
        choices=["auto", "csv", "tsv", "json", "zeek", "bind", "pcap"],
        default="auto",
        help="Log format (default: auto-detect)",
    )
    analyze_p.add_argument(
        "--entropy-threshold",
        type=float,
        default=3.6,
        help="Shannon entropy threshold for alerts (default: 3.6)",
    )
    analyze_p.add_argument(
        "--min-score",
        type=float,
        default=45.0,
        help="Minimum composite risk score (0-100) to trigger alert (default: 45.0)",
    )
    analyze_p.add_argument(
        "--whitelist",
        nargs="*",
        default=[],
        help="Domains to whitelist, or path to a text file with one domain per line",
    )
    analyze_p.add_argument(
        "--output-json", help="Path to save alerts as a JSON report"
    )
    analyze_p.add_argument(
        "--output-csv", help="Path to save alerts as a CSV report"
    )
    analyze_p.add_argument(
        "--output-md", help="Path to save summary report as Markdown"
    )
    analyze_p.add_argument(
        "--output-html", help="Path to save visual HTML incident report"
    )
    analyze_p.add_argument(
        "--max-display",
        type=int,
        default=50,
        help="Maximum alerts to display in terminal (default: 50)",
    )

    # Mode 2: Live network capture
    live_p = subparsers.add_parser(
        "live", help="Sniff live DNS packets on a network interface"
    )
    live_p.add_argument(
        "-i", "--interface", default=None, help="Network interface to monitor"
    )
    live_p.add_argument(
        "--filter", default="udp port 53", help="BPF packet filter (default: 'udp port 53')"
    )
    live_p.add_argument(
        "--min-score",
        type=float,
        default=45.0,
        help="Minimum risk score to alert (default: 45.0)",
    )

    # Mode 3: Interactive single domain calculator
    calc_p = subparsers.add_parser(
        "calc", help="Quickly analyze a single FQDN or string"
    )
    calc_p.add_argument(
        "domain", help="Fully-qualified domain name (e.g. '7a8b9c1d2e.tunnel.evil.com')"
    )
    calc_p.add_argument(
        "--qtype", default="A", help="DNS query type (default: 'A')"
    )

    return parser


def handle_analyze(args: argparse.Namespace) -> int:
    reporter = ConsoleReporter()
    reporter.print_banner()

    log_path = Path(args.file)
    if not log_path.exists():
        print(f"\033[91m[-] Error: File not found: {log_path}\033[0m")
        return 1

    format_hint = None if args.format == "auto" else args.format
    try:
        parser = get_parser_for_file(log_path, format_hint=format_hint)
    except Exception as e:
        print(f"\033[91m[-] Parser error: {e}\033[0m")
        return 1

    config = EngineConfig(
        entropy_threshold=args.entropy_threshold,
        min_score_to_alert=args.min_score,
    )

    # Process custom whitelists
    if args.whitelist:
        for item in args.whitelist:
            wl_path = Path(item)
            if wl_path.exists() and wl_path.is_file():
                with open(wl_path, "r", encoding="utf-8") as f:
                    for line in f:
                        dom = line.strip().lower()
                        if dom and not dom.startswith("#"):
                            config.whitelist.add(dom)
            else:
                config.whitelist.add(item.strip().lower())

    engine = DetectionEngine(config=config)
    alerts: List[DNSAlert] = []

    print(f"[*] Reading and analyzing DNS events from: \033[1m{log_path}\033[0m ...")

    try:
        for query in parser.parse():
            alert = engine.analyze(query)
            if alert:
                alerts.append(alert)
    except Exception as e:
        print(f"\033[91m[-] Error during parsing/analysis: {e}\033[0m")
        return 1

    reporter.display_alerts(alerts, max_display=args.max_display)
    summary = engine.get_summary()
    reporter.display_summary(summary)

    # Export reports if requested
    if args.output_json:
        ReportExporter.export_json(alerts, summary, args.output_json)
        print(f"[+] JSON report saved to: {args.output_json}")

    if args.output_csv:
        ReportExporter.export_csv(alerts, args.output_csv)
        print(f"[+] CSV report saved to: {args.output_csv}")

    if args.output_md:
        ReportExporter.export_markdown(alerts, summary, args.output_md)
        print(f"[+] Markdown report saved to: {args.output_md}")

    if args.output_html:
        ReportExporter.export_html(alerts, summary, args.output_html)
        print(f"[+] HTML visual report saved to: {args.output_html}")

    return 0 if not alerts else 2


def handle_live(args: argparse.Namespace) -> int:
    reporter = ConsoleReporter()
    reporter.print_banner()

    config = EngineConfig(min_score_to_alert=args.min_score)
    engine = DetectionEngine(config=config)

    def on_alert(alert: DNSAlert) -> None:
        color = alert.severity.color
        print(
            f"{color}{alert.severity.badge:<10}\033[0m "
            f"Score: {alert.risk_score:>5.1f} | "
            f"{alert.query.client_ip or 'unknown'} -> {alert.query.query_name} ({alert.query.qtype}) | "
            f"Entropy: {alert.entropy:.3f} | Rules: [{', '.join(alert.triggered_rules)}]"
        )

    sniffer = LiveDNSSniffer(
        engine=engine,
        interface=args.interface,
        bpf_filter=args.filter,
        alert_callback=on_alert,
    )
    sniffer.start()
    return 0


def handle_calc(args: argparse.Namespace) -> int:
    reporter = ConsoleReporter()
    reporter.print_banner()

    domain = args.domain.strip()
    query = DNSQuery(query_name=domain, qtype=args.qtype)
    engine = DetectionEngine()
    alert = engine.analyze(query)

    entropy = calculate_entropy(domain)
    metric_ent = calculate_metric_entropy(domain)
    char_dist = analyze_character_distribution(domain)

    print(f"\n--- Domain Inspection: {domain} ---")
    print(f"FQDN Length:                {len(domain)} chars")
    print(f"Overall Shannon Entropy:    {entropy:.4f} bits/char")
    print(f"Metric Entropy:             {metric_ent:.4f}")
    print(f"Unique Characters:          {char_dist['unique_chars']} (ratio: {char_dist['unique_ratio']:.2f})")
    print(f"Hexadecimal Ratio:          {char_dist['hex_ratio']:.2%}")
    print(f"Digit Ratio:                {char_dist['digit_ratio']:.2%}")
    print(f"Vowel / Consonant Ratio:    {char_dist['vowel_consonant_ratio']:.2f}")
    print(f"Max Consecutive Consonants: {char_dist['max_consecutive_consonants']}")

    if alert:
        print("\n" + "=" * 50)
        print(f"DETECTION STATUS: \033[91mSUSPICIOUS / TUNNELING DETECTED\033[0m")
        print(f"Risk Score:       {alert.risk_score:.1f} / 100")
        print(f"Severity:         {alert.severity.color}{alert.severity.value}\033[0m")
        print(f"Apex Domain:      {alert.base_domain}")
        print(f"Subdomain:        {alert.subdomain}")
        print(f"Subdomain Length: {alert.subdomain_length} chars")
        print(f"Triggered Rules:  {', '.join(alert.triggered_rules)}")
        print(f"Recommendation:   {alert.recommendation}")
        print("=" * 50 + "\n")
    else:
        print("\n" + "=" * 50)
        print("DETECTION STATUS: \033[92mBENIGN / NORMAL DOMAIN\033[0m")
        print("No suspicious exfiltration or tunneling heuristics were triggered.")
        print("=" * 50 + "\n")

    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "analyze":
        return handle_analyze(args)
    elif args.command == "live":
        return handle_live(args)
    elif args.command == "calc":
        return handle_calc(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
