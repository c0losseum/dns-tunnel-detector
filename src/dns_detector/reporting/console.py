from __future__ import annotations

import sys
from typing import List, Dict, Any, Optional
from dns_detector.models.alert import DNSAlert, AlertSeverity

try:
    from rich.console import Console as RichConsole
    from rich.table import Table as RichTable
    from rich.panel import Panel as RichPanel
    from rich import box
    _HAS_RICH = True
except ImportError:
    _HAS_RICH = False


class ConsoleReporter:
    """Renders formatted detection results to the standard output."""

    def __init__(self) -> None:
        self.rich_console = RichConsole() if _HAS_RICH else None

    def print_banner(self) -> None:
        banner = """
========================================================================
   ____  _   _ ____  _____                  _   ____       _            
  |  _ \| \ | / ___|| ____|   _  ___       | | |  _ \  ___| |_ ___  ___ 
  | | | |  \| \___ \|  _| | | | |/ _ \ _____| | | | | |/ _ \ __/ _ \/ __|
  | |_| | |\  |___) | |___| |_| |  __/_____| | | |_| |  __/ ||  __/ (__ 
  |____/|_| \_|____/|_____|\__, |\___|     |_| |____/ \___|\__\___|\___|
                           |___/                                        
       DNS Tunneling & Data Exfiltration Detection Framework v1.0.0
========================================================================
"""
        if _HAS_RICH and self.rich_console:
            self.rich_console.print(f"[bold cyan]{banner}[/bold cyan]")
        else:
            print(f"\033[96m{banner}\033[0m")

    def display_alerts(self, alerts: List[DNSAlert], max_display: int = 50) -> None:
        if not alerts:
            msg = "[+] No malicious or suspicious DNS tunneling queries detected."
            if _HAS_RICH and self.rich_console:
                self.rich_console.print(f"[bold green]{msg}[/bold green]")
            else:
                print(f"\033[92m{msg}\033[0m")
            return

        if _HAS_RICH and self.rich_console:
            self._display_alerts_rich(alerts, max_display)
        else:
            self._display_alerts_ansi(alerts, max_display)

    def _display_alerts_rich(self, alerts: List[DNSAlert], max_display: int) -> None:
        table = RichTable(
            title=f"Detected Suspicious DNS Activities ({len(alerts)} alerts)",
            box=box.ROUNDED,
            header_style="bold magenta",
        )
        table.add_column("Severity", justify="center", style="bold")
        table.add_column("Score", justify="right")
        table.add_column("Client IP", justify="center")
        table.add_column("Type", justify="center")
        table.add_column("Query Domain (Truncated)", style="cyan")
        table.add_column("Entropy", justify="right")
        table.add_column("SubLen", justify="right")
        table.add_column("Primary Reason", style="yellow")

        for alert in alerts[:max_display]:
            sev = alert.severity
            sev_color = {
                AlertSeverity.CRITICAL: "bold red",
                AlertSeverity.HIGH: "bold dark_orange",
                AlertSeverity.MEDIUM: "bold yellow",
                AlertSeverity.LOW: "bold green",
                AlertSeverity.INFO: "bold blue",
            }.get(sev, "white")

            qname = alert.query.query_name
            if len(qname) > 42:
                qname = qname[:20] + "..." + qname[-19:]

            primary_rule = alert.triggered_rules[0] if alert.triggered_rules else "Score threshold"

            table.add_row(
                f"[{sev_color}]{sev.value}[/{sev_color}]",
                f"{alert.risk_score:.1f}",
                alert.query.client_ip or "N/A",
                alert.query.qtype,
                qname,
                f"{alert.entropy:.3f}",
                str(alert.subdomain_length),
                primary_rule,
            )

        self.rich_console.print(table)
        if len(alerts) > max_display:
            self.rich_console.print(
                f"[italic yellow](Displaying top {max_display} of {len(alerts)} alerts)[/italic yellow]"
            )

    def _display_alerts_ansi(self, alerts: List[DNSAlert], max_display: int) -> None:
        header = f"{'SEVERITY':<10} {'SCORE':<7} {'CLIENT':<16} {'TYPE':<6} {'ENTROPY':<9} {'SUBLEN':<8} {'QUERY DOMAIN'}"
        print("\n" + "=" * 90)
        print(f"\033[1m{header}\033[0m")
        print("-" * 90)

        for alert in alerts[:max_display]:
            sev = alert.severity
            color = sev.color
            client = alert.query.client_ip or "-"
            qname = alert.query.query_name
            if len(qname) > 40:
                qname = qname[:18] + "..." + qname[-19:]

            row = (
                f"{color}{sev.value:<10}\033[0m "
                f"{alert.risk_score:>5.1f}  "
                f"{client:<16} "
                f"{alert.query.qtype:<6} "
                f"{alert.entropy:>6.3f}   "
                f"{alert.subdomain_length:>6}   "
                f"{qname}"
            )
            print(row)

        print("=" * 90)
        if len(alerts) > max_display:
            print(f"(Displaying top {max_display} of {len(alerts)} alerts)")

    def display_summary(self, summary: Dict[str, Any]) -> None:
        total = summary.get("total_queries_inspected", 0)
        alerts_count = summary.get("total_alerts", 0)
        sev_counts = summary.get("alerts_by_severity", {})
        top_domains = summary.get("top_suspicious_domains", [])
        top_clients = summary.get("top_suspicious_clients", [])
        exfil_bytes = summary.get("estimated_exfiltrated_bytes", 0)

        if _HAS_RICH and self.rich_console:
            crit = sev_counts.get("CRITICAL", 0)
            high = sev_counts.get("HIGH", 0)
            med = sev_counts.get("MEDIUM", 0)
            low = sev_counts.get("LOW", 0)

            stats_text = (
                f"[bold]Total Queries Analyzed:[/bold] {total:,}\n"
                f"[bold]Total Alerts Triggered:[/bold] {alerts_count:,}\n"
                f"  - [bold red]CRITICAL:[/bold red] {crit}\n"
                f"  - [bold dark_orange]HIGH:[/bold dark_orange] {high}\n"
                f"  - [bold yellow]MEDIUM:[/bold yellow] {med}\n"
                f"  - [bold green]LOW:[/bold green] {low}\n"
                f"[bold]Estimated Data In Exfiltrated Subdomains:[/bold] {exfil_bytes:,} bytes (~{exfil_bytes / 1024:.2f} KB)"
            )
            self.rich_console.print(RichPanel(stats_text, title="Inspection Summary", border_style="blue"))
        else:
            print("\n" + "#" * 60)
            print("                 INSPECTION SUMMARY")
            print("#" * 60)
            print(f"Total Queries Analyzed:               {total:,}")
            print(f"Total Alerts Triggered:               {alerts_count:,}")
            for s, c in sev_counts.items():
                print(f"  - {s:<10}                         {c}")
            print(f"Estimated Exfiltrated Payload Bytes:  {exfil_bytes:,} bytes (~{exfil_bytes/1024:.2f} KB)")
            if top_domains:
                print("\nTop Suspicious Apex Domains:")
                for dom, cnt in top_domains[:5]:
                    print(f"  • {dom:<30} ({cnt} alerts)")
            if top_clients:
                print("\nTop Offending Client IPs:")
                for ip, cnt in top_clients[:5]:
                    print(f"  • {ip:<20} ({cnt} alerts)")
            print("#" * 60 + "\n")
