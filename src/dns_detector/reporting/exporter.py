from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Union
from dns_detector.models.alert import DNSAlert


class ReportExporter:
    """Exports detection results into JSON, CSV, Markdown, or HTML formats."""

    @staticmethod
    def export_json(
        alerts: List[DNSAlert], summary: Dict[str, Any], filepath: Union[str, Path]
    ) -> None:
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "summary": summary,
            "alerts": [alert.to_dict() for alert in alerts],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def export_csv(alerts: List[DNSAlert], filepath: Union[str, Path]) -> None:
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        fieldnames = [
            "timestamp",
            "severity",
            "risk_score",
            "client_ip",
            "qtype",
            "query_name",
            "base_domain",
            "subdomain",
            "entropy",
            "metric_entropy",
            "subdomain_length",
            "triggered_rules",
            "recommendation",
        ]
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for a in alerts:
                writer.writerow({
                    "timestamp": a.timestamp.isoformat(),
                    "severity": a.severity.value,
                    "risk_score": a.risk_score,
                    "client_ip": a.query.client_ip or "",
                    "qtype": a.query.qtype,
                    "query_name": a.query.query_name,
                    "base_domain": a.base_domain,
                    "subdomain": a.subdomain,
                    "entropy": a.entropy,
                    "metric_entropy": a.metric_entropy,
                    "subdomain_length": a.subdomain_length,
                    "triggered_rules": "; ".join(a.triggered_rules),
                    "recommendation": a.recommendation,
                })

    @staticmethod
    def export_markdown(
        alerts: List[DNSAlert], summary: Dict[str, Any], filepath: Union[str, Path]
    ) -> None:
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        lines = [
            "# DNS Tunneling & Exfiltration Incident Report",
            f"\n*Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}*",
            "\n## Executive Summary",
            f"- **Total Queries Inspected:** {summary.get('total_queries_inspected', 0):,}",
            f"- **Suspicious Alerts Triggered:** {summary.get('total_alerts', 0):,}",
            f"- **Estimated Exfiltrated Data:** {summary.get('estimated_exfiltrated_bytes', 0):,} bytes",
            "\n### Alerts Breakdown by Severity",
        ]

        sev_counts = summary.get("alerts_by_severity", {})
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if s in sev_counts:
                lines.append(f"- **{s}:** {sev_counts[s]}")

        lines.extend([
            "\n## Top Flagged Apex Domains",
            "| Apex Domain | Alert Count |",
            "|---|---|",
        ])
        for dom, cnt in summary.get("top_suspicious_domains", []):
            lines.append(f"| `{dom}` | {cnt} |")

        lines.extend([
            "\n## Detected Threat Details",
            "| Severity | Score | Client IP | Type | Query Domain | Entropy | Rules Triggered |",
            "|---|---|---|---|---|---|---|",
        ])

        for a in alerts[:100]:
            rules_str = "<br>".join(a.triggered_rules[:3])
            client = a.query.client_ip or "-"
            lines.append(
                f"| **{a.severity.value}** | {a.risk_score:.1f} | `{client}` | `{a.query.qtype}` | `{a.query.query_name}` | {a.entropy:.2f} | {rules_str} |"
            )

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    @staticmethod
    def export_html(
        alerts: List[DNSAlert], summary: Dict[str, Any], filepath: Union[str, Path]
    ) -> None:
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        rows_html = []
        for a in alerts:
            sev_class = a.severity.value.lower()
            rules = ", ".join(a.triggered_rules)
            client = a.query.client_ip or "N/A"
            rows_html.append(f"""
            <tr>
                <td><span class="badge badge-{sev_class}">{a.severity.value}</span></td>
                <td><strong>{a.risk_score:.1f}</strong></td>
                <td><code>{client}</code></td>
                <td><span class="badge badge-type">{a.query.qtype}</span></td>
                <td class="domain-cell" title="{a.query.query_name}"><code>{a.query.query_name}</code></td>
                <td>{a.entropy:.3f}</td>
                <td>{a.subdomain_length}</td>
                <td><small>{rules}</small></td>
            </tr>
            """)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>DNS Tunneling & Exfiltration Incident Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #0f172a;
            color: #e2e8f0;
            margin: 0;
            padding: 2rem;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        h1 {{ color: #38bdf8; margin-bottom: 0.5rem; }}
        .meta {{ color: #94a3b8; margin-bottom: 2rem; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
        .card {{ background: #1e293b; padding: 1.25rem; border-radius: 8px; border: 1px solid #334155; }}
        .card-num {{ font-size: 2rem; font-weight: bold; color: #f8fafc; margin-top: 0.5rem; }}
        table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #334155; font-size: 0.9rem; }}
        th {{ background: #0f172a; color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 0.75rem; }}
        tr:hover {{ background: #283548; }}
        .badge {{ padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }}
        .badge-critical {{ background: #ef4444; color: #fff; }}
        .badge-high {{ background: #f97316; color: #fff; }}
        .badge-medium {{ background: #eab308; color: #000; }}
        .badge-low {{ background: #22c55e; color: #fff; }}
        .badge-info {{ background: #3b82f6; color: #fff; }}
        .badge-type {{ background: #475569; color: #fff; }}
        .domain-cell {{ max-width: 380px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
        code {{ color: #38bdf8; font-family: monospace; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>DNS Covert Channel & Exfiltration Report</h1>
        <div class="meta">Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} | Analyzer Engine v1.0.0</div>

        <div class="grid">
            <div class="card"><div>Total Inspected</div><div class="card-num">{summary.get('total_queries_inspected', 0):,}</div></div>
            <div class="card"><div>Total Alerts</div><div class="card-num" style="color: #ef4444;">{summary.get('total_alerts', 0):,}</div></div>
            <div class="card"><div>Critical Severity</div><div class="card-num" style="color: #ef4444;">{summary.get('alerts_by_severity', {}).get('CRITICAL', 0)}</div></div>
            <div class="card"><div>High Severity</div><div class="card-num" style="color: #f97316;">{summary.get('alerts_by_severity', {}).get('HIGH', 0)}</div></div>
            <div class="card"><div>Est. Exfil Payload</div><div class="card-num" style="color: #38bdf8;">{summary.get('estimated_exfiltrated_bytes', 0):,} B</div></div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Score</th>
                    <th>Client IP</th>
                    <th>Type</th>
                    <th>Query Domain</th>
                    <th>Entropy</th>
                    <th>SubLen</th>
                    <th>Triggered Heuristic Rules</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows_html)}
            </tbody>
        </table>
    </div>
</body>
</html>
"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(html_content)
