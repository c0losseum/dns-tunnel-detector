#!/usr/bin/env python3
"""
Traffic Generator Tool:
Synthesizes realistic DNS query datasets with mixed benign and malicious DNS tunneling traffic.
Generates CSV, JSON, or Zeek log files.
"""

import argparse
import base64
import os
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

BENIGN_ROOTS = [
    "google.com",
    "youtube.com",
    "facebook.com",
    "amazon.com",
    "wikipedia.org",
    "yahoo.com",
    "reddit.com",
    "netflix.com",
    "microsoft.com",
    "instagram.com",
    "twitter.com",
    "github.com",
    "linkedin.com",
    "apple.com",
    "cloudflare.com",
]

BENIGN_PREFIXES = [
    "www",
    "mail",
    "api",
    "auth",
    "cdn",
    "static",
    "assets",
    "images",
    "login",
    "app",
    "status",
    "blog",
    "shop",
    "support",
    "portal",
]

MALICIOUS_ROOTS = [
    "darktunnel.net",
    "shadow-c2.org",
    "infiltrate-dns.io",
    "covert-beacon.com",
    "exfil-corp.biz",
]


def random_ip(network: str = "192.168.1.") -> str:
    return f"{network}{random.randint(10, 240)}"


def generate_hex_payload(length: int = 48) -> str:
    chars = "0123456789abcdef"
    return "".join(random.choice(chars) for _ in range(length))


def generate_base64_payload(length: int = 36) -> str:
    raw_bytes = os.urandom(length)
    b64 = base64.b64encode(raw_bytes).decode("ascii")
    # Clean characters safe for DNS labels
    return b64.replace("/", "-").replace("+", "_").rstrip("=")


def generate_dataset(
    count: int = 200, malicious_ratio: float = 0.2
) -> list[dict]:
    records = []
    base_time = datetime.utcnow() - timedelta(minutes=count)

    for i in range(count):
        current_time = base_time + timedelta(seconds=i * random.uniform(0.5, 3.0))
        is_malicious = random.random() < malicious_ratio

        if is_malicious:
            client_ip = random_ip("192.168.100.")
            root = random.choice(MALICIOUS_ROOTS)
            mode = random.choice(["hex", "base64", "dnscat"])

            if mode == "hex":
                chunk = generate_hex_payload(random.randint(32, 54))
                query = f"{chunk}.tunnel.{root}"
                qtype = random.choice(["A", "TXT"])
            elif mode == "base64":
                chunk = generate_base64_payload(random.randint(24, 40))
                query = f"{chunk}.exfil.{root}"
                qtype = "TXT"
            else:
                chunk = generate_hex_payload(32)
                query = f"dnscat.{chunk}.c2.{root}"
                qtype = random.choice(["TXT", "CNAME", "A"])

            records.append({
                "timestamp": current_time.strftime("%Y-%m-%d %H:%M:%S"),
                "client_ip": client_ip,
                "query": query,
                "qtype": qtype,
                "rcode": "NOERROR",
                "label": "MALICIOUS",
            })
        else:
            client_ip = random_ip("192.168.1.")
            root = random.choice(BENIGN_ROOTS)
            if random.random() < 0.6:
                prefix = random.choice(BENIGN_PREFIXES)
                query = f"{prefix}.{root}"
            else:
                query = root

            records.append({
                "timestamp": current_time.strftime("%Y-%m-%d %H:%M:%S"),
                "client_ip": client_ip,
                "query": query,
                "qtype": random.choice(["A", "A", "A", "AAAA", "MX"]),
                "rcode": "NOERROR",
                "label": "BENIGN",
            })

    return records


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic DNS query dataset.")
    parser.add_argument("-n", "--count", type=int, default=300, help="Total queries (default: 300)")
    parser.add_argument(
        "-r", "--ratio", type=float, default=0.25, help="Malicious ratio 0.0 - 1.0 (default: 0.25)"
    )
    parser.add_argument("-o", "--output", default="samples/synthetic_dns_traffic.csv", help="Output path")
    args = parser.parse_args()

    records = generate_dataset(count=args.count, malicious_ratio=args.ratio)
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    import csv
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["timestamp", "client_ip", "query", "qtype", "rcode", "label"]
        )
        writer.writeheader()
        writer.writerows(records)

    print(f"[+] Successfully generated {len(records)} DNS queries saved to: {out_path}")


if __name__ == "__main__":
    main()
