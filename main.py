#!/usr/bin/env python3
"""
Convenience entry point for DNS Tunneling & Exfiltration Detector.
Usage:
    python main.py analyze -f samples/dns_tunnel_sample.csv
    python main.py calc "7a8b9c1d2e3f4a5b6c.tunnel.exfil.org"
"""

import sys
from pathlib import Path

# Ensure src/ is on Python search path
SRC_DIR = Path(__file__).resolve().parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from dns_detector.cli import main

if __name__ == "__main__":
    sys.exit(main())
