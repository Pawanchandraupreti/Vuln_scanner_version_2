"""
Local Network Vulnerability Scanner
────────────────────────────────────
Usage:
    python main.py                        # Auto-detect subnet, scan common ports
    python main.py --target 192.168.1.0/24
    python main.py --target 192.168.1.1   # Single host
    python main.py --target 192.168.1.0/24 --ports 22,80,443,3306
    python main.py --no-report            # Skip PDF generation

Requirements:
    pip install python-nmap reportlab
    sudo apt install nmap       # Linux
    brew install nmap           # macOS
    (Windows: https://nmap.org/download.html)

Note: Run with sudo/admin for OS detection and SYN scans.
"""

import argparse
import json
import sys
import os
from datetime import datetime

from scanner import NetworkVulnScanner, get_local_network, SEVERITY_ORDER

# ── Terminal colors (no external deps) ───────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
ORANGE = "\033[33m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
GRAY   = "\033[90m"
WHITE  = "\033[97m"

SEV_TERM = {
    "CRITICAL": RED,
    "HIGH":     ORANGE,
    "MEDIUM":   YELLOW,
    "LOW":      GREEN,
    "INFO":     BLUE,
}

BANNER = f"""
{CYAN}{BOLD}
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
 ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗██║     ███████║██╔██╗ ██║
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██║     ██╔══██║██║╚██╗██║
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║╚██████╗██║  ██║██║ ╚████║
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{RESET}{GRAY}  Local Network Vulnerability Scanner  |  github.com/Pawanchandraupreti{RESET}
"""


def print_banner():
    print(BANNER)


def sev_badge(sev: str) -> str:
    col = SEV_TERM.get(sev, BLUE)
    return f"{col}{BOLD}[{sev}]{RESET}"


def print_device(device: dict):
    risk_col = SEV_TERM.get(device["risk"], BLUE)
    print(f"\n{BOLD}{WHITE}{'─'*65}{RESET}")
    print(f"  {BOLD}{WHITE}{device['ip']}{RESET}  {GRAY}({device['hostname']}){RESET}")
    print(f"  OS     : {GRAY}{device['os']}{RESET}")
    print(f"  Ports  : {CYAN}{', '.join(str(p) for p in device['open_ports']) or 'None'}{RESET}")
    print(f"  Risk   : {risk_col}{BOLD}{device['risk']}{RESET}")

    if not device["findings"]:
        print(f"  {GREEN}No known vulnerable services detected.{RESET}")
        return

    print(f"\n  {'PORT':<8}{'SERVICE':<16}{'SEVERITY':<12}RECOMMENDATION")
    print(f"  {GRAY}{'─'*60}{RESET}")

    for f in device["findings"]:
        col = SEV_TERM.get(f["severity"], BLUE)
        port_str = str(f["port"]).ljust(8)
        svc_str  = f["service"][:14].ljust(16)
        sev_str  = f"{col}{BOLD}{f['severity']:<10}{RESET}"
        advice   = f["advice"][:55] + ("..." if len(f["advice"]) > 55 else "")
        print(f"  {port_str}{svc_str}{sev_str}{GRAY}{advice}{RESET}")


def print_summary(devices: list):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for d in devices:
        for f in d["findings"]:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    print(f"\n{BOLD}{WHITE}{'═'*65}{RESET}")
    print(f"{BOLD}{WHITE}  SCAN SUMMARY{RESET}")
    print(f"{BOLD}{WHITE}{'═'*65}{RESET}")
    print(f"  Devices scanned : {CYAN}{BOLD}{len(devices)}{RESET}")
    print(f"  {RED}{BOLD}Critical{RESET}        : {RED}{BOLD}{counts['CRITICAL']}{RESET}")
    print(f"  {ORANGE}{BOLD}High{RESET}            : {ORANGE}{BOLD}{counts['HIGH']}{RESET}")
    print(f"  {YELLOW}{BOLD}Medium{RESET}          : {YELLOW}{BOLD}{counts['MEDIUM']}{RESET}")
    print(f"  {GREEN}{BOLD}Low{RESET}             : {GREEN}{BOLD}{counts['LOW']}{RESET}")
    print(f"{BOLD}{WHITE}{'═'*65}{RESET}\n")


def save_json(devices: list, path: str):
    with open(path, "w") as f:
        json.dump(devices, f, indent=2)
    print(f"{GREEN}[+] JSON saved: {path}{RESET}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Local Network Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("--target",    help="Target IP or subnet (default: auto-detect)", default=None)
    parser.add_argument("--ports",     help="Custom port list (default: common risky ports)", default=None)
    parser.add_argument("--no-report", action="store_true", help="Skip PDF report generation")
    parser.add_argument("--json",      action="store_true", help="Also save results as JSON")
    parser.add_argument("--output",    help="Output PDF path", default="vulnerability_report.pdf")
    args = parser.parse_args()

    print_banner()

    # ── Run scan ──────────────────────────────────────────────────────────────
    scanner = NetworkVulnScanner(target=args.target)
    scan_kwargs = {}
    if args.ports:
        scan_kwargs["ports"] = args.ports

    devices = scanner.scan(**scan_kwargs)

    if not devices:
        print(f"{YELLOW}[!] No active hosts found. Check your target or network connection.{RESET}")
        sys.exit(0)

    # ── Print results ─────────────────────────────────────────────────────────
    for device in devices:
        print_device(device)

    print_summary(devices)

    # ── Save JSON ─────────────────────────────────────────────────────────────
    if args.json:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        save_json(devices, f"scan_{ts}.json")

    # ── Generate PDF ──────────────────────────────────────────────────────────
    if not args.no_report:
        try:
            from report import generate_report
            scan_time = scanner.scan_time.strftime("%Y-%m-%d %H:%M:%S") if scanner.scan_time else "Unknown"
            generate_report(
                devices,
                output_path=args.output,
                scan_target=scanner.target,
                scan_time=scan_time,
            )
            print(f"{GREEN}{BOLD}[+] PDF report: {args.output}{RESET}")
        except ImportError:
            print(f"{YELLOW}[!] ReportLab not installed. Skipping PDF. Run: pip install reportlab{RESET}")
        except Exception as e:
            print(f"{RED}[!] PDF generation failed: {e}{RESET}")

    print(f"\n{GRAY}Done. Stay secure.{RESET}\n")


if __name__ == "__main__":
    main()


