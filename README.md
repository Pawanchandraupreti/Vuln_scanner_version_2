# 🔍 Local Network Vulnerability Scanner

A real-world network security tool that scans devices on your local network,
identifies open ports, flags risky services with severity ratings, and generates
a professional PDF security report — exactly what small businesses pay for.

## What it does

- Discovers all active hosts on your subnet
- Detects open ports and identifies running services + versions
- Rates each finding: `CRITICAL / HIGH / MEDIUM / LOW`
- Gives specific remediation advice per vulnerability
- Outputs a clean, dark-themed PDF report

## Installation

```bash
# 1. Install nmap (required system tool)
sudo apt install nmap          # Ubuntu/Debian
brew install nmap              # macOS

# 2. Install Python dependencies
pip install -r requirements.txt
```

## Usage

```bash
# Auto-detect your subnet and scan
sudo python main.py

# Scan a specific subnet
sudo python main.py --target 192.168.1.0/24

# Scan a single host
sudo python main.py --target 192.168.1.105

# Custom ports
sudo python main.py --target 192.168.1.0/24 --ports 22,80,443,3306,5432

# Skip PDF, just terminal output
sudo python main.py --no-report

# Also export JSON
sudo python main.py --json

# Custom output path
sudo python main.py --output my_home_scan.pdf
```

> **Note:** Run with `sudo` for OS detection and accurate SYN scanning.
> Without sudo, nmap falls back to TCP connect scans (still works, slightly slower).

## Output

**Terminal:**
```
192.168.1.1  (router.local)
OS     : Linux 4.x
Ports  : 22, 80, 443
Risk   : MEDIUM

PORT    SERVICE         SEVERITY    RECOMMENDATION
22      SSH             LOW         Secure if updated. Ensure key-based auth...
80      HTTP            MEDIUM      Unencrypted web traffic. Consider enforcing HTTPS.
```

**PDF Report includes:**
- Executive summary with severity counts
- Device overview table
- Per-device findings with service versions
- Remediation priority guide

## Scanned Ports (Default)

| Port  | Service    | Why it matters                        |
|-------|------------|---------------------------------------|
| 21    | FTP        | Plaintext credentials                 |
| 23    | Telnet     | Completely unencrypted                |
| 445   | SMB        | WannaCry / EternalBlue target         |
| 3389  | RDP        | Brute-forced constantly               |
| 5900  | VNC        | Often runs with no authentication     |
| 6379  | Redis      | Frequently exposed with no auth       |
| 27017 | MongoDB    | Frequently exposed with no auth       |
| ...   | +15 more   |                                       |

## Project Structure

```
vuln_scanner/
├── main.py          # CLI entry point, terminal output
├── scanner.py       # Core nmap wrapper + risk classification
├── report.py        # PDF report generator (ReportLab)
└── requirements.txt
```

## Skills Demonstrated

- Network scanning with nmap (industry standard tool)
- Service fingerprinting and version detection
- Risk classification and CVE-aware port assessment  
- Professional report generation
- CLI tool design with argparse

## Ethical Use

Only scan networks you own or have explicit permission to test.
Unauthorized scanning may be illegal in your jurisdiction.

---
Built by Pawan Chandra Upreti | Lovely Professional University




