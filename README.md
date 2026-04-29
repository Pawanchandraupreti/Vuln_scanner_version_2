# 🔍 Local Network Vulnerability Scanner

A real-world network security tool that scans devices on your local network,
identifies open ports, flags risky services with severity ratings, and generates
a professional PDF security report — exactly what small businesses pay for.

## What it does

- Discovers all active hosts on your subnet
- Detects open ports and identifies running services + versions
- Rates each finding: `CRITICAL / HIGH / MEDIUM / LOW`
- Gives specific remediation advice per vulnerability
- Outputs a clean, dark-themed PDF report (optional)

## Installation

### Quick Setup (Windows)
```bash
# Run the setup script
setup.bat
```

### Manual Setup
```bash
# 1. Create virtual environment
python -m venv venv

# 2. Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

### Full Installation (with nmap for advanced features)
```bash
# Install nmap system tool
# Linux: sudo apt install nmap
# macOS: brew install nmap
# Windows: https://nmap.org/download.html

# Then install Python dependencies
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan (auto-detect your subnet)
python main.py

# Scan specific target
python main.py --target 192.168.1.0/24
python main.py --target 192.168.1.100

# Scan specific ports only
python main.py --target 192.168.1.0/24 --ports 22,80,443,3306

# Skip PDF generation
python main.py --no-report

# Also save results as JSON
python main.py --json

# Custom output PDF name
python main.py --output my_report.pdf
```

## Features

### Scanning Modes
- **nmap mode** (when nmap is installed): Full-featured scanning with version detection
- **Socket mode** (fallback): Works without nmap, uses Python socket connections

### Supported Operating Systems
- Windows (tested with Python 3.14)
- Linux
- macOS

### Port Analysis
The scanner checks for known risky services on common ports including:
- 21-25: FTP, SSH, Telnet, SMTP
- 80, 443: HTTP, HTTPS
- 3306, 5432, 27017: Databases
- 3389, 5900, 6379: Remote access and caches
- And many more...

## Examples

### Scan your entire network
```bash
python main.py
```
Output:
```
VULNSCAN - Local Network Vulnerability Scanner
=================================================

[*] Scanning network: 192.168.1.0/24
[*] Ports: 21-25,53,80,...

─────────────────────────────────────────────────
  192.168.1.50   (myserver.local)
  OS     : Ubuntu 20.04 LTS
  Ports  : 22, 80, 443
  Risk   : HIGH

  PORT    SERVICE          SEVERITY   RECOMMENDATION
  ───────────────────────────────────────────────
  22      SSH             LOW        Secure if updated...
  80      HTTP            MEDIUM     Unencrypted web traffic...
  443     HTTPS           LOW        Encrypted web...
```

## Troubleshooting

### "nmap not found" warning
This is normal! The scanner will fall back to Python-based socket scanning.
For full scanning with version detection, install nmap.

### "No active hosts found"
- Check your target IP range is correct
- Verify network connectivity
- Try pinging the target manually

### Unicode/encoding errors (Windows)
These have been fixed in the latest version. If you encounter any, report them.

## Requirements

**Core:**
- Python 3.7+
- python-nmap (optional, falls back to socket scanning)

**System:**
- nmap (optional, for advanced features)

**Optional:**
- reportlab (for PDF generation)

## License

MIT

## Author

Pawan Chandra Upreti
GitHub: https://github.com/Pawanchandraupreti


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
