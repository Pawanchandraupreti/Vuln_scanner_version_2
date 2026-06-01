"""
Local Network Vulnerability Scanner
Core scanning engine - uses nmap under the hood via python-nmap
"""

import nmap
import socket
import ipaddress
import json
from datetime import datetime
from typing import Optional

# ── Severity helpers ──────────────────────────────────────────────────────────

RISKY_PORTS = {
    21:  ("FTP",           "HIGH",   "Transmits credentials in plaintext. Replace with SFTP/SCP."),
    22:  ("SSH",           "LOW",    "Secure if updated. Ensure key-based auth and disable root login."),
    23:  ("Telnet",        "CRITICAL","Completely unencrypted. Disable immediately and use SSH."),
    25:  ("SMTP",          "MEDIUM", "Mail server exposed. Ensure authentication is required."),
    53:  ("DNS",           "MEDIUM", "DNS service open. Verify it's not an open resolver."),
    80:  ("HTTP",          "MEDIUM", "Unencrypted web traffic. Consider enforcing HTTPS."),
    110: ("POP3",          "HIGH",   "Email retrieval in plaintext. Use POP3S (port 995)."),
    135: ("MS-RPC",        "HIGH",   "Windows RPC - common attack vector. Firewall if possible."),
    139: ("NetBIOS",       "HIGH",   "Legacy Windows sharing. Disable if not needed."),
    143: ("IMAP",          "HIGH",   "Email in plaintext. Use IMAPS (port 993)."),
    443: ("HTTPS",         "LOW",    "Encrypted web. Verify TLS version is TLS 1.2+."),
    445: ("SMB",           "CRITICAL","EternalBlue / WannaCry target. Patch and firewall immediately."),
    1433: ("MSSQL",        "HIGH",   "Database exposed to network. Should never be public."),
    1521: ("Oracle DB",    "HIGH",   "Database exposed to network. Restrict with firewall rules."),
    3306: ("MySQL",        "HIGH",   "Database exposed. Bind to 127.0.0.1 unless remote access needed."),
    3389: ("RDP",          "CRITICAL","Remote Desktop - brute-forced constantly. Use VPN + NLA."),
    5432: ("PostgreSQL",   "HIGH",   "Database exposed. Bind to localhost unless remote needed."),
    5900: ("VNC",          "CRITICAL","Remote desktop, often no auth. Use VPN or disable."),
    6379: ("Redis",        "CRITICAL","Often runs with no auth. Bind to localhost immediately."),
    8080: ("HTTP-Alt",     "MEDIUM", "Alternate web port. Check if intentional."),
    8443: ("HTTPS-Alt",    "LOW",    "Alternate HTTPS port. Verify TLS config."),
    27017:("MongoDB",      "CRITICAL","Frequently exposed with no auth. Bind to localhost."),
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def severity_color(sev: str) -> str:
    return {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "🔵"}.get(sev, "⚪")


# ── Network helpers ───────────────────────────────────────────────────────────

def get_local_network() -> str:
    """Detect the local subnet automatically."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    # Assume /24 subnet (works for most home/office networks)
    parts = ip.rsplit(".", 1)
    return f"{parts[0]}.0/24"


def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"


# ── Core scanner ─────────────────────────────────────────────────────────────

class NetworkVulnScanner:
    def __init__(self, target: Optional[str] = None):
        self.target = target or get_local_network()
        self.results = []
        self.scan_time = None
        self.use_nmap = True
        
        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError:
            print("[!] nmap not found. Using Python-based socket scanning (limited mode).")
            print("[!] For full scanning, install nmap: https://nmap.org/download.html")
            self.use_nmap = False
            self.nm = None

    def scan(self, ports: str = "21-25,53,80,110,135,139,143,443,445,1433,1521,3306,3389,5432,5900,6379,8080,8443,27017") -> list:
        """
        Run the scan using nmap or fallback to Python socket scanning.
        -sV  : version detection
        -O   : OS detection (needs root)
        -T4  : aggressive timing
        --open: only show open ports
        """
        print(f"\n[*] Scanning network: {self.target}")
        print(f"[*] Ports: {ports}")
        print("[*] This may take 1-3 minutes...\n")

        self.scan_time = datetime.now()

        if self.use_nmap:
            return self._scan_with_nmap(ports)
        else:
            return self._scan_with_sockets(ports)

    def _scan_with_nmap(self, ports: str) -> list:
        """Scan using nmap."""
        try:
            self.nm.scan(
                hosts=self.target,
                ports=ports,
                arguments="-sV -T4 --open"
            )
        except nmap.PortScannerError as e:
            print(f"[!] Nmap error: {e}")
            print("[!] Make sure nmap is installed: sudo apt install nmap")
            return []

        self.results = self._parse_results()
        return self.results

    def _scan_with_sockets(self, ports: str) -> list:
        """Fallback scanning using Python sockets (limited functionality)."""
        port_list = self._parse_port_string(ports)
        devices = []
        
        # Parse target to see if it's a single host or a subnet
        try:
            network = ipaddress.ip_network(self.target, strict=False)
            hosts_to_scan = list(network.hosts()) if network.num_addresses > 2 else [network.network_address]
        except:
            # Single host
            try:
                hosts_to_scan = [ipaddress.ip_address(self.target)]
            except:
                print(f"[!] Invalid target: {self.target}")
                return []
        
        for host_ip in hosts_to_scan:
            hostname = resolve_hostname(str(host_ip))
            open_ports = []
            findings = []
            
            for port in port_list:
                if self._check_port(str(host_ip), port):
                    open_ports.append(port)
                    
                    if port in RISKY_PORTS:
                        name, severity, advice = RISKY_PORTS[port]
                        findings.append({
                            "port": port,
                            "service": name,
                            "detected_version": "Unknown (no version detection in socket mode)",
                            "severity": severity,
                            "advice": advice,
                        })
                    else:
                        findings.append({
                            "port": port,
                            "service": f"Service on port {port}",
                            "detected_version": "Unknown",
                            "severity": "INFO",
                            "advice": "Non-standard port open. Verify this is intentional.",
                        })
            
            if open_ports:  # Only add hosts with open ports
                findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
                risk = _device_risk(findings)
                
                devices.append({
                    "ip": str(host_ip),
                    "hostname": hostname,
                    "os": "Unknown",
                    "open_ports": open_ports,
                    "findings": findings,
                    "risk": risk,
                })
        
        devices.sort(key=lambda d: SEVERITY_ORDER.get(d["risk"], 99))
        self.results = devices
        return devices

    def _parse_port_string(self, ports: str) -> list:
        """Parse port specification like '80,443,22-25' into a list of ports."""
        port_list = []
        for part in ports.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                port_list.extend(range(start, end + 1))
            else:
                port_list.append(int(part.strip()))
        return sorted(list(set(port_list)))

    def _check_port(self, host: str, port: int, timeout: float = 0.5) -> bool:
        """Check if a port is open on a host."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((host, port))
            return result == 0
        finally:
            sock.close()

    def _parse_results(self) -> list:
        devices = []

        for host in self.nm.all_hosts():
            hostname = resolve_hostname(host)
            os_info = "Unknown"

            # Try to get OS info if available
            if "osmatch" in self.nm[host] and self.nm[host]["osmatch"]:
                os_info = self.nm[host]["osmatch"][0].get("name", "Unknown")

            open_ports = []
            findings = []

            for proto in self.nm[host].all_protocols():
                for port in sorted(self.nm[host][proto].keys()):
                    state = self.nm[host][proto][port]["state"]
                    if state != "open":
                        continue

                    service = self.nm[host][proto][port].get("name", "unknown")
                    version = self.nm[host][proto][port].get("version", "")
                    product = self.nm[host][proto][port].get("product", "")

                    open_ports.append(port)

                    if port in RISKY_PORTS:
                        name, severity, advice = RISKY_PORTS[port]
                        findings.append({
                            "port": port,
                            "service": name,
                            "detected_version": f"{product} {version}".strip() or service,
                            "severity": severity,
                            "advice": advice,
                        })
                    else:
                        findings.append({
                            "port": port,
                            "service": service,
                            "detected_version": f"{product} {version}".strip() or service,
                            "severity": "INFO",
                            "advice": "Non-standard port open. Verify this is intentional.",
                        })

            # Sort findings by severity
            findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))

            # Overall risk score for device
            risk = _device_risk(findings)

            devices.append({
                "ip": host,
                "hostname": hostname,
                "os": os_info,
                "open_ports": open_ports,
                "findings": findings,
                "risk": risk,
            })

        # Sort devices: most risky first
        devices.sort(key=lambda d: SEVERITY_ORDER.get(d["risk"], 99))
        return devices


def _device_risk(findings: list) -> str:
    """Derive overall device risk from its findings."""
    if not findings:
        return "LOW"
    severities = [f["severity"] for f in findings]
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if level in severities:
            return level
    return "INFO"