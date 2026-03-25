"""
Shield — Intrusion Prevention & Protection agent.

Detects port scans, ARP spoofing, rogue DHCP servers, TLS certificate
issues, and suspicious outbound connections.  Can auto-block malicious IPs
via nftables and flush poisoned ARP caches.

Schedule: continuous (every 5 minutes)
"""

import json
import os
import re
import socket
import ssl
import subprocess
import time
from datetime import datetime, timezone

from reflex.base import ReflexAgent

ROUTER_IP = os.environ.get("HALO_ROUTER_IP", "xxx.xxx.xxx.1")
GATEWAY_MAC_PATH = "/srv/ai/meek/gateway-mac.json"
OUTBOUND_WHITELIST_PATH = "/srv/ai/meek/outbound-whitelist.json"
CADDY_HOST = "localhost"
CADDY_PORT = 443
CERT_EXPIRY_WARN_DAYS = 7
PORT_SCAN_THRESHOLD = 10  # connection attempts from a single IP


def _run(cmd: str, timeout: int = 10) -> tuple[int, str]:
    """Run a shell command and return (returncode, stdout)."""
    try:
        proc = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout,
        )
        return proc.returncode, proc.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return -1, str(exc)


class ShieldAgent(ReflexAgent):
    """Intrusion Prevention & Protection agent."""

    name = "shield"
    description = "Detects port scans, ARP spoofing, rogue DHCP, TLS issues, and suspicious outbound connections"
    schedule = "continuous"  # every 5 minutes

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self) -> dict:
        start = time.monotonic_ns()
        findings: list[dict] = []
        auto_fixed: list[str] = []

        self._check_port_scan(findings, auto_fixed)
        self._check_arp_spoofing(findings, auto_fixed)
        self._check_rogue_dhcp(findings)
        self._check_tls_cert(findings)
        self._check_outbound_connections(findings)

        worst = self._overall_severity(findings)
        elapsed_ms = (time.monotonic_ns() - start) // 1_000_000

        return {
            "agent": self.name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": worst,
            "findings": findings,
            "auto_fixed": auto_fixed,
            "scan_duration_ms": elapsed_ms,
        }

    def can_auto_fix(self, finding: dict) -> bool:
        return finding.get("auto_fixable", False)

    def auto_fix(self, finding: dict) -> bool:
        fix_id = finding.get("fix_id")
        if fix_id == "block_ip":
            ip = finding.get("target_ip")
            if ip:
                return self._fix_block_ip(ip)
        if fix_id == "flush_arp":
            return self._fix_flush_arp()
        return False

    # ------------------------------------------------------------------
    # 1. Port Scan Detection
    # ------------------------------------------------------------------

    def _check_port_scan(self, findings: list[dict], auto_fixed: list[str]) -> None:
        # Check SYN_RECV connections from ss
        rc, output = _run("ss -tn state syn-recv")
        syn_recv_ips: dict[str, int] = {}

        if rc == 0:
            for line in output.splitlines()[1:]:  # skip header
                parts = line.split()
                if len(parts) < 5:
                    continue
                peer_addr = parts[4]
                ip, _, _ = peer_addr.rpartition(":")
                ip = ip.strip("[]")
                if ip:
                    syn_recv_ips[ip] = syn_recv_ips.get(ip, 0) + 1

        # Also check conntrack if available
        rc, output = _run("conntrack -L 2>/dev/null")
        conntrack_ips: dict[str, int] = {}

        if rc == 0:
            for line in output.splitlines():
                if "SYN_RECV" in line or "SYN_SENT" in line:
                    src_match = re.search(r"src=(\d+\.\d+\.\d+\.\d+)", line)
                    if src_match:
                        ip = src_match.group(1)
                        conntrack_ips[ip] = conntrack_ips.get(ip, 0) + 1

        # Merge counts
        all_ips: dict[str, int] = {}
        for ip, count in syn_recv_ips.items():
            all_ips[ip] = all_ips.get(ip, 0) + count
        for ip, count in conntrack_ips.items():
            all_ips[ip] = all_ips.get(ip, 0) + count

        for ip, count in all_ips.items():
            if count >= PORT_SCAN_THRESHOLD:
                finding = {
                    "check": "port_scan_detected",
                    "severity": "HIGH",
                    "message": f"Possible port scan from {ip}: {count} connection attempts",
                    "detail": f"IP {ip} has {count} SYN_RECV/SYN_SENT entries (threshold: {PORT_SCAN_THRESHOLD})",
                    "auto_fixable": True,
                    "fix_id": "block_ip",
                    "target_ip": ip,
                }
                findings.append(finding)

                # Auto-block the IP
                if self._fix_block_ip(ip):
                    auto_fixed.append(f"Blocked port-scanning IP {ip} via nftables")

    # ------------------------------------------------------------------
    # 2. ARP Spoofing Detection
    # ------------------------------------------------------------------

    def _check_arp_spoofing(self, findings: list[dict], auto_fixed: list[str]) -> None:
        rc, output = _run("ip neigh show")
        if rc != 0:
            return

        ip_to_macs: dict[str, list[str]] = {}
        gateway_mac = None

        for line in output.splitlines():
            parts = line.split()
            if len(parts) < 5 or "lladdr" not in parts:
                continue
            ip = parts[0]
            mac_idx = parts.index("lladdr") + 1
            if mac_idx >= len(parts):
                continue
            mac = parts[mac_idx].lower()

            ip_to_macs.setdefault(ip, []).append(mac)

            if ip == ROUTER_IP:
                gateway_mac = mac

        # Check for duplicate IPs (multiple MACs for same IP)
        for ip, macs in ip_to_macs.items():
            unique_macs = set(macs)
            if len(unique_macs) > 1:
                findings.append({
                    "check": "arp_duplicate_ip",
                    "severity": "CRITICAL",
                    "message": f"ARP spoofing indicator: IP {ip} resolves to multiple MACs",
                    "detail": f"MACs: {', '.join(sorted(unique_macs))}",
                    "auto_fixable": True,
                    "fix_id": "flush_arp",
                })

        # Check gateway MAC consistency
        if gateway_mac:
            stored_mac = self._load_gateway_mac()
            if stored_mac is None:
                # First run — store the baseline
                self._save_gateway_mac(gateway_mac)
                findings.append({
                    "check": "gateway_mac_baseline",
                    "severity": "LOW",
                    "message": f"Stored gateway MAC baseline: {gateway_mac}",
                    "detail": f"Router {ROUTER_IP} MAC saved to {GATEWAY_MAC_PATH}",
                    "auto_fixable": False,
                    "fix_id": None,
                })
            elif stored_mac != gateway_mac:
                findings.append({
                    "check": "gateway_mac_changed",
                    "severity": "CRITICAL",
                    "message": f"Gateway MAC address changed! Was {stored_mac}, now {gateway_mac}",
                    "detail": f"Router {ROUTER_IP} MAC changed — possible ARP poisoning attack",
                    "auto_fixable": True,
                    "fix_id": "flush_arp",
                })
                if self._fix_flush_arp():
                    auto_fixed.append("Flushed ARP cache due to gateway MAC change")

    @staticmethod
    def _load_gateway_mac() -> str | None:
        try:
            with open(GATEWAY_MAC_PATH, "r") as f:
                data = json.load(f)
                return data.get("gateway_mac")
        except (FileNotFoundError, json.JSONDecodeError):
            return None

    @staticmethod
    def _save_gateway_mac(mac: str) -> None:
        os.makedirs(os.path.dirname(GATEWAY_MAC_PATH), exist_ok=True)
        with open(GATEWAY_MAC_PATH, "w") as f:
            json.dump({"gateway_mac": mac, "router_ip": ROUTER_IP}, f, indent=2)

    # ------------------------------------------------------------------
    # 3. Rogue DHCP Detection
    # ------------------------------------------------------------------

    def _check_rogue_dhcp(self, findings: list[dict]) -> None:
        # Parse systemd journal for DHCP-related messages
        rc, output = _run(
            "journalctl -u systemd-networkd -u systemd-resolved "
            "--since '10 minutes ago' --no-pager -o short 2>/dev/null"
        )
        if rc != 0:
            return

        dhcp_servers: set[str] = set()
        for line in output.splitlines():
            # Look for DHCP server addresses in log messages
            match = re.search(r"DHCP.*?server\s+(\d+\.\d+\.\d+\.\d+)", line, re.IGNORECASE)
            if match:
                dhcp_servers.add(match.group(1))

            # Also catch "from <ip>" patterns near DHCP mentions
            if "DHCP" in line.upper():
                from_match = re.search(r"from\s+(\d+\.\d+\.\d+\.\d+)", line)
                if from_match:
                    dhcp_servers.add(from_match.group(1))

        rogue = dhcp_servers - {ROUTER_IP}
        if rogue:
            findings.append({
                "check": "rogue_dhcp",
                "severity": "CRITICAL",
                "message": f"Rogue DHCP server(s) detected: {', '.join(sorted(rogue))}",
                "detail": f"Expected DHCP server: {ROUTER_IP}. "
                          f"Found responses from: {', '.join(sorted(rogue))}",
                "auto_fixable": False,
                "fix_id": None,
            })

    # ------------------------------------------------------------------
    # 4. SSL/TLS Verification
    # ------------------------------------------------------------------

    def _check_tls_cert(self, findings: list[dict]) -> None:
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                server_hostname=CADDY_HOST,
            ) as sock:
                sock.settimeout(5)
                sock.connect((CADDY_HOST, CADDY_PORT))
                cert = sock.getpeercert()

            if not cert:
                findings.append({
                    "check": "tls_cert_missing",
                    "severity": "HIGH",
                    "message": "TLS certificate could not be retrieved from Caddy",
                    "detail": f"Connected to {CADDY_HOST}:{CADDY_PORT} but no cert returned",
                    "auto_fixable": False,
                    "fix_id": None,
                })
                return

            # Check expiry
            not_after = cert.get("notAfter", "")
            if not_after:
                # Format: 'Mon DD HH:MM:SS YYYY GMT'
                try:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expiry - datetime.utcnow()).days

                    if days_left < 0:
                        findings.append({
                            "check": "tls_cert_expired",
                            "severity": "HIGH",
                            "message": f"TLS certificate has expired ({abs(days_left)} days ago)",
                            "detail": f"Certificate notAfter: {not_after}",
                            "auto_fixable": False,
                            "fix_id": None,
                        })
                    elif days_left < CERT_EXPIRY_WARN_DAYS:
                        findings.append({
                            "check": "tls_cert_expiring",
                            "severity": "MEDIUM",
                            "message": f"TLS certificate expires in {days_left} days",
                            "detail": f"Certificate notAfter: {not_after}. "
                                      f"Caddy should auto-renew, but verify it is working.",
                            "auto_fixable": False,
                            "fix_id": None,
                        })
                except ValueError:
                    pass

        except ssl.SSLCertVerificationError as exc:
            findings.append({
                "check": "tls_cert_invalid",
                "severity": "HIGH",
                "message": "TLS certificate verification failed",
                "detail": str(exc),
                "auto_fixable": False,
                "fix_id": None,
            })
        except (ConnectionRefusedError, socket.timeout, OSError) as exc:
            findings.append({
                "check": "tls_connect_failed",
                "severity": "MEDIUM",
                "message": f"Could not connect to Caddy on port {CADDY_PORT}",
                "detail": str(exc),
                "auto_fixable": False,
                "fix_id": None,
            })

    # ------------------------------------------------------------------
    # 5. Outbound Connection Audit
    # ------------------------------------------------------------------

    def _check_outbound_connections(self, findings: list[dict]) -> None:
        rc, output = _run("ss -tnp state established")
        if rc != 0:
            return

        whitelist = self._load_outbound_whitelist()
        whitelisted_ips = set(whitelist.get("ips", [])) if whitelist else set()
        whitelisted_cidrs = whitelist.get("cidrs", []) if whitelist else []

        unknown_destinations: list[dict] = []

        for line in output.splitlines()[1:]:  # skip header
            parts = line.split()
            if len(parts) < 5:
                continue
            peer_addr = parts[4]
            ip, _, port_str = peer_addr.rpartition(":")
            ip = ip.strip("[]")

            if not ip or self._is_local(ip):
                continue

            if ip in whitelisted_ips:
                continue

            if any(self._ip_in_cidr(ip, cidr) for cidr in whitelisted_cidrs):
                continue

            process = parts[5] if len(parts) > 5 else "unknown"
            unknown_destinations.append({
                "ip": ip,
                "port": port_str,
                "process": process,
            })

        if unknown_destinations:
            detail_lines = [
                f"  {d['ip']}:{d['port']} ({d['process']})"
                for d in unknown_destinations[:20]  # cap detail output
            ]
            findings.append({
                "check": "unknown_outbound",
                "severity": "MEDIUM",
                "message": f"{len(unknown_destinations)} outbound connections to unknown destinations",
                "detail": "Destinations not in whitelist:\n" + "\n".join(detail_lines),
                "auto_fixable": False,
                "fix_id": None,
            })

    @staticmethod
    def _load_outbound_whitelist() -> dict | None:
        try:
            with open(OUTBOUND_WHITELIST_PATH, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return None

    @staticmethod
    def _is_local(ip: str) -> bool:
        """Return True if the IP is a LAN or loopback address."""
        return any(ip.startswith(p) for p in (
            "127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.",
            "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
            "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
            "172.29.", "172.30.", "172.31.", "::1", "fe80:",
        ))

    @staticmethod
    def _ip_in_cidr(ip: str, cidr: str) -> bool:
        """Basic CIDR membership check without importing ipaddress (keep it light)."""
        try:
            import ipaddress
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
        except (ValueError, TypeError):
            return False

    # ------------------------------------------------------------------
    # Auto-fix actions
    # ------------------------------------------------------------------

    @staticmethod
    def _fix_block_ip(ip: str) -> bool:
        """Block an IP via nftables blacklist set."""
        rc, _ = _run(f"nft add element inet filter blacklist {{ {ip} }}")
        return rc == 0

    @staticmethod
    def _fix_flush_arp() -> bool:
        """Flush the ARP cache to clear poisoned entries."""
        rc, _ = _run("ip neigh flush all")
        return rc == 0

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _overall_severity(findings: list[dict]) -> str:
        severities = {f["severity"] for f in findings}
        if "CRITICAL" in severities:
            return "CRITICAL"
        if "HIGH" in severities:
            return "HIGH"
        if "MEDIUM" in severities:
            return "MEDIUM"
        if "LOW" in severities:
            return "LOW"
        return "PASS"
