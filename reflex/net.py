"""
Net — Network Monitor & Router Guardian.

Monitors internet connectivity, router health, LAN devices, DNS integrity,
WireGuard VPN status, port scan indicators, and bandwidth utilization.

Schedule: continuous (every 5 minutes)
"""

import json
import os
import re
import socket
import subprocess
import time
from datetime import datetime, timezone

from reflex.base import ReflexAgent

ROUTER_IP = os.environ.get("HALO_ROUTER_IP", "xxx.xxx.xxx.1")
ROUTER_SSH_PORT = 22
PING_TARGETS = ("1.1.1.1", "8.8.8.8")
DNS_TEST_HOST = "google.com"
LATENCY_THRESHOLD_MS = 100
WG_HANDSHAKE_STALE_SECONDS = 180  # 3 minutes
KNOWN_DEVICES_PATH = "/srv/ai/meek/known-devices.json"
BANDWIDTH_SPIKE_PERCENT = 90
PROC_NET_DEV = "/proc/net/dev"
BANDWIDTH_STATE_PATH = "/srv/ai/meek/.net-bandwidth-state.json"


def _run(cmd: str, timeout: int = 10) -> tuple[int, str]:
    """Run a shell command and return (returncode, stdout)."""
    try:
        proc = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout,
        )
        return proc.returncode, proc.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return -1, str(exc)


class NetAgent(ReflexAgent):
    """Network Monitor & Router Guardian."""

    name = "net"
    description = "Monitors internet connectivity, router health, LAN devices, DNS, VPN, and bandwidth"
    schedule = "continuous"  # every 5 minutes

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self) -> dict:
        start = time.monotonic_ns()
        findings: list[dict] = []
        auto_fixed: list[str] = []

        self._check_internet_connectivity(findings)
        self._check_router_health(findings)
        self._check_lan_devices(findings)
        self._check_dns_leak(findings)
        self._check_wireguard(findings)
        self._check_port_scan_indicators(findings)
        self._check_bandwidth(findings)

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
        if fix_id == "restart_networkd":
            return self._fix_restart_networkd()
        if fix_id == "flush_dns":
            return self._fix_flush_dns()
        if fix_id == "restart_wireguard":
            return self._fix_restart_wireguard()
        return False

    # ------------------------------------------------------------------
    # 1. Internet Connectivity
    # ------------------------------------------------------------------

    def _check_internet_connectivity(self, findings: list[dict]) -> None:
        ping_results: dict[str, float | None] = {}

        for target in PING_TARGETS:
            rc, output = _run(f"ping -c 1 -W 3 {target}")
            if rc == 0:
                match = re.search(r"time=([\d.]+)\s*ms", output)
                latency = float(match.group(1)) if match else None
                ping_results[target] = latency
            else:
                ping_results[target] = None

        # DNS resolution test
        dns_ok = False
        try:
            socket.getaddrinfo(DNS_TEST_HOST, 80, socket.AF_INET, socket.SOCK_STREAM)
            dns_ok = True
        except (socket.gaierror, OSError):
            pass

        all_pings_failed = all(v is None for v in ping_results.values())
        any_ping_ok = any(v is not None for v in ping_results.values())

        if all_pings_failed and not dns_ok:
            findings.append({
                "check": "internet_connectivity",
                "severity": "CRITICAL",
                "message": "Internet is down — all ping targets unreachable and DNS resolution failed",
                "detail": f"Ping targets: {', '.join(PING_TARGETS)}; DNS test: {DNS_TEST_HOST}",
                "auto_fixable": True,
                "fix_id": "restart_networkd",
            })
            return

        if all_pings_failed:
            findings.append({
                "check": "internet_ping",
                "severity": "HIGH",
                "message": "All ping targets unreachable but DNS works",
                "detail": f"ICMP may be blocked. Targets: {', '.join(PING_TARGETS)}",
                "auto_fixable": False,
                "fix_id": None,
            })

        if not dns_ok:
            findings.append({
                "check": "dns_resolution",
                "severity": "HIGH",
                "message": f"DNS resolution failed for {DNS_TEST_HOST}",
                "detail": "Internet pings succeed but DNS is broken",
                "auto_fixable": True,
                "fix_id": "flush_dns",
            })

        # Latency check
        for target, latency in ping_results.items():
            if latency is not None and latency > LATENCY_THRESHOLD_MS:
                findings.append({
                    "check": "internet_latency",
                    "severity": "MEDIUM",
                    "message": f"High latency to {target}: {latency:.1f}ms (threshold: {LATENCY_THRESHOLD_MS}ms)",
                    "detail": f"Measured {latency:.1f}ms round-trip",
                    "auto_fixable": False,
                    "fix_id": None,
                })

    # ------------------------------------------------------------------
    # 2. Router Health
    # ------------------------------------------------------------------

    def _check_router_health(self, findings: list[dict]) -> None:
        # Ping router
        rc, output = _run(f"ping -c 1 -W 3 {ROUTER_IP}")
        if rc != 0:
            findings.append({
                "check": "router_ping",
                "severity": "CRITICAL",
                "message": f"Router at {ROUTER_IP} is unreachable",
                "detail": "Gateway ping failed — possible router crash or cable disconnect",
                "auto_fixable": False,
                "fix_id": None,
            })
            return

        # Check SSH port reachability
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ROUTER_IP, ROUTER_SSH_PORT))
            sock.close()
            if result != 0:
                findings.append({
                    "check": "router_ssh",
                    "severity": "MEDIUM",
                    "message": f"Router SSH port {ROUTER_SSH_PORT} is not reachable",
                    "detail": f"TCP connect to {ROUTER_IP}:{ROUTER_SSH_PORT} returned code {result}",
                    "auto_fixable": False,
                    "fix_id": None,
                })
        except (socket.timeout, OSError) as exc:
            findings.append({
                "check": "router_ssh",
                "severity": "MEDIUM",
                "message": f"Router SSH port check failed: {exc}",
                "detail": f"Could not probe {ROUTER_IP}:{ROUTER_SSH_PORT}",
                "auto_fixable": False,
                "fix_id": None,
            })

    # ------------------------------------------------------------------
    # 3. LAN Device Discovery
    # ------------------------------------------------------------------

    def _check_lan_devices(self, findings: list[dict]) -> None:
        rc, output = _run("ip neigh show")
        if rc != 0:
            return

        current_devices: dict[str, str] = {}  # MAC -> IP
        for line in output.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            ip = parts[0]
            # MAC is typically at index 4 after "lladdr"
            if "lladdr" in parts:
                mac_idx = parts.index("lladdr") + 1
                if mac_idx < len(parts):
                    mac = parts[mac_idx].lower()
                    current_devices[mac] = ip

        # Load or create known devices baseline
        known_devices = self._load_known_devices()
        if known_devices is None:
            # First run — create baseline
            self._save_known_devices(current_devices)
            findings.append({
                "check": "lan_device_baseline",
                "severity": "LOW",
                "message": f"Created LAN device baseline with {len(current_devices)} devices",
                "detail": f"Saved to {KNOWN_DEVICES_PATH}",
                "auto_fixable": False,
                "fix_id": None,
            })
            return

        # Compare against known devices
        known_macs = set(known_devices.keys())
        current_macs = set(current_devices.keys())
        unknown_macs = current_macs - known_macs

        for mac in unknown_macs:
            ip = current_devices[mac]
            findings.append({
                "check": "unknown_lan_device",
                "severity": "MEDIUM",
                "message": f"Unknown device on LAN: {mac} ({ip})",
                "detail": f"MAC {mac} with IP {ip} is not in known devices list at {KNOWN_DEVICES_PATH}",
                "auto_fixable": False,
                "fix_id": None,
            })

    def _load_known_devices(self) -> dict | None:
        try:
            with open(KNOWN_DEVICES_PATH, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return None

    @staticmethod
    def _save_known_devices(devices: dict) -> None:
        os.makedirs(os.path.dirname(KNOWN_DEVICES_PATH), exist_ok=True)
        with open(KNOWN_DEVICES_PATH, "w") as f:
            json.dump(devices, f, indent=2)

    # ------------------------------------------------------------------
    # 4. DNS Leak Check
    # ------------------------------------------------------------------

    def _check_dns_leak(self, findings: list[dict]) -> None:
        expected_dns = {ROUTER_IP, "127.0.0.53", "127.0.0.1", "::1"}

        try:
            with open("/etc/resolv.conf", "r") as f:
                content = f.read()
        except (FileNotFoundError, PermissionError):
            return

        nameservers = re.findall(r"^nameserver\s+(\S+)", content, re.MULTILINE)
        unexpected = [ns for ns in nameservers if ns not in expected_dns]

        if unexpected:
            findings.append({
                "check": "dns_leak",
                "severity": "MEDIUM",
                "message": f"Unexpected DNS servers in /etc/resolv.conf: {', '.join(unexpected)}",
                "detail": f"Expected only: {', '.join(sorted(expected_dns))}. "
                          f"Found: {', '.join(nameservers)}",
                "auto_fixable": False,
                "fix_id": None,
            })

    # ------------------------------------------------------------------
    # 5. WireGuard VPN Status
    # ------------------------------------------------------------------

    def _check_wireguard(self, findings: list[dict]) -> None:
        rc, output = _run("wg show wg0")
        if rc != 0:
            findings.append({
                "check": "wireguard_status",
                "severity": "HIGH",
                "message": "WireGuard interface wg0 is down or not accessible",
                "detail": output or "wg show wg0 failed",
                "auto_fixable": True,
                "fix_id": "restart_wireguard",
            })
            return

        # Parse peer handshake times
        peers = re.findall(
            r"peer:\s+(\S+).*?latest handshake:\s+(.+?)(?:\n|$)",
            output, re.DOTALL,
        )

        for peer_key, handshake_str in peers:
            stale = self._is_handshake_stale(handshake_str)
            if stale:
                findings.append({
                    "check": "wireguard_handshake",
                    "severity": "MEDIUM",
                    "message": f"Stale WireGuard handshake for peer {peer_key[:12]}...",
                    "detail": f"Last handshake: {handshake_str.strip()}. "
                              f"Threshold: {WG_HANDSHAKE_STALE_SECONDS}s",
                    "auto_fixable": False,
                    "fix_id": None,
                })

        # Report transfer stats (informational)
        transfer_lines = re.findall(r"transfer:\s+(.+)", output)
        if transfer_lines:
            for transfer in transfer_lines:
                findings.append({
                    "check": "wireguard_transfer",
                    "severity": "PASS",
                    "message": f"WireGuard transfer stats: {transfer.strip()}",
                    "detail": "Informational — no action needed",
                    "auto_fixable": False,
                    "fix_id": None,
                })

    @staticmethod
    def _is_handshake_stale(handshake_str: str) -> bool:
        """Return True if the handshake string indicates a stale peer."""
        # wg show outputs things like "1 minute, 30 seconds ago"
        total_seconds = 0
        minutes = re.search(r"(\d+)\s+minute", handshake_str)
        seconds = re.search(r"(\d+)\s+second", handshake_str)
        hours = re.search(r"(\d+)\s+hour", handshake_str)

        if hours:
            total_seconds += int(hours.group(1)) * 3600
        if minutes:
            total_seconds += int(minutes.group(1)) * 60
        if seconds:
            total_seconds += int(seconds.group(1))

        # If we couldn't parse anything, assume stale
        if total_seconds == 0 and not seconds and not minutes and not hours:
            return True

        return total_seconds > WG_HANDSHAKE_STALE_SECONDS

    # ------------------------------------------------------------------
    # 6. Port Scan Detection
    # ------------------------------------------------------------------

    def _check_port_scan_indicators(self, findings: list[dict]) -> None:
        # Check for SYN_RECV state connections (potential port scan)
        rc, output = _run("ss -tn state syn-recv")
        if rc == 0 and output:
            lines = [l for l in output.splitlines()[1:] if l.strip()]  # skip header
            if len(lines) > 5:
                findings.append({
                    "check": "syn_recv_flood",
                    "severity": "MEDIUM",
                    "message": f"{len(lines)} connections in SYN_RECV state (possible port scan or SYN flood)",
                    "detail": "First 5:\n" + "\n".join(lines[:5]),
                    "auto_fixable": False,
                    "fix_id": None,
                })

        # Check fail2ban for non-SSH bans
        rc, output = _run("fail2ban-client status")
        if rc == 0:
            jails = re.findall(r"Jail list:\s+(.*)", output)
            if jails:
                jail_names = [j.strip() for j in jails[0].split(",")]
                for jail in jail_names:
                    if jail == "sshd":
                        continue  # Fang handles SSH
                    jrc, jout = _run(f"fail2ban-client status {jail}")
                    if jrc == 0:
                        banned_match = re.search(r"Currently banned:\s+(\d+)", jout)
                        if banned_match and int(banned_match.group(1)) > 0:
                            findings.append({
                                "check": f"fail2ban_{jail}",
                                "severity": "MEDIUM",
                                "message": f"fail2ban jail '{jail}' has {banned_match.group(1)} banned IPs",
                                "detail": jout,
                                "auto_fixable": False,
                                "fix_id": None,
                            })

    # ------------------------------------------------------------------
    # 7. Bandwidth Monitoring
    # ------------------------------------------------------------------

    def _check_bandwidth(self, findings: list[dict]) -> None:
        current_stats = self._read_proc_net_dev()
        if not current_stats:
            return

        previous_stats = self._load_bandwidth_state()
        self._save_bandwidth_state(current_stats)

        if previous_stats is None:
            return  # First run, no comparison possible

        prev_time = previous_stats.get("_timestamp", 0)
        curr_time = time.time()
        elapsed = curr_time - prev_time
        if elapsed <= 0:
            return

        for iface, stats in current_stats.items():
            if iface.startswith("_") or iface == "lo":
                continue
            prev = previous_stats.get(iface)
            if prev is None:
                continue

            rx_bytes_sec = (stats["rx_bytes"] - prev["rx_bytes"]) / elapsed
            tx_bytes_sec = (stats["tx_bytes"] - prev["tx_bytes"]) / elapsed

            # Assume 1Gbps for physical interfaces, 100Mbps for others
            capacity_bps = 1_000_000_000 if iface.startswith(("eth", "en")) else 100_000_000
            capacity_Bps = capacity_bps / 8

            rx_pct = (rx_bytes_sec / capacity_Bps) * 100 if capacity_Bps else 0
            tx_pct = (tx_bytes_sec / capacity_Bps) * 100 if capacity_Bps else 0

            if rx_pct > BANDWIDTH_SPIKE_PERCENT or tx_pct > BANDWIDTH_SPIKE_PERCENT:
                findings.append({
                    "check": "bandwidth_spike",
                    "severity": "LOW",
                    "message": f"Bandwidth spike on {iface}: RX {rx_pct:.1f}% TX {tx_pct:.1f}% of capacity",
                    "detail": f"RX: {rx_bytes_sec / 1_000_000:.2f} MB/s, TX: {tx_bytes_sec / 1_000_000:.2f} MB/s",
                    "auto_fixable": False,
                    "fix_id": None,
                })

    @staticmethod
    def _read_proc_net_dev() -> dict | None:
        try:
            with open(PROC_NET_DEV, "r") as f:
                lines = f.readlines()
        except (FileNotFoundError, PermissionError):
            return None

        stats: dict = {"_timestamp": time.time()}
        for line in lines[2:]:  # skip headers
            parts = line.split()
            if len(parts) < 10:
                continue
            iface = parts[0].rstrip(":")
            stats[iface] = {
                "rx_bytes": int(parts[1]),
                "tx_bytes": int(parts[9]),
            }
        return stats

    @staticmethod
    def _load_bandwidth_state() -> dict | None:
        try:
            with open(BANDWIDTH_STATE_PATH, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return None

    @staticmethod
    def _save_bandwidth_state(stats: dict) -> None:
        os.makedirs(os.path.dirname(BANDWIDTH_STATE_PATH), exist_ok=True)
        with open(BANDWIDTH_STATE_PATH, "w") as f:
            json.dump(stats, f)

    # ------------------------------------------------------------------
    # Auto-fix actions
    # ------------------------------------------------------------------

    @staticmethod
    def _fix_restart_networkd() -> bool:
        rc, _ = _run("systemctl restart systemd-networkd", timeout=30)
        return rc == 0

    @staticmethod
    def _fix_flush_dns() -> bool:
        rc, _ = _run("resolvectl flush-caches")
        return rc == 0

    @staticmethod
    def _fix_restart_wireguard() -> bool:
        rc, _ = _run("systemctl restart wg-quick@wg0", timeout=30)
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
