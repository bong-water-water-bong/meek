"""Firewall & Network Monitor — Reflex Security Agent.

Continuously monitors network security posture: nftables rules, listening
ports, active connections, and WireGuard status.
"""

import json
import re
import subprocess
import time
from datetime import datetime, timezone

from reflex.base import ReflexAgent

# Subnets considered LAN (CIDR).  Extend as needed.
LAN_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                "172.30.", "172.31.", "127.")

# Ports that are expected to bind on 0.0.0.0 / [::]
ALLOWED_WILDCARD_SERVICES = {443, 51820}

# Ports that must be LAN-restricted
LAN_ONLY_PORTS = {22, 443}

NFTABLES_CONF = "/etc/nftables.conf"


def _run(cmd: str, timeout: int = 10) -> tuple[int, str]:
    """Run a shell command and return (returncode, stdout)."""
    try:
        proc = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout,
        )
        return proc.returncode, proc.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return -1, str(exc)


def _is_lan(ip: str) -> bool:
    """Return True if *ip* falls inside a known LAN prefix."""
    return any(ip.startswith(p) for p in LAN_PREFIXES)


class GateAgent(ReflexAgent):
    """Firewall & Network Monitor."""

    name = "gate"
    description = "Monitors firewall rules, listening ports, and active connections"
    schedule = "continuous"  # every 5 minutes

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self) -> dict:
        start = time.monotonic_ns()
        findings: list[dict] = []

        self._check_nftables(findings)
        self._check_listening_ports(findings)
        self._check_established(findings)
        self._check_ip_forwarding(findings)
        self._check_wireguard(findings)

        auto_fixed = [f for f in findings if self.can_auto_fix(f) and self.auto_fix(f)]

        elapsed_ms = (time.monotonic_ns() - start) // 1_000_000
        severity = self._overall_severity(findings)

        return {
            "agent": self.name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": severity,
            "findings": findings,
            "auto_fixed": auto_fixed,
            "scan_duration_ms": elapsed_ms,
        }

    def can_auto_fix(self, finding: dict) -> bool:
        return finding.get("auto_fixable", False)

    def auto_fix(self, finding: dict) -> bool:
        fix_id = finding.get("fix_id")
        if fix_id == "reload_nftables":
            return self._fix_reload_nftables()
        return False

    # ------------------------------------------------------------------
    # Checks
    # ------------------------------------------------------------------

    def _check_nftables(self, findings: list[dict]) -> None:
        rc, output = _run("nft list ruleset")
        if rc != 0 or not output:
            findings.append({
                "check": "nftables_active",
                "severity": "CRITICAL",
                "message": "nftables is not active or not loaded",
                "detail": output or "no ruleset returned",
                "auto_fixable": self._nftables_conf_exists(),
                "fix_id": "reload_nftables",
            })
            return

        # Default input policy should be "drop"
        if not self._input_policy_is_drop(output):
            findings.append({
                "check": "default_input_policy",
                "severity": "CRITICAL",
                "message": "Default INPUT chain policy is not 'drop'",
                "detail": "Firewall allows inbound traffic by default",
                "auto_fixable": False,
                "fix_id": None,
            })

        # SSH (22) and Caddy (443) should be restricted to LAN
        for port in LAN_ONLY_PORTS:
            if not self._port_restricted_to_lan(output, port):
                findings.append({
                    "check": f"port_{port}_lan_only",
                    "severity": "HIGH",
                    "message": f"Port {port} does not appear restricted to LAN subnet",
                    "detail": f"Expected accept rule scoped to LAN CIDR for port {port}",
                    "auto_fixable": False,
                    "fix_id": None,
                })

        # WireGuard port (51820) should be open
        if "51820" not in output:
            findings.append({
                "check": "wireguard_port_open",
                "severity": "HIGH",
                "message": "WireGuard port 51820 not found in nftables ruleset",
                "detail": "WireGuard traffic may be blocked",
                "auto_fixable": False,
                "fix_id": None,
            })

    def _check_listening_ports(self, findings: list[dict]) -> None:
        for proto, flag in [("tcp", "-tlnp"), ("udp", "-ulnp")]:
            rc, output = _run(f"ss {flag}")
            if rc != 0:
                continue
            for line in output.splitlines()[1:]:  # skip header
                parts = line.split()
                if len(parts) < 5:
                    continue
                local_addr = parts[4]
                ip, _, port_str = local_addr.rpartition(":")
                try:
                    port = int(port_str)
                except ValueError:
                    continue

                # Flag services bound to 0.0.0.0 or [::] that shouldn't be
                if ip in ("0.0.0.0", "*", "[::]", "::") and port not in ALLOWED_WILDCARD_SERVICES:
                    process = parts[6] if len(parts) > 6 else "unknown"
                    findings.append({
                        "check": "wildcard_bind",
                        "severity": "HIGH",
                        "message": f"{proto.upper()} port {port} bound to {ip}",
                        "detail": f"Process: {process} — should bind to 127.0.0.1",
                        "auto_fixable": False,
                        "fix_id": None,
                    })

    def _check_established(self, findings: list[dict]) -> None:
        rc, output = _run("ss -tnp state established")
        if rc != 0:
            return
        for line in output.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            peer_addr = parts[4]
            ip, _, _ = peer_addr.rpartition(":")
            ip = ip.strip("[]")
            if ip and not _is_lan(ip):
                process = parts[5] if len(parts) > 5 else "unknown"
                findings.append({
                    "check": "unexpected_established",
                    "severity": "MEDIUM",
                    "message": f"Established connection from non-LAN IP {ip}",
                    "detail": f"Process: {process}",
                    "auto_fixable": False,
                    "fix_id": None,
                })

    def _check_ip_forwarding(self, findings: list[dict]) -> None:
        rc, output = _run("cat /proc/sys/net/ipv4/ip_forward")
        if rc != 0 or output.strip() != "1":
            findings.append({
                "check": "ip_forwarding",
                "severity": "HIGH",
                "message": "IPv4 forwarding is disabled (required for WireGuard)",
                "detail": f"ip_forward = {output.strip() if rc == 0 else 'unreadable'}",
                "auto_fixable": False,
                "fix_id": None,
            })

    def _check_wireguard(self, findings: list[dict]) -> None:
        rc, output = _run("wg show")
        if rc != 0:
            findings.append({
                "check": "wireguard_status",
                "severity": "HIGH",
                "message": "WireGuard is not running or not accessible",
                "detail": output or "wg show failed",
                "auto_fixable": False,
                "fix_id": None,
            })
            return

        if "latest handshake" not in output:
            findings.append({
                "check": "wireguard_peers",
                "severity": "MEDIUM",
                "message": "No recent WireGuard peer handshakes detected",
                "detail": "Peers may be unreachable or misconfigured",
                "auto_fixable": False,
                "fix_id": None,
            })

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _nftables_conf_exists() -> bool:
        import os
        return os.path.isfile(NFTABLES_CONF)

    @staticmethod
    def _input_policy_is_drop(ruleset: str) -> bool:
        # Match lines like: type filter hook input priority 0; policy drop;
        return bool(re.search(r"hook\s+input\b.*policy\s+drop", ruleset, re.IGNORECASE))

    @staticmethod
    def _port_restricted_to_lan(ruleset: str, port: int) -> bool:
        # Look for an accept rule that combines the port with a LAN CIDR
        lan_cidrs = (r"10\.\d", r"192\.168\.", r"172\.(1[6-9]|2\d|3[01])\.")
        for cidr_pat in lan_cidrs:
            pattern = rf"{cidr_pat}.*\b{port}\b.*accept|{port}\b.*{cidr_pat}.*accept"
            if re.search(pattern, ruleset, re.IGNORECASE):
                return True
        return False

    @staticmethod
    def _fix_reload_nftables() -> bool:
        rc, _ = _run(f"nft -f {NFTABLES_CONF}")
        return rc == 0

    @staticmethod
    def _overall_severity(findings: list[dict]) -> str:
        severities = {f["severity"] for f in findings}
        if "CRITICAL" in severities:
            return "CRITICAL"
        if "HIGH" in severities:
            return "HIGH"
        if "MEDIUM" in severities:
            return "MEDIUM"
        return "OK"
