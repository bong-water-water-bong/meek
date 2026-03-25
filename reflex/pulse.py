"""Reflex Agent: Service Health Monitor (pulse)

Checks all halo-ai services are running and responsive.
Severity CRITICAL for Caddy/llama-server, HIGH for others.
Can auto-fix by restarting failed services.
"""

import subprocess
import re

from .base import ReflexAgent


# Service definitions: (systemd unit, display name, health check tuple or None)
# Health check tuple: (url_or_method, port)
SERVICES = {
    "halo-open-webui.service": {
        "name": "Open WebUI",
        "health": ("http://127.0.0.1:3000", 3000),
    },
    "halo-dashboard-api.service": {
        "name": "Dashboard API",
        "health": ("http://127.0.0.1:3002/health", 3002),
    },
    "halo-lemonade.service": {
        "name": "Lemonade",
        "health": ("http://127.0.0.1:8080/health", 8080),
    },
    "halo-llama-server.service": {
        "name": "llama-server",
        "health": ("http://127.0.0.1:8081/health", 8081),
        "critical": True,
    },
    "halo-searxng.service": {
        "name": "SearXNG",
        "health": ("http://127.0.0.1:8888", 8888),
    },
    "halo-n8n.service": {
        "name": "n8n",
        "health": ("http://127.0.0.1:5678/healthz", 5678),
    },
    "halo-caddy.service": {
        "name": "Caddy",
        "health": ("port:443", 443),
        "critical": True,
    },
}

INFRA_CHECKS = {
    "wireguard": {
        "name": "WireGuard (wg0)",
        "check_cmd": ["ip", "link", "show", "wg0"],
    },
    "fail2ban": {
        "name": "fail2ban",
        "check_cmd": ["systemctl", "is-active", "fail2ban.service"],
    },
    "nftables": {
        "name": "nftables",
        "check_cmd": ["nft", "list", "ruleset"],
    },
}


class PulseAgent(ReflexAgent):
    """Service health monitor for halo-ai infrastructure."""

    name = "pulse"
    description = "Checks all halo-ai services are running and responsive"
    schedule = "hourly"

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _run(cmd, timeout=10):
        """Run a command and return (returncode, stdout)."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.returncode, result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            return 1, str(exc)

    @staticmethod
    def _curl(url, timeout=5):
        """Hit a URL with curl -s and return (ok, body)."""
        rc, out = PulseAgent._run(
            ["curl", "-s", "--max-time", str(timeout), url],
            timeout=timeout + 2,
        )
        return rc == 0, out

    @staticmethod
    def _port_listening(port):
        """Check whether a TCP port is listening on 127.0.0.1."""
        rc, _ = PulseAgent._run(
            ["ss", "-tlnH", f"sport = :{port}"],
        )
        if rc != 0:
            return False
        # ss returns empty output when nothing listens
        _, out = PulseAgent._run(["ss", "-tlnH", f"sport = :{port}"])
        return bool(out)

    # --------------------------------------------------------- service checks

    def _check_systemd_unit(self, unit):
        """Return True if the systemd unit is active."""
        rc, out = self._run(["systemctl", "is-active", unit])
        return rc == 0 and out == "active"

    def _check_health(self, health_tuple):
        """Run the appropriate health check. Returns (ok, detail)."""
        url, port = health_tuple
        if url.startswith("port:"):
            ok = self._port_listening(port)
            detail = "port listening" if ok else f"port {port} not listening"
            return ok, detail
        ok, body = self._curl(url)
        if ok:
            return True, "healthy"
        return False, f"health endpoint unreachable ({url})"

    # --------------------------------------------------------- infra checks

    def _check_wireguard(self):
        rc, _ = self._run(["ip", "link", "show", "wg0"])
        return rc == 0

    def _check_fail2ban(self):
        return self._check_systemd_unit("fail2ban.service")

    def _check_nftables(self):
        rc, out = self._run(["nft", "list", "ruleset"])
        # Consider loaded if there is any output (rules present)
        return rc == 0 and len(out) > 0

    # ------------------------------------------------------------------ scan

    # Known bcrypt hash of the default password "Caddy"
    DEFAULT_CADDY_HASH = "$2a$14$hyBjre0RT3lbdTzAtACFRuhlYeFAx4xsxVsk0IR2RkDy3KVJIi2Nq"
    CADDYFILE_PATH = "/srv/ai/configs/Caddyfile"

    def _check_default_caddy_password(self):
        """Return True if the Caddyfile still contains the default password hash."""
        try:
            with open(self.CADDYFILE_PATH, "r") as fh:
                return self.DEFAULT_CADDY_HASH in fh.read()
        except (OSError, IOError):
            return False

    def scan(self) -> dict:
        findings = []

        # --- CRITICAL: default Caddy password check ---
        if self._check_default_caddy_password():
            findings.append({
                "id": "pulse:security:default-caddy-password",
                "severity": "CRITICAL",
                "title": "Default Caddy password in use — run halo-change-password.sh immediately",
                "detail": (
                    f"The Caddyfile at {self.CADDYFILE_PATH} still contains the "
                    "default bcrypt hash for password 'Caddy'. All web services are "
                    "accessible with a publicly known password. Run "
                    "/srv/ai/scripts/halo-change-password.sh to set a secure password."
                ),
                "fixable": False,
            })

        # --- systemd halo-* services ---
        for unit, info in SERVICES.items():
            svc_name = info["name"]
            critical = info.get("critical", False)
            active = self._check_systemd_unit(unit)

            if not active:
                findings.append({
                    "id": f"pulse:service-down:{unit}",
                    "severity": "CRITICAL" if critical else "HIGH",
                    "title": f"{svc_name} is not running",
                    "detail": f"systemd unit {unit} is not active",
                    "unit": unit,
                    "fixable": True,
                })
                continue

            # Unit is active — run health check if defined
            health = info.get("health")
            if health:
                ok, detail = self._check_health(health)
                if not ok:
                    findings.append({
                        "id": f"pulse:health-fail:{unit}",
                        "severity": "CRITICAL" if critical else "HIGH",
                        "title": f"{svc_name} health check failed",
                        "detail": detail,
                        "unit": unit,
                        "fixable": True,
                    })

        # --- infrastructure: WireGuard ---
        if not self._check_wireguard():
            findings.append({
                "id": "pulse:infra:wireguard-down",
                "severity": "HIGH",
                "title": "WireGuard interface wg0 is down",
                "detail": "ip link show wg0 failed",
                "unit": "wg-quick@wg0.service",
                "fixable": True,
            })

        # --- infrastructure: fail2ban ---
        if not self._check_fail2ban():
            findings.append({
                "id": "pulse:infra:fail2ban-down",
                "severity": "HIGH",
                "title": "fail2ban is not running",
                "detail": "systemctl is-active fail2ban.service != active",
                "unit": "fail2ban.service",
                "fixable": True,
            })

        # --- infrastructure: nftables ---
        if not self._check_nftables():
            findings.append({
                "id": "pulse:infra:nftables-unloaded",
                "severity": "HIGH",
                "title": "nftables ruleset is not loaded",
                "detail": "nft list ruleset returned empty or failed",
                "unit": "nftables.service",
                "fixable": True,
            })

        # --- overall severity ---
        if not findings:
            severity = "PASS"
        elif any(f["severity"] == "CRITICAL" for f in findings):
            severity = "CRITICAL"
        else:
            severity = "HIGH"

        return {
            "agent": self.name,
            "severity": severity,
            "findings": findings,
            "summary": f"{len(findings)} issue(s) detected" if findings else "All services healthy",
        }

    # --------------------------------------------------------------- auto-fix

    def can_auto_fix(self, finding) -> bool:
        return finding.get("fixable", False) and "unit" in finding

    def auto_fix(self, finding) -> bool:
        unit = finding.get("unit")
        if not unit:
            return False
        rc, _ = self._run(["systemctl", "restart", unit], timeout=30)
        return rc == 0
