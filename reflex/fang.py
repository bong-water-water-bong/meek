"""
Fang — Intrusion Detection agent.

Monitors for unauthorized access attempts, brute-force SSH attacks,
suspicious processes, and compromised authorized_keys files.

Schedule: continuous
"""

import json
import os
import re
import subprocess
import time

from reflex.base import ReflexAgent

# IPs considered part of the trusted LAN.
_LAN_PREFIXES = ("192.168.50.", "10.100.0.")

# Known crypto-miner process patterns.
_MINER_PATTERNS = re.compile(
    r"(xmrig|minerd|cryptonight|stratum\+tcp|cpuminer|"
    r"ethminer|ccminer|bfgminer|cgminer|nbminer|t-rex|"
    r"phoenixminer|lolminer|gminer|claymore)",
    re.IGNORECASE,
)


class FangAgent(ReflexAgent):
    """Intrusion Detection agent."""

    name = "fang"
    description = "Monitors for unauthorized access and intrusion indicators"
    schedule = "continuous"

    # ── Scan entry point ────────────────────────────────────────────────

    def scan(self) -> dict:
        findings: list[dict] = []
        auto_fixed: list[str] = []
        worst = "PASS"

        # 1. Fail2ban status
        f2b_findings = self._check_fail2ban()
        findings.extend(f2b_findings)

        # 2. Recent SSH auth failures from journalctl
        ssh_findings, suspicious_ips = self._check_ssh_journal()
        findings.extend(ssh_findings)

        # 3. Successful logins from non-LAN IPs
        login_findings = self._check_non_lan_logins()
        findings.extend(login_findings)

        # 4. Root login attempts
        root_findings = self._check_root_login_attempts()
        findings.extend(root_findings)

        # 5. authorized_keys modification
        ak_findings = self._check_authorized_keys()
        findings.extend(ak_findings)

        # 6. Suspicious (crypto-miner) processes
        proc_findings = self._check_suspicious_processes()
        findings.extend(proc_findings)

        # ── Auto-fix: ban suspicious IPs via fail2ban ───────────────────
        for ip in suspicious_ips:
            if self._ban_ip(ip):
                auto_fixed.append(f"Banned suspicious IP {ip} via fail2ban")

        # Determine overall severity (pick the worst).
        severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "PASS": 0}
        for f in findings:
            if severity_rank.get(f["severity"], 0) > severity_rank.get(worst, 0):
                worst = f["severity"]

        return self._result(severity=worst, findings=findings, auto_fixed=auto_fixed)

    # ── Can / auto-fix ──────────────────────────────────────────────────

    def can_auto_fix(self, finding: dict) -> bool:
        return finding.get("auto_fixable", False)

    def auto_fix(self, finding: dict) -> bool:
        ip = finding.get("detail", "").split()[-1] if finding.get("auto_fixable") else None
        if ip:
            return self._ban_ip(ip)
        return False

    # ── Private helpers ─────────────────────────────────────────────────

    def _check_fail2ban(self) -> list[dict]:
        findings: list[dict] = []
        try:
            proc = subprocess.run(
                ["fail2ban-client", "status", "sshd"],
                capture_output=True, text=True, timeout=10,
            )
            if proc.returncode != 0:
                findings.append(self._finding(
                    "MEDIUM", "fail2ban check failed",
                    f"fail2ban-client returned code {proc.returncode}: {proc.stderr.strip()}",
                ))
                return findings

            output = proc.stdout

            # Currently banned
            banned_match = re.search(r"Currently banned:\s+(\d+)", output)
            banned_count = int(banned_match.group(1)) if banned_match else 0

            banned_ips_match = re.search(r"Banned IP list:\s+(.*)", output)
            banned_ips = banned_ips_match.group(1).strip() if banned_ips_match else ""

            # Total failed
            failed_match = re.search(r"Currently failed:\s+(\d+)", output)
            failed_count = int(failed_match.group(1)) if failed_match else 0

            if banned_count > 0:
                findings.append(self._finding(
                    "MEDIUM", f"{banned_count} IPs currently banned by fail2ban",
                    f"Banned IPs: {banned_ips}",
                ))

            if failed_count > 20:
                findings.append(self._finding(
                    "HIGH", f"{failed_count} currently failed attempts tracked by fail2ban",
                    "High volume of authentication failures detected.",
                ))

        except FileNotFoundError:
            findings.append(self._finding(
                "MEDIUM", "fail2ban-client not found",
                "fail2ban may not be installed or is not in PATH.",
            ))
        except subprocess.TimeoutExpired:
            findings.append(self._finding(
                "LOW", "fail2ban-client timed out",
                "Could not query fail2ban status within 10 seconds.",
            ))
        return findings

    def _check_ssh_journal(self) -> tuple[list[dict], set[str]]:
        """Parse journalctl for SSH failures in the last hour.

        Returns (findings, set_of_suspicious_ips).
        """
        findings: list[dict] = []
        suspicious_ips: set[str] = set()

        try:
            proc = subprocess.run(
                ["journalctl", "-u", "sshd", "--since", "1 hour ago",
                 "--no-pager", "-o", "json"],
                capture_output=True, text=True, timeout=30,
            )
            if proc.returncode != 0:
                return findings, suspicious_ips

            failed_passwords = 0
            invalid_users = 0
            source_ips: set[str] = set()

            for line in proc.stdout.splitlines():
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                msg = entry.get("MESSAGE", "")

                if "Failed password" in msg:
                    failed_passwords += 1
                    ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", msg)
                    if ip_match:
                        source_ips.add(ip_match.group(1))

                if "Invalid user" in msg:
                    invalid_users += 1
                    ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", msg)
                    if ip_match:
                        source_ips.add(ip_match.group(1))

            # Identify non-LAN IPs as suspicious
            for ip in source_ips:
                if not any(ip.startswith(prefix) for prefix in _LAN_PREFIXES):
                    suspicious_ips.add(ip)

            total_failures = failed_passwords + invalid_users

            if total_failures > 20:
                findings.append(self._finding(
                    "HIGH",
                    f"{total_failures} SSH auth failures in last hour",
                    f"Failed passwords: {failed_passwords}, Invalid users: {invalid_users}. "
                    f"Source IPs: {', '.join(source_ips) or 'unknown'}",
                    auto_fixable=bool(suspicious_ips),
                ))
            elif total_failures > 0:
                findings.append(self._finding(
                    "LOW",
                    f"{total_failures} SSH auth failures in last hour",
                    f"Failed passwords: {failed_passwords}, Invalid users: {invalid_users}. "
                    f"Source IPs: {', '.join(source_ips) or 'unknown'}",
                ))

            if suspicious_ips:
                findings.append(self._finding(
                    "HIGH",
                    f"{len(suspicious_ips)} non-LAN IPs attempting SSH",
                    f"Suspicious IPs: {', '.join(sorted(suspicious_ips))}",
                    auto_fixable=True,
                ))

        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass  # journalctl unavailable; nothing to report

        return findings, suspicious_ips

    def _check_non_lan_logins(self) -> list[dict]:
        """Check for successful SSH logins from non-LAN IPs."""
        findings: list[dict] = []
        try:
            proc = subprocess.run(
                ["journalctl", "-u", "sshd", "--since", "1 hour ago",
                 "--no-pager", "-o", "json"],
                capture_output=True, text=True, timeout=30,
            )
            if proc.returncode != 0:
                return findings

            for line in proc.stdout.splitlines():
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                msg = entry.get("MESSAGE", "")
                if "Accepted" in msg:
                    ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", msg)
                    if ip_match:
                        ip = ip_match.group(1)
                        if not any(ip.startswith(prefix) for prefix in _LAN_PREFIXES):
                            findings.append(self._finding(
                                "CRITICAL",
                                f"Successful SSH login from non-LAN IP {ip}",
                                f"Full log message: {msg}",
                                auto_fixable=True,
                            ))

        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return findings

    def _check_root_login_attempts(self) -> list[dict]:
        """Check for root login attempts in the last hour."""
        findings: list[dict] = []
        try:
            proc = subprocess.run(
                ["journalctl", "-u", "sshd", "--since", "1 hour ago",
                 "--no-pager", "-o", "json"],
                capture_output=True, text=True, timeout=30,
            )
            if proc.returncode != 0:
                return findings

            root_attempts = 0
            for line in proc.stdout.splitlines():
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                msg = entry.get("MESSAGE", "")
                if re.search(r"(Failed password|Invalid user).*\broot\b", msg):
                    root_attempts += 1

            if root_attempts > 0:
                findings.append(self._finding(
                    "HIGH",
                    f"{root_attempts} root login attempts in last hour",
                    "Direct root SSH login attempts detected. "
                    "Ensure PermitRootLogin is set to 'no' in sshd_config.",
                ))

        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return findings

    def _check_authorized_keys(self) -> list[dict]:
        """Check if any user's authorized_keys was modified in the last hour."""
        findings: list[dict] = []
        one_hour_ago = time.time() - 3600

        # Check common locations
        for home_dir in ("/root", "/home"):
            if home_dir == "/home" and os.path.isdir(home_dir):
                users = [os.path.join(home_dir, u) for u in os.listdir(home_dir)]
            elif home_dir == "/root" and os.path.isdir(home_dir):
                users = [home_dir]
            else:
                continue

            for user_home in users:
                ak_path = os.path.join(user_home, ".ssh", "authorized_keys")
                if os.path.isfile(ak_path):
                    try:
                        mtime = os.path.getmtime(ak_path)
                        if mtime > one_hour_ago:
                            findings.append(self._finding(
                                "HIGH",
                                f"authorized_keys modified recently: {ak_path}",
                                f"Last modified: {time.ctime(mtime)}. "
                                "Verify this change was intentional.",
                            ))
                    except OSError:
                        pass

        return findings

    def _check_suspicious_processes(self) -> list[dict]:
        """Scan ps aux for known crypto-miner patterns."""
        findings: list[dict] = []
        try:
            proc = subprocess.run(
                ["ps", "aux"], capture_output=True, text=True, timeout=10,
            )
            if proc.returncode != 0:
                return findings

            for line in proc.stdout.splitlines()[1:]:  # skip header
                if _MINER_PATTERNS.search(line):
                    findings.append(self._finding(
                        "CRITICAL",
                        "Suspicious process detected (possible crypto miner)",
                        f"Process line: {line.strip()}",
                    ))

        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return findings

    def _ban_ip(self, ip: str) -> bool:
        """Ban an IP via fail2ban-client."""
        try:
            proc = subprocess.run(
                ["fail2ban-client", "set", "sshd", "banip", ip],
                capture_output=True, text=True, timeout=10,
            )
            return proc.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
