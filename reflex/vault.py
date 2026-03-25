"""
Vault — Backup Verification agent.

Checks the health, recency, and integrity of backups stored
under /srv/ai/backups/.

Schedule: daily
"""

import os
import re
import shutil
import subprocess

from reflex.base import ReflexAgent

_BACKUP_ROOT = "/srv/ai/backups/"

# Files that should be present in a healthy backup.
_CRITICAL_FILES = [
    "Caddyfile",
    "settings.yml",
]

# Pattern for systemd unit files.
_SYSTEMD_PATTERN = re.compile(r".*\.(service|timer|socket)$")


class VaultAgent(ReflexAgent):
    """Backup Verification agent."""

    name = "vault"
    description = "Checks backup health, recency, and integrity"
    schedule = "daily"

    # ── Scan entry point ────────────────────────────────────────────────

    def scan(self) -> dict:
        findings: list[dict] = []
        auto_fixed: list[str] = []
        worst = "PASS"

        # 1. Backup directory existence
        if not os.path.isdir(_BACKUP_ROOT):
            findings.append(self._finding(
                "CRITICAL",
                "Backup directory missing",
                f"{_BACKUP_ROOT} does not exist.",
                auto_fixable=True,
            ))
            return self._result(severity="CRITICAL", findings=findings)

        if not os.listdir(_BACKUP_ROOT):
            findings.append(self._finding(
                "CRITICAL",
                "Backup directory is empty",
                f"{_BACKUP_ROOT} exists but contains no backups.",
                auto_fixable=True,
            ))
            return self._result(severity="CRITICAL", findings=findings)

        # 2. Find most recent backup by timestamp directory name
        latest_backup, age_days = self._find_latest_backup()

        if latest_backup is None:
            findings.append(self._finding(
                "CRITICAL",
                "No timestamped backup directories found",
                f"Could not identify any backup directories in {_BACKUP_ROOT}.",
                auto_fixable=True,
            ))
            return self._result(severity="CRITICAL", findings=findings)

        # 3. Check age
        age_findings = self._check_age(latest_backup, age_days)
        findings.extend(age_findings)

        # 4. Verify SHA256SUMS if present
        integrity_findings = self._check_integrity(latest_backup)
        findings.extend(integrity_findings)

        # 5. Backup timer status
        timer_findings = self._check_backup_timer()
        findings.extend(timer_findings)

        # 6. Disk usage
        disk_findings = self._check_disk_usage()
        findings.extend(disk_findings)

        # 7. Critical files in latest backup
        content_findings = self._check_critical_files(latest_backup)
        findings.extend(content_findings)

        # Determine overall severity.
        severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "PASS": 0}
        for f in findings:
            if severity_rank.get(f["severity"], 0) > severity_rank.get(worst, 0):
                worst = f["severity"]

        return self._result(severity=worst, findings=findings, auto_fixed=auto_fixed)

    # ── Can / auto-fix ──────────────────────────────────────────────────

    def can_auto_fix(self, finding: dict) -> bool:
        return finding.get("auto_fixable", False)

    def auto_fix(self, finding: dict) -> bool:
        """Trigger backup via systemctl start halo-backup.service."""
        return self._trigger_backup()

    # ── Private helpers ─────────────────────────────────────────────────

    def _find_latest_backup(self) -> tuple:
        """Find the most recent backup directory by name (timestamp).

        Returns (path_to_latest, age_in_days) or (None, None).
        """
        import datetime

        # Common timestamp directory formats.
        timestamp_patterns = [
            re.compile(r"^(\d{4})-(\d{2})-(\d{2})(?:[T_-](\d{2})[-:]?(\d{2})[-:]?(\d{2}))?"),
            re.compile(r"^(\d{4})(\d{2})(\d{2})(?:[-_T]?(\d{2})(\d{2})(\d{2}))?"),
        ]

        latest_dt = None
        latest_path = None

        for entry in os.listdir(_BACKUP_ROOT):
            entry_path = os.path.join(_BACKUP_ROOT, entry)
            if not os.path.isdir(entry_path):
                continue

            for pattern in timestamp_patterns:
                m = pattern.match(entry)
                if m:
                    groups = m.groups()
                    year, month, day = int(groups[0]), int(groups[1]), int(groups[2])
                    hour = int(groups[3]) if groups[3] else 0
                    minute = int(groups[4]) if groups[4] else 0
                    second = int(groups[5]) if groups[5] else 0
                    try:
                        dt = datetime.datetime(year, month, day, hour, minute, second)
                        if latest_dt is None or dt > latest_dt:
                            latest_dt = dt
                            latest_path = entry_path
                    except ValueError:
                        pass
                    break

        if latest_dt is None:
            # Fallback: use mtime of directories.
            dirs = []
            for entry in os.listdir(_BACKUP_ROOT):
                entry_path = os.path.join(_BACKUP_ROOT, entry)
                if os.path.isdir(entry_path):
                    dirs.append((os.path.getmtime(entry_path), entry_path))
            if dirs:
                dirs.sort(reverse=True)
                mtime, latest_path = dirs[0]
                latest_dt = datetime.datetime.fromtimestamp(mtime)

        if latest_dt is None:
            return None, None

        age_days = (datetime.datetime.utcnow() - latest_dt).total_seconds() / 86400
        return latest_path, age_days

    def _check_age(self, latest_path: str, age_days: float) -> list[dict]:
        findings: list[dict] = []
        backup_name = os.path.basename(latest_path)

        if age_days > 7:
            findings.append(self._finding(
                "HIGH",
                f"Latest backup is {age_days:.1f} days old",
                f"Most recent backup: {backup_name}. Backups older than 7 days "
                "indicate the backup pipeline may be broken.",
                auto_fixable=True,
            ))
        elif age_days > 3:
            findings.append(self._finding(
                "MEDIUM",
                f"Latest backup is {age_days:.1f} days old",
                f"Most recent backup: {backup_name}. Consider investigating "
                "why no recent backup exists.",
                auto_fixable=True,
            ))
        else:
            findings.append(self._finding(
                "PASS",
                f"Latest backup is {age_days:.1f} days old",
                f"Most recent backup: {backup_name}.",
            ))

        return findings

    def _check_integrity(self, backup_path: str) -> list[dict]:
        """Verify SHA256SUMS if present in the backup directory."""
        findings: list[dict] = []
        sums_file = os.path.join(backup_path, "SHA256SUMS")

        if not os.path.isfile(sums_file):
            findings.append(self._finding(
                "LOW",
                "No SHA256SUMS file in latest backup",
                f"Expected checksum file at {sums_file}.",
            ))
            return findings

        try:
            proc = subprocess.run(
                ["sha256sum", "-c", "SHA256SUMS"],
                capture_output=True, text=True, timeout=120,
                cwd=backup_path,
            )
            if proc.returncode != 0:
                failed_lines = [
                    line for line in proc.stdout.splitlines()
                    if "FAILED" in line
                ]
                findings.append(self._finding(
                    "HIGH",
                    "Backup integrity check failed",
                    f"sha256sum -c reported failures:\n"
                    + "\n".join(failed_lines[:10]),
                ))
            else:
                findings.append(self._finding(
                    "PASS",
                    "Backup integrity check passed",
                    "All checksums in SHA256SUMS verified successfully.",
                ))
        except FileNotFoundError:
            findings.append(self._finding(
                "LOW", "sha256sum not found",
                "Cannot verify backup integrity without sha256sum.",
            ))
        except subprocess.TimeoutExpired:
            findings.append(self._finding(
                "MEDIUM", "Integrity check timed out",
                "sha256sum -c did not complete within 120 seconds.",
            ))

        return findings

    def _check_backup_timer(self) -> list[dict]:
        """Check if the halo-backup.timer is active."""
        findings: list[dict] = []
        try:
            proc = subprocess.run(
                ["systemctl", "is-active", "halo-backup.timer"],
                capture_output=True, text=True, timeout=10,
            )
            status = proc.stdout.strip()
            if status != "active":
                findings.append(self._finding(
                    "HIGH",
                    f"halo-backup.timer is {status}",
                    "The systemd timer for automated backups is not active. "
                    "Backups will not run on schedule.",
                    auto_fixable=True,
                ))
            else:
                findings.append(self._finding(
                    "PASS",
                    "halo-backup.timer is active",
                    "Backup timer is running normally.",
                ))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            findings.append(self._finding(
                "MEDIUM",
                "Could not check backup timer status",
                "systemctl is not available or timed out.",
            ))
        return findings

    def _check_disk_usage(self) -> list[dict]:
        """Check disk usage of the backup directory."""
        findings: list[dict] = []
        try:
            usage = shutil.disk_usage(_BACKUP_ROOT)
            used_pct = (usage.used / usage.total) * 100
            free_gb = usage.free / (1024 ** 3)

            # Get backup dir size.
            proc = subprocess.run(
                ["du", "-sh", _BACKUP_ROOT],
                capture_output=True, text=True, timeout=30,
            )
            backup_size = proc.stdout.split()[0] if proc.returncode == 0 else "unknown"

            if free_gb < 1:
                findings.append(self._finding(
                    "CRITICAL",
                    f"Disk nearly full: {free_gb:.1f} GB free ({used_pct:.0f}% used)",
                    f"Backup directory size: {backup_size}. "
                    "Insufficient space for new backups.",
                ))
            elif free_gb < 5:
                findings.append(self._finding(
                    "MEDIUM",
                    f"Disk space low: {free_gb:.1f} GB free ({used_pct:.0f}% used)",
                    f"Backup directory size: {backup_size}. "
                    "Consider cleaning old backups.",
                ))
            else:
                findings.append(self._finding(
                    "PASS",
                    f"Disk space OK: {free_gb:.1f} GB free ({used_pct:.0f}% used)",
                    f"Backup directory size: {backup_size}.",
                ))

        except OSError as exc:
            findings.append(self._finding(
                "LOW",
                "Could not check disk usage",
                str(exc),
            ))
        return findings

    def _check_critical_files(self, backup_path: str) -> list[dict]:
        """Verify critical files are present in the latest backup."""
        findings: list[dict] = []
        missing: list[str] = []
        has_systemd = False

        # Walk the backup to build a set of filenames.
        all_files: set[str] = set()
        for dirpath, _, filenames in os.walk(backup_path):
            for fn in filenames:
                all_files.add(fn)
                if _SYSTEMD_PATTERN.match(fn):
                    has_systemd = True

        for critical in _CRITICAL_FILES:
            if critical not in all_files:
                missing.append(critical)

        if not has_systemd:
            missing.append("systemd unit files (*.service/*.timer)")

        if missing:
            findings.append(self._finding(
                "HIGH",
                "Critical files missing from latest backup",
                f"Missing: {', '.join(missing)}. "
                f"Backup path: {backup_path}",
            ))
        else:
            findings.append(self._finding(
                "PASS",
                "All critical files present in latest backup",
                f"Checked: {', '.join(_CRITICAL_FILES)} + systemd units.",
            ))

        return findings

    def _trigger_backup(self) -> bool:
        """Trigger a backup by starting halo-backup.service."""
        try:
            proc = subprocess.run(
                ["systemctl", "start", "halo-backup.service"],
                capture_output=True, text=True, timeout=30,
            )
            return proc.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
