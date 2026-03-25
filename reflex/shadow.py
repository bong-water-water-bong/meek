"""File Integrity Monitor — Reflex Security Agent.

Maintains a SHA-256 baseline of critical system and application files and
reports any modifications, additions, or deletions between scans.
"""

import glob
import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from reflex.base import ReflexAgent

BASELINE_PATH = "/srv/ai/meek/shadow-baseline.json"

# Monitored paths — supports both literal files and glob patterns.
MONITORED_PATTERNS: list[str] = [
    "/srv/ai/configs/*",
    "/etc/systemd/system/halo-*.service",
    "/etc/nftables.conf",
    "/etc/ssh/sshd_config.d/90-halo-security.conf",
    "/etc/wireguard/wg0.conf",
    "/srv/ai/scripts/*.sh",
    "/etc/fail2ban/jail.local",
]

# Severity mapping — longest-prefix match wins.
_SEVERITY_RULES: list[tuple[str, str]] = [
    ("/etc/systemd/system/",                    "CRITICAL"),
    ("/etc/ssh/",                               "CRITICAL"),
    ("/etc/nftables.conf",                      "HIGH"),
    ("/etc/wireguard/",                         "HIGH"),
    ("/etc/fail2ban/",                          "HIGH"),
    ("/srv/ai/configs/",                        "MEDIUM"),
    ("/srv/ai/scripts/",                        "MEDIUM"),
]


def _sha256(path: str) -> str | None:
    """Return hex SHA-256 digest, or None if unreadable."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def _resolve_patterns(patterns: list[str]) -> dict[str, str | None]:
    """Expand glob patterns and hash every matched file."""
    result: dict[str, str | None] = {}
    for pattern in patterns:
        matched = glob.glob(pattern, recursive=False)
        if not matched and not any(c in pattern for c in "*?["):
            # Literal path — include even if missing so deletions are caught
            matched = [pattern]
        for path in sorted(matched):
            if os.path.isfile(path):
                result[path] = _sha256(path)
    return result


def _severity_for(path: str) -> str:
    """Determine severity based on file path."""
    best = "MEDIUM"
    best_len = 0
    for prefix, sev in _SEVERITY_RULES:
        if path.startswith(prefix) and len(prefix) > best_len:
            best = sev
            best_len = len(prefix)
    return best


class ShadowAgent(ReflexAgent):
    """File Integrity Monitor."""

    name = "shadow"
    description = "Watches critical files for unauthorized changes via SHA-256 hashing"
    schedule = "hourly"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self) -> dict:
        start = time.monotonic_ns()
        findings: list[dict] = []

        current_hashes = _resolve_patterns(MONITORED_PATTERNS)
        baseline = self._load_baseline()

        if baseline is None:
            # First run — create the baseline and report it.
            self._save_baseline(current_hashes)
            findings.append({
                "check": "baseline_created",
                "severity": "INFO",
                "message": f"Initial baseline created with {len(current_hashes)} files",
                "detail": BASELINE_PATH,
                "auto_fixable": False,
                "fix_id": None,
            })
        else:
            self._compare(baseline, current_hashes, findings)

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
        # File integrity changes cannot be auto-fixed — they may be legitimate.
        return False

    def auto_fix(self, finding: dict) -> bool:
        return False

    def refresh_baseline(self) -> dict:
        """Re-hash all monitored files and overwrite the baseline.

        Call this after legitimate changes have been verified.
        Returns a summary dict.
        """
        current_hashes = _resolve_patterns(MONITORED_PATTERNS)
        self._save_baseline(current_hashes)
        return {
            "agent": self.name,
            "action": "refresh_baseline",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "files_baselined": len(current_hashes),
            "baseline_path": BASELINE_PATH,
        }

    # ------------------------------------------------------------------
    # Comparison logic
    # ------------------------------------------------------------------

    def _compare(
        self,
        baseline: dict[str, str | None],
        current: dict[str, str | None],
        findings: list[dict],
    ) -> None:
        all_paths = sorted(set(baseline) | set(current))

        for path in all_paths:
            old_hash = baseline.get(path)
            new_hash = current.get(path)

            if old_hash is not None and new_hash is None:
                # File was in baseline but is now missing or unreadable.
                if not os.path.exists(path):
                    change_type = "deleted"
                    message = f"Monitored file deleted: {path}"
                else:
                    change_type = "unreadable"
                    message = f"Monitored file now unreadable: {path}"
                findings.append({
                    "check": "file_integrity",
                    "severity": _severity_for(path),
                    "change": change_type,
                    "path": path,
                    "message": message,
                    "previous_hash": old_hash,
                    "current_hash": None,
                    "auto_fixable": False,
                    "fix_id": None,
                })

            elif old_hash is None and new_hash is not None:
                # New file appeared since baseline.
                findings.append({
                    "check": "file_integrity",
                    "severity": _severity_for(path),
                    "change": "added",
                    "path": path,
                    "message": f"New file detected: {path}",
                    "previous_hash": None,
                    "current_hash": new_hash,
                    "auto_fixable": False,
                    "fix_id": None,
                })

            elif old_hash != new_hash:
                # File content changed.
                findings.append({
                    "check": "file_integrity",
                    "severity": _severity_for(path),
                    "change": "modified",
                    "path": path,
                    "message": f"File modified: {path}",
                    "previous_hash": old_hash,
                    "current_hash": new_hash,
                    "auto_fixable": False,
                    "fix_id": None,
                })

    # ------------------------------------------------------------------
    # Baseline persistence
    # ------------------------------------------------------------------

    @staticmethod
    def _load_baseline() -> dict[str, str | None] | None:
        try:
            with open(BASELINE_PATH, "r") as fh:
                data = json.load(fh)
            return data.get("hashes", {})
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return None

    @staticmethod
    def _save_baseline(hashes: dict[str, str | None]) -> None:
        payload = {
            "created": datetime.now(timezone.utc).isoformat(),
            "file_count": len(hashes),
            "hashes": hashes,
        }
        os.makedirs(os.path.dirname(BASELINE_PATH), exist_ok=True)
        tmp_path = BASELINE_PATH + ".tmp"
        with open(tmp_path, "w") as fh:
            json.dump(payload, fh, indent=2)
        os.replace(tmp_path, BASELINE_PATH)

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
        return "OK"
