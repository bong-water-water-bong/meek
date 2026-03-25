"""
Mirror — PII Scanner agent.

Walks /srv/ai/ looking for accidental personal data leaks:
emails, real IP addresses, phone numbers, Discord IDs,
and SSH private key material.

Schedule: daily
"""

import os
import re

from reflex.base import ReflexAgent

# Maximum file size to scan (skip anything larger than 10 MB).
_MAX_FILE_SIZE = 10 * 1024 * 1024

# Directories to skip entirely.
_SKIP_DIRS = {".git", "node_modules", "__pycache__", "venv", ".venv", "env", ".env"}

# Binary extensions to skip.
_BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg",
    ".mp3", ".mp4", ".mkv", ".avi", ".mov", ".flac", ".ogg",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".bin", ".exe", ".so", ".dll", ".o", ".pyc", ".pyo",
    ".woff", ".woff2", ".ttf", ".eot", ".pdf",
    ".db", ".sqlite", ".sqlite3",
}

# ── Regex patterns ──────────────────────────────────────────────────────

_EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
)

# Emails to ignore.
_EMAIL_EXCLUDE_RE = re.compile(
    r"(^noreply@|@example\.com$|@localhost$|@users\.noreply\.github\.com$)",
    re.IGNORECASE,
)

_IP_RE = re.compile(
    r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
)

# IPs to ignore (loopback, unspecified, private ranges, placeholder xxx).
_IP_IGNORE = re.compile(
    r"^(127\.0\.0\.1|0\.0\.0\.0|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|"
    r"xxx\.xxx\.\d+\.\d+|xxx\.xxx\.xxx\.xxx|\d+\.\d+\.xxx\.xxx)$",
    re.IGNORECASE,
)

_PHONE_RE = re.compile(
    r"(?<!\d)"  # not preceded by digit
    r"(?:"
    r"\+?1[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}"  # US/CA
    r"|"
    r"\+\d{1,3}[-.\s]?\d{2,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}"  # international
    r"|"
    r"\(\d{3}\)\s?\d{3}[-.]?\d{4}"  # (555) 123-4567
    r")"
    r"(?!\d)"  # not followed by digit
)

_DISCORD_ID_RE = re.compile(
    r"(?<!\d)(\d{17,20})(?!\d)"
)

_SSH_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
)


class MirrorAgent(ReflexAgent):
    """PII Scanner agent."""

    name = "mirror"
    description = "Scans /srv/ai/ for accidental personal data leaks"
    schedule = "daily"

    # ── Scan entry point ────────────────────────────────────────────────

    def scan(self) -> dict:
        findings: list[dict] = []
        scan_root = "/srv/ai/"

        if not os.path.isdir(scan_root):
            return self._result(
                severity="LOW",
                findings=[self._finding(
                    "LOW", "Scan root does not exist",
                    f"{scan_root} is not a directory; nothing to scan.",
                )],
            )

        for dirpath, dirnames, filenames in os.walk(scan_root):
            # Prune skipped directories in-place.
            dirnames[:] = [
                d for d in dirnames
                if d not in _SKIP_DIRS
            ]

            for filename in filenames:
                filepath = os.path.join(dirpath, filename)

                # Skip binary extensions.
                _, ext = os.path.splitext(filename)
                if ext.lower() in _BINARY_EXTS:
                    continue

                # Skip oversized files.
                try:
                    if os.path.getsize(filepath) > _MAX_FILE_SIZE:
                        continue
                except OSError:
                    continue

                file_findings = self._scan_file(filepath)
                findings.extend(file_findings)

        # Determine worst severity.
        severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "PASS": 0}
        worst = "PASS"
        for f in findings:
            if severity_rank.get(f["severity"], 0) > severity_rank.get(worst, 0):
                worst = f["severity"]

        return self._result(severity=worst, findings=findings)

    # No auto-fix — PII findings require human review.
    def can_auto_fix(self, finding: dict) -> bool:
        return False

    def auto_fix(self, finding: dict) -> bool:
        return False

    # ── Private helpers ─────────────────────────────────────────────────

    def _scan_file(self, filepath: str) -> list[dict]:
        findings: list[dict] = []

        try:
            with open(filepath, "r", errors="replace") as fh:
                content = fh.read()
        except (OSError, PermissionError):
            return findings

        # ── Emails ──────────────────────────────────────────────────────
        emails = set()
        for match in _EMAIL_RE.finditer(content):
            email = match.group(0)
            if not _EMAIL_EXCLUDE_RE.search(email):
                emails.add(email)

        if emails:
            findings.append(self._finding(
                "HIGH",
                f"Email address(es) found in {filepath}",
                f"Found {len(emails)} email(s): {', '.join(sorted(emails)[:5])}"
                + (f" ... and {len(emails) - 5} more" if len(emails) > 5 else ""),
            ))

        # ── Real IP addresses ───────────────────────────────────────────
        real_ips = set()
        for match in _IP_RE.finditer(content):
            ip = match.group(1)
            # Validate each octet is 0-255.
            octets = ip.split(".")
            if all(0 <= int(o) <= 255 for o in octets) and not _IP_IGNORE.match(ip):
                real_ips.add(ip)

        if real_ips:
            findings.append(self._finding(
                "HIGH",
                f"Real IP address(es) found in {filepath}",
                f"Found {len(real_ips)} IP(s): {', '.join(sorted(real_ips)[:5])}"
                + (f" ... and {len(real_ips) - 5} more" if len(real_ips) > 5 else ""),
            ))

        # ── Phone numbers ──────────────────────────────────────────────
        phones = set()
        for match in _PHONE_RE.finditer(content):
            phones.add(match.group(0).strip())

        if phones:
            findings.append(self._finding(
                "MEDIUM",
                f"Potential phone number(s) found in {filepath}",
                f"Found {len(phones)} number(s): {', '.join(sorted(phones)[:5])}"
                + (f" ... and {len(phones) - 5} more" if len(phones) > 5 else ""),
            ))

        # ── Discord IDs ────────────────────────────────────────────────
        discord_ids = set()
        for match in _DISCORD_ID_RE.finditer(content):
            discord_ids.add(match.group(1))

        if discord_ids:
            findings.append(self._finding(
                "MEDIUM",
                f"Potential Discord ID(s) found in {filepath}",
                f"Found {len(discord_ids)} ID(s): {', '.join(sorted(discord_ids)[:5])}"
                + (f" ... and {len(discord_ids) - 5} more" if len(discord_ids) > 5 else ""),
            ))

        # ── SSH private keys ───────────────────────────────────────────
        if _SSH_KEY_RE.search(content):
            # Ignore example/placeholder keys.
            if "ExampleKey" not in content:
                findings.append(self._finding(
                    "HIGH",
                    f"SSH private key material found in {filepath}",
                    "File contains what appears to be a real SSH private key.",
                ))

        return findings
