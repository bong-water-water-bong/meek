"""
ReflexAgent — base class for all Meek security agents.

Every agent module under reflex/ should subclass ReflexAgent
and implement at minimum the scan() method.
"""

import datetime


class ReflexAgent:
    """Base class for Meek reflex agents."""

    name: str = "base"
    description: str = ""
    schedule: str = "hourly"  # continuous | hourly | daily

    def scan(self) -> dict:
        """
        Run the security scan.

        Must return a dict with at least:
            severity     — "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "PASS"
            findings     — list of finding dicts
            auto_fixed   — list of strings describing auto-remediated issues

        Each finding dict:
            severity      — same scale as above
            title         — short human-readable summary
            detail        — longer explanation
            auto_fixable  — bool, whether auto_fix() can handle it
        """
        raise NotImplementedError(f"{self.__class__.__name__} must implement scan()")

    def can_auto_fix(self, finding: dict) -> bool:
        """Return True if this finding can be auto-remediated."""
        return False

    def auto_fix(self, finding: dict) -> bool:
        """
        Attempt to auto-fix a finding.

        Return True on success, False on failure.
        """
        return False

    # ── Helpers available to all agents ────────────────────────────────────

    @staticmethod
    def _now_iso() -> str:
        """Return current UTC time as ISO-8601 string."""
        return datetime.datetime.utcnow().isoformat()

    def _result(self, severity: str = "PASS", findings: list = None, auto_fixed: list = None) -> dict:
        """Convenience builder for the standard result dict."""
        return {
            "agent": self.name,
            "timestamp": self._now_iso(),
            "severity": severity,
            "findings": findings or [],
            "auto_fixed": auto_fixed or [],
        }

    def _finding(self, severity: str, title: str, detail: str = "", auto_fixable: bool = False) -> dict:
        """Convenience builder for a single finding dict."""
        return {
            "severity": severity,
            "title": title,
            "detail": detail,
            "auto_fixable": auto_fixable,
        }
