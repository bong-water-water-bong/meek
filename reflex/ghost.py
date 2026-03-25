"""Reflex Agent: Secret Scanner (ghost)

Scans the halo-ai codebase and configuration directories for leaked
secrets, private keys, cloud credentials, and exposed .env files.
"""

import os
import re
import stat
import subprocess

from .base import ReflexAgent


# ------------------------------------------------------------------ patterns

# Private keys — always CRITICAL
RE_PRIVATE_KEY = re.compile(
    r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"
    r"|-----BEGIN\s+EC\s+PRIVATE\s+KEY-----"
    r"|-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----"
)

# AWS access key IDs (start with AKIA)
RE_AWS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")

# GCP service account JSON (project_id + private_key_id in same file)
RE_GCP_SA = re.compile(r'"type"\s*:\s*"service_account"')

# Generic tokens / passwords assigned a real value
# Matches: token=abc123, api_key="secret", password='val', SECRET=something
RE_TOKEN_ASSIGN = re.compile(
    r"""(?:token|api_key|apikey|secret|password|passwd|auth)"""
    r"""[\s]*[=:][\s]*['"]?"""
    r"""([A-Za-z0-9+/=_\-]{12,})""",
    re.IGNORECASE,
)

# Long hex strings (>32 chars) that look like keys
RE_HEX_KEY = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{33,}(?![A-Fa-f0-9])")

# Long base64 strings (>40 chars, with mixed case + digits)
RE_BASE64_KEY = re.compile(
    r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/])"
)

# Known default / weak passwords
DEFAULT_PASSWORDS = [
    "admin", "password", "changeme", "letmein", "12345678",
    "default", "root", "toor", "passw0rd", "qwerty",
]
RE_DEFAULT_PW = re.compile(
    r"""(?:password|passwd|pass)[\s]*[=:][\s]*['"]?"""
    + r"(?:" + "|".join(re.escape(p) for p in DEFAULT_PASSWORDS) + r")"
    + r"""['"]?\s*$""",
    re.IGNORECASE | re.MULTILINE,
)

# ---------------------------------------------------------- placeholder guard
# Values that are obviously placeholders — skip them
RE_PLACEHOLDER = re.compile(
    r"<YOUR_\w+>"
    r"|xxx\.xxx"
    r"|CHANGEME"
    r"|not-needed"
    r"|REPLACE_ME"
    r"|TODO"
    r"|example\.com"
    r"|\$\{.+\}"           # shell/env variable references
    r"|%\(.+\)s"           # python %-formatting
    r"|\{\{.+\}\}",        # jinja / template vars
    re.IGNORECASE,
)

# ----------------------------------------------- directories / files to skip

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", "venv", ".venv",
    "env", ".env.d", ".tox", ".mypy_cache", ".pytest_cache",
    "site-packages",
}

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".svg",
    ".woff", ".woff2", ".ttf", ".eot",
    ".zip", ".gz", ".tar", ".bz2", ".xz", ".7z",
    ".bin", ".so", ".dylib", ".dll", ".exe", ".o", ".a",
    ".gguf", ".safetensors", ".pt", ".pth", ".onnx",
    ".db", ".sqlite", ".sqlite3",
    ".pdf", ".doc", ".docx",
    ".pyc", ".class",
}

SCAN_ROOTS = ["/srv/ai/", "/home/"]
MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MiB — skip larger files


class GhostAgent(ReflexAgent):
    """Secret scanner for halo-ai codebase and configs."""

    name = "ghost"
    description = "Scans halo-ai codebase and configs for leaked secrets"
    schedule = "daily"

    # ---------------------------------------------------------------- helpers

    @staticmethod
    def _is_skippable_dir(dirname):
        return dirname in SKIP_DIRS

    @staticmethod
    def _is_binary(filepath):
        _, ext = os.path.splitext(filepath)
        return ext.lower() in BINARY_EXTENSIONS

    @staticmethod
    def _is_placeholder(value):
        return bool(RE_PLACEHOLDER.search(value))

    def _read_file(self, filepath):
        """Read a text file, returning None on failure."""
        try:
            size = os.path.getsize(filepath)
            if size > MAX_FILE_SIZE:
                return None
            with open(filepath, "r", errors="ignore") as fh:
                return fh.read()
        except (OSError, IOError):
            return None

    # ----------------------------------------------------------- scan a file

    def _scan_file(self, filepath):
        """Return a list of finding dicts for a single file."""
        findings = []
        content = self._read_file(filepath)
        if content is None:
            return findings

        basename = os.path.basename(filepath)
        is_env_file = basename.startswith(".env")

        # --- private keys (CRITICAL) ---
        if RE_PRIVATE_KEY.search(content):
            findings.append({
                "id": f"ghost:private-key:{filepath}",
                "severity": "CRITICAL",
                "title": "Private key found",
                "detail": f"Private key material detected in {filepath}",
                "path": filepath,
                "fixable": True,
            })

        # --- AWS credentials (CRITICAL) ---
        for m in RE_AWS_KEY.finditer(content):
            line = content[max(0, m.start() - 40):m.end() + 40]
            if not self._is_placeholder(line):
                findings.append({
                    "id": f"ghost:aws-key:{filepath}:{m.start()}",
                    "severity": "CRITICAL",
                    "title": "AWS access key found",
                    "detail": f"AWS key ID {m.group()[:8]}... in {filepath}",
                    "path": filepath,
                    "fixable": True,
                })

        # --- GCP service account (CRITICAL) ---
        if RE_GCP_SA.search(content):
            findings.append({
                "id": f"ghost:gcp-sa:{filepath}",
                "severity": "CRITICAL",
                "title": "GCP service account JSON found",
                "detail": f"Service account credentials in {filepath}",
                "path": filepath,
                "fixable": True,
            })

        # --- token / password assignments (HIGH) ---
        for m in RE_TOKEN_ASSIGN.finditer(content):
            value = m.group(1)
            context = m.group(0)
            if self._is_placeholder(context):
                continue
            # skip very short matches that are likely false positives
            if len(value) < 12:
                continue
            findings.append({
                "id": f"ghost:token:{filepath}:{m.start()}",
                "severity": "HIGH",
                "title": "Secret token/password assignment",
                "detail": f"Possible secret assigned in {filepath}",
                "path": filepath,
                "fixable": True,
            })

        # --- default passwords (HIGH) ---
        if RE_DEFAULT_PW.search(content):
            findings.append({
                "id": f"ghost:default-pw:{filepath}",
                "severity": "HIGH",
                "title": "Default/weak password detected",
                "detail": f"Known default password in {filepath}",
                "path": filepath,
                "fixable": True,
            })

        # --- long hex keys (HIGH) — only in non-.env config-like files ---
        for m in RE_HEX_KEY.finditer(content):
            context = content[max(0, m.start() - 60):m.end() + 20]
            if self._is_placeholder(context):
                continue
            findings.append({
                "id": f"ghost:hex-key:{filepath}:{m.start()}",
                "severity": "HIGH",
                "title": "Long hex string (possible key)",
                "detail": f"Hex string ({len(m.group())} chars) in {filepath}",
                "path": filepath,
                "fixable": True,
            })
            break  # one finding per file is enough for hex noise

        # --- .env files with real values (MEDIUM) ---
        if is_env_file:
            real_values = False
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    _, _, val = line.partition("=")
                    val = val.strip().strip("'\"")
                    if val and not self._is_placeholder(val):
                        real_values = True
                        break
            if real_values:
                # Check permissions
                try:
                    mode = os.stat(filepath).st_mode
                    world_readable = mode & stat.S_IROTH
                except OSError:
                    world_readable = False
                findings.append({
                    "id": f"ghost:env-file:{filepath}",
                    "severity": "MEDIUM",
                    "title": ".env file with real values",
                    "detail": f"{filepath} contains non-placeholder values"
                             + (" (world-readable)" if world_readable else ""),
                    "path": filepath,
                    "fixable": True,
                })

        return findings

    # ---------------------------------------------------------- walk and scan

    def _walk_roots(self):
        """Yield all scannable file paths under SCAN_ROOTS."""
        for root_dir in SCAN_ROOTS:
            if not os.path.isdir(root_dir):
                continue
            for dirpath, dirnames, filenames in os.walk(root_dir):
                # Prune skippable directories in-place
                dirnames[:] = [
                    d for d in dirnames if not self._is_skippable_dir(d)
                ]
                for fname in filenames:
                    fpath = os.path.join(dirpath, fname)
                    if self._is_binary(fpath):
                        continue
                    # Skip symlinks to avoid loops
                    if os.path.islink(fpath):
                        continue
                    yield fpath

    # ------------------------------------------------------------------ scan

    def scan(self) -> dict:
        findings = []
        files_scanned = 0

        for fpath in self._walk_roots():
            file_findings = self._scan_file(fpath)
            if file_findings:
                findings.extend(file_findings)
            files_scanned += 1

        # Deduplicate by id
        seen = set()
        unique = []
        for f in findings:
            if f["id"] not in seen:
                seen.add(f["id"])
                unique.append(f)
        findings = unique

        # Overall severity
        if not findings:
            severity = "PASS"
        elif any(f["severity"] == "CRITICAL" for f in findings):
            severity = "CRITICAL"
        elif any(f["severity"] == "HIGH" for f in findings):
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        return {
            "agent": self.name,
            "severity": severity,
            "findings": findings,
            "files_scanned": files_scanned,
            "summary": (
                f"{len(findings)} secret(s) found across {files_scanned} files"
                if findings
                else f"No secrets found ({files_scanned} files scanned)"
            ),
        }

    # --------------------------------------------------------------- auto-fix

    def can_auto_fix(self, finding) -> bool:
        return finding.get("fixable", False) and "path" in finding

    def auto_fix(self, finding) -> bool:
        """Set file permissions to 600 (owner read/write only)."""
        filepath = finding.get("path")
        if not filepath or not os.path.isfile(filepath):
            return False
        try:
            os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
            return True
        except OSError:
            return False
