"""Secret detection via regex pattern matching."""

import os
import re
from typing import List

from scanner.models import Finding, Severity

# (pattern_name, regex, severity)
SECRET_PATTERNS = [
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}"), Severity.CRITICAL),
    ("AWS Secret Access Key", re.compile(r"""(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"""), Severity.CRITICAL),
    ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"), Severity.CRITICAL),
    ("GitHub Personal Access Token (classic)", re.compile(r"ghp_[A-Za-z0-9_]{36,255}"), Severity.CRITICAL),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), Severity.HIGH),
    ("Vercel Token", re.compile(r"""(?:VERCEL_TOKEN|vercel_token)\s*[=:]\s*['"]?([A-Za-z0-9_]{24,})['"]?"""), Severity.HIGH),
    ("Generic API Key", re.compile(r"""(?:api[_-]?key|apikey|API_KEY)\s*[=:]\s*['"]([A-Za-z0-9_\-]{20,})['"]""", re.IGNORECASE), Severity.MEDIUM),
    ("Generic Secret", re.compile(r"""(?:secret|SECRET|password|PASSWORD)\s*[=:]\s*['"]([^'"]{8,})['"]"""), Severity.MEDIUM),
    ("Private Key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), Severity.CRITICAL),
    ("Connection String", re.compile(r"""(?:mongodb\+srv|mongodb|postgres|postgresql|mysql|mssql|redis)://[^\s'"]+""", re.IGNORECASE), Severity.HIGH),
    ("Slack Webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"), Severity.HIGH),
    ("Telegram Bot Token", re.compile(r"\d{8,10}:[A-Za-z0-9_-]{35}"), Severity.HIGH),
]

SKIP_EXTENSIONS = {
    ".lock", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff",
    ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".zip", ".tar", ".gz",
    ".pdf", ".min.js", ".min.css", ".map",
}

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".next", "dist", "build",
    ".venv", "venv", "vendor", ".security-scanner",
}


def run(scan_path: str) -> List[Finding]:
    findings: List[Finding] = []

    for root, dirs, files in os.walk(scan_path):
        # Skip directories in-place
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for filename in files:
            ext = os.path.splitext(filename)[1].lower()
            if ext in SKIP_EXTENSIONS:
                continue

            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, scan_path)

            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    for line_num, line in enumerate(f, start=1):
                        for pattern_name, pattern, severity in SECRET_PATTERNS:
                            if pattern.search(line):
                                # Mask the actual secret in the description
                                masked_line = line.strip()
                                if len(masked_line) > 100:
                                    masked_line = masked_line[:100] + "..."

                                findings.append(Finding(
                                    title=f"[secret] {pattern_name} in {rel_path}",
                                    description=f"Potential {pattern_name} found at line {line_num}",
                                    severity=severity,
                                    category="secret",
                                    file_path=rel_path,
                                    line_number=line_num,
                                    remediation=(
                                        "Remove the secret from source code. "
                                        "Use environment variables or a secrets manager. "
                                        "Rotate the exposed credential immediately."
                                    ),
                                ))
            except (OSError, UnicodeDecodeError):
                continue

    return findings
