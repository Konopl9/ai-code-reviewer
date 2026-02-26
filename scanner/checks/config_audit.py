"""Configuration security audit."""

import json
import os
import re
from typing import List

from scanner.models import Finding, Severity

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".next", "dist", "build",
    ".venv", "venv", "vendor", ".security-scanner",
}


def run(scan_path: str) -> List[Finding]:
    findings: List[Finding] = []
    findings.extend(_check_debug_mode(scan_path))
    findings.extend(_check_cors_wildcard(scan_path))
    findings.extend(_check_docker_compose(scan_path))
    findings.extend(_check_env_files(scan_path))
    return findings


def _check_debug_mode(scan_path: str) -> List[Finding]:
    """Check for debug mode enabled in configuration files."""
    findings: List[Finding] = []
    patterns = [
        (re.compile(r"""['"]?DEBUG['"]?\s*[=:]\s*['"]?[Tt]rue['"]?"""), "DEBUG=True"),
        (re.compile(r"""FLASK_DEBUG\s*=\s*['"]?1['"]?"""), "FLASK_DEBUG=1"),
        (re.compile(r"""NODE_ENV\s*=\s*['"]?development['"]?"""), "NODE_ENV=development"),
    ]

    config_files = _find_config_files(scan_path)
    for filepath in config_files:
        rel_path = os.path.relpath(filepath, scan_path)
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                for pattern, desc in patterns:
                    match = pattern.search(content)
                    if match:
                        findings.append(Finding(
                            title=f"[config] Debug mode enabled: {desc}",
                            description=f"Debug mode appears to be enabled in {rel_path}",
                            severity=Severity.MEDIUM,
                            category="config",
                            file_path=rel_path,
                            remediation="Disable debug mode in production configurations.",
                        ))
        except OSError:
            continue
    return findings


def _check_cors_wildcard(scan_path: str) -> List[Finding]:
    """Check for CORS wildcard configuration."""
    findings: List[Finding] = []
    patterns = [
        re.compile(r"""cors.*['"]\*['"]""", re.IGNORECASE),
        re.compile(r"""Access-Control-Allow-Origin.*\*""", re.IGNORECASE),
        re.compile(r"""AllowAnyOrigin"""),
    ]

    for root, dirs, files in os.walk(scan_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for filename in files:
            ext = os.path.splitext(filename)[1].lower()
            if ext not in {".py", ".js", ".ts", ".jsx", ".tsx", ".cs", ".json", ".yaml", ".yml", ".conf"}:
                continue
            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, scan_path)
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    for line_num, line in enumerate(f, start=1):
                        for pattern in patterns:
                            if pattern.search(line):
                                findings.append(Finding(
                                    title=f"[config] CORS wildcard in {rel_path}",
                                    description=f"CORS wildcard (*) allows any origin at line {line_num}",
                                    severity=Severity.MEDIUM,
                                    category="config",
                                    file_path=rel_path,
                                    line_number=line_num,
                                    remediation="Restrict CORS to specific trusted origins.",
                                ))
                                break  # one finding per file per pattern type is enough
            except OSError:
                continue
    return findings


def _check_docker_compose(scan_path: str) -> List[Finding]:
    """Check docker-compose for exposed ports and privileged mode."""
    findings: List[Finding] = []
    compose_files = [
        "docker-compose.yml", "docker-compose.yaml",
        "compose.yml", "compose.yaml",
    ]

    for fname in compose_files:
        filepath = os.path.join(scan_path, fname)
        if not os.path.isfile(filepath):
            continue

        rel_path = os.path.relpath(filepath, scan_path)
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Check for host-bound ports (0.0.0.0 or no bind address)
            port_pattern = re.compile(r"""['"]?(\d+):(\d+)['"]?""")
            for match in port_pattern.finditer(content):
                host_port = match.group(1)
                findings.append(Finding(
                    title=f"[config] Exposed port {host_port} in {rel_path}",
                    description=f"Port {host_port} is exposed to the host in {rel_path}",
                    severity=Severity.LOW,
                    category="config",
                    file_path=rel_path,
                    remediation="Bind ports to 127.0.0.1 if not needed externally.",
                ))

            if "privileged: true" in content:
                findings.append(Finding(
                    title=f"[config] Privileged container in {rel_path}",
                    description="Container running in privileged mode",
                    severity=Severity.HIGH,
                    category="config",
                    file_path=rel_path,
                    remediation="Remove privileged mode and use specific capabilities instead.",
                ))
        except OSError:
            continue

    return findings


def _check_env_files(scan_path: str) -> List[Finding]:
    """Check for .env files that might be committed."""
    findings: List[Finding] = []
    env_patterns = [".env", ".env.local", ".env.production"]

    for env_file in env_patterns:
        filepath = os.path.join(scan_path, env_file)
        if os.path.isfile(filepath):
            rel_path = os.path.relpath(filepath, scan_path)
            findings.append(Finding(
                title=f"[config] Environment file committed: {rel_path}",
                description=f"Environment file {rel_path} is present in the repository",
                severity=Severity.HIGH,
                category="config",
                file_path=rel_path,
                remediation="Add environment files to .gitignore and use CI/CD secrets.",
            ))

    return findings


def _find_config_files(scan_path: str) -> List[str]:
    """Find common configuration files."""
    config_names = {
        ".env", ".env.local", ".env.production", ".env.development",
        "settings.py", "config.py", "app.config.js", "app.config.ts",
        "next.config.js", "next.config.ts", "next.config.mjs",
        "appsettings.json", "appsettings.Development.json",
        "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    }
    found = []
    for root, dirs, files in os.walk(scan_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for filename in files:
            if filename in config_names:
                found.append(os.path.join(root, filename))
    return found
