"""Dependency CVE scanning via npm audit and pip-audit."""

import json
import os
import shutil
import subprocess
from typing import List

from scanner.models import Finding, Severity

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def run(scan_path: str) -> List[Finding]:
    findings: List[Finding] = []

    if os.path.isfile(os.path.join(scan_path, "package.json")):
        findings.extend(_npm_audit(scan_path))

    if os.path.isfile(os.path.join(scan_path, "requirements.txt")):
        findings.extend(_pip_audit(scan_path))

    return findings


def _npm_audit(scan_path: str) -> List[Finding]:
    findings: List[Finding] = []

    if not shutil.which("npm"):
        return findings

    # Install deps first so audit has a lockfile to work with
    subprocess.run(
        ["npm", "install", "--package-lock-only", "--ignore-scripts"],
        cwd=scan_path,
        capture_output=True,
        timeout=120,
    )

    result = subprocess.run(
        ["npm", "audit", "--json"],
        cwd=scan_path,
        capture_output=True,
        text=True,
        timeout=120,
    )

    try:
        data = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        return findings

    vulnerabilities = data.get("vulnerabilities", {})
    for pkg_name, vuln_info in vulnerabilities.items():
        severity_str = vuln_info.get("severity", "info").lower()
        severity = SEVERITY_MAP.get(severity_str, Severity.INFO)

        via = vuln_info.get("via", [])
        description_parts = []
        cve_ids = []
        for v in via:
            if isinstance(v, dict):
                desc = v.get("title", "")
                if desc:
                    description_parts.append(desc)
                url = v.get("url", "")
                if url:
                    description_parts.append(url)
                cve = v.get("cve")
                if cve:
                    cve_ids.append(cve)

        cve_str = ", ".join(cve_ids) if cve_ids else "N/A"
        description = "; ".join(description_parts) if description_parts else "Vulnerability detected"
        fix_available = vuln_info.get("fixAvailable", False)
        remediation = "Fix available via `npm audit fix`" if fix_available else "No automatic fix available"

        findings.append(Finding(
            title=f"[npm] {pkg_name}: {cve_str}",
            description=description,
            severity=severity,
            category="dependency",
            file_path="package.json",
            remediation=remediation,
        ))

    return findings


def _pip_audit(scan_path: str) -> List[Finding]:
    findings: List[Finding] = []

    if not shutil.which("pip-audit"):
        return findings

    result = subprocess.run(
        ["pip-audit", "--format=json", "--requirement",
         os.path.join(scan_path, "requirements.txt")],
        capture_output=True,
        text=True,
        timeout=120,
    )

    try:
        data = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        return findings

    dependencies = data if isinstance(data, list) else data.get("dependencies", [])
    for dep in dependencies:
        vulns = dep.get("vulns", [])
        for vuln in vulns:
            vuln_id = vuln.get("id", "N/A")
            description = vuln.get("description", "Vulnerability detected")
            fix_versions = vuln.get("fix_versions", [])
            severity = Severity.HIGH  # pip-audit doesn't always provide severity

            remediation = (
                f"Upgrade to version {', '.join(fix_versions)}"
                if fix_versions
                else "No fix version available"
            )

            findings.append(Finding(
                title=f"[pip] {dep.get('name', 'unknown')}: {vuln_id}",
                description=description,
                severity=severity,
                category="dependency",
                file_path="requirements.txt",
                remediation=remediation,
            ))

    return findings
