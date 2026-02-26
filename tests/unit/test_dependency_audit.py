"""Tests for scanner.checks.dependency_audit — npm audit / pip-audit parsing."""

import json
from unittest.mock import patch, MagicMock

from scanner.checks.dependency_audit import run, _npm_audit, _pip_audit, SEVERITY_MAP
from scanner.models import Severity


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

class TestSeverityMap:
    def test_critical_maps(self):
        assert SEVERITY_MAP["critical"] == Severity.CRITICAL

    def test_high_maps(self):
        assert SEVERITY_MAP["high"] == Severity.HIGH

    def test_moderate_maps_to_medium(self):
        assert SEVERITY_MAP["moderate"] == Severity.MEDIUM

    def test_medium_maps(self):
        assert SEVERITY_MAP["medium"] == Severity.MEDIUM

    def test_low_maps(self):
        assert SEVERITY_MAP["low"] == Severity.LOW

    def test_info_maps(self):
        assert SEVERITY_MAP["info"] == Severity.INFO


# ---------------------------------------------------------------------------
# npm audit parsing
# ---------------------------------------------------------------------------

NPM_AUDIT_OUTPUT = json.dumps({
    "vulnerabilities": {
        "lodash": {
            "severity": "high",
            "via": [
                {
                    "title": "Prototype Pollution",
                    "url": "https://github.com/advisories/GHSA-1234",
                    "cve": "CVE-2021-23337",
                }
            ],
            "fixAvailable": True,
        },
        "minimist": {
            "severity": "critical",
            "via": [
                {
                    "title": "Prototype Pollution in minimist",
                    "url": "https://npmjs.com/advisories/1179",
                    "cve": "CVE-2020-7598",
                }
            ],
            "fixAvailable": False,
        },
    }
})


class TestNpmAudit:
    @patch("scanner.checks.dependency_audit.subprocess.run")
    @patch("scanner.checks.dependency_audit.shutil.which", return_value="/usr/bin/npm")
    @patch("scanner.checks.dependency_audit.os.path.isfile", return_value=True)
    def test_parses_vulnerabilities(self, mock_isfile, mock_which, mock_run):
        # First call: npm install, second: npm audit
        install_result = MagicMock(returncode=0)
        audit_result = MagicMock(stdout=NPM_AUDIT_OUTPUT, returncode=1)
        mock_run.side_effect = [install_result, audit_result]

        findings = _npm_audit("/fake/path")

        assert len(findings) == 2
        titles = {f.title for f in findings}
        assert "[npm] lodash: CVE-2021-23337" in titles
        assert "[npm] minimist: CVE-2020-7598" in titles

    @patch("scanner.checks.dependency_audit.subprocess.run")
    @patch("scanner.checks.dependency_audit.shutil.which", return_value="/usr/bin/npm")
    @patch("scanner.checks.dependency_audit.os.path.isfile", return_value=True)
    def test_fix_available_in_remediation(self, mock_isfile, mock_which, mock_run):
        install_result = MagicMock(returncode=0)
        audit_result = MagicMock(stdout=NPM_AUDIT_OUTPUT, returncode=1)
        mock_run.side_effect = [install_result, audit_result]

        findings = _npm_audit("/fake/path")
        lodash = next(f for f in findings if "lodash" in f.title)
        minimist = next(f for f in findings if "minimist" in f.title)

        assert "npm audit fix" in lodash.remediation
        assert "No automatic fix" in minimist.remediation

    @patch("scanner.checks.dependency_audit.subprocess.run")
    @patch("scanner.checks.dependency_audit.shutil.which", return_value="/usr/bin/npm")
    @patch("scanner.checks.dependency_audit.os.path.isfile", return_value=True)
    def test_severity_mapping(self, mock_isfile, mock_which, mock_run):
        install_result = MagicMock(returncode=0)
        audit_result = MagicMock(stdout=NPM_AUDIT_OUTPUT, returncode=1)
        mock_run.side_effect = [install_result, audit_result]

        findings = _npm_audit("/fake/path")
        lodash = next(f for f in findings if "lodash" in f.title)
        minimist = next(f for f in findings if "minimist" in f.title)

        assert lodash.severity == Severity.HIGH
        assert minimist.severity == Severity.CRITICAL

    @patch("scanner.checks.dependency_audit.shutil.which", return_value=None)
    def test_npm_not_installed_returns_empty(self, mock_which):
        assert _npm_audit("/fake") == []

    @patch("scanner.checks.dependency_audit.subprocess.run")
    @patch("scanner.checks.dependency_audit.shutil.which", return_value="/usr/bin/npm")
    @patch("scanner.checks.dependency_audit.os.path.isfile", return_value=True)
    def test_invalid_json_returns_empty(self, mock_isfile, mock_which, mock_run):
        install_result = MagicMock(returncode=0)
        audit_result = MagicMock(stdout="not json", returncode=1)
        mock_run.side_effect = [install_result, audit_result]

        assert _npm_audit("/fake") == []


# ---------------------------------------------------------------------------
# pip-audit parsing
# ---------------------------------------------------------------------------

PIP_AUDIT_OUTPUT = json.dumps({
    "dependencies": [
        {
            "name": "django",
            "version": "3.2.0",
            "vulns": [
                {
                    "id": "PYSEC-2021-1",
                    "description": "XSS in Django admin",
                    "fix_versions": ["3.2.1"],
                }
            ],
        },
        {
            "name": "requests",
            "version": "2.25.0",
            "vulns": [],
        },
    ]
})


class TestPipAudit:
    @patch("scanner.checks.dependency_audit.subprocess.run")
    @patch("scanner.checks.dependency_audit.shutil.which", return_value="/usr/bin/pip-audit")
    @patch("scanner.checks.dependency_audit.os.path.isfile", return_value=True)
    def test_parses_vulnerabilities(self, mock_isfile, mock_which, mock_run):
        mock_run.return_value = MagicMock(stdout=PIP_AUDIT_OUTPUT, returncode=0)

        findings = _pip_audit("/fake/path")
        assert len(findings) == 1
        assert "django" in findings[0].title
        assert "PYSEC-2021-1" in findings[0].title

    @patch("scanner.checks.dependency_audit.subprocess.run")
    @patch("scanner.checks.dependency_audit.shutil.which", return_value="/usr/bin/pip-audit")
    @patch("scanner.checks.dependency_audit.os.path.isfile", return_value=True)
    def test_fix_versions_in_remediation(self, mock_isfile, mock_which, mock_run):
        mock_run.return_value = MagicMock(stdout=PIP_AUDIT_OUTPUT, returncode=0)

        findings = _pip_audit("/fake/path")
        assert "3.2.1" in findings[0].remediation

    @patch("scanner.checks.dependency_audit.shutil.which", return_value=None)
    def test_pip_audit_not_installed(self, mock_which):
        assert _pip_audit("/fake") == []

    @patch("scanner.checks.dependency_audit.subprocess.run")
    @patch("scanner.checks.dependency_audit.shutil.which", return_value="/usr/bin/pip-audit")
    @patch("scanner.checks.dependency_audit.os.path.isfile", return_value=True)
    def test_list_format_supported(self, mock_isfile, mock_which, mock_run):
        """pip-audit can return a bare list instead of {dependencies: [...]}."""
        bare_list = json.dumps([
            {"name": "flask", "version": "1.0", "vulns": [
                {"id": "CVE-2023-1234", "description": "RCE", "fix_versions": ["2.0"]}
            ]}
        ])
        mock_run.return_value = MagicMock(stdout=bare_list, returncode=0)

        findings = _pip_audit("/fake/path")
        assert len(findings) == 1
        assert "flask" in findings[0].title


# ---------------------------------------------------------------------------
# run() dispatcher
# ---------------------------------------------------------------------------

class TestRunDispatcher:
    @patch("scanner.checks.dependency_audit._pip_audit", return_value=[])
    @patch("scanner.checks.dependency_audit._npm_audit", return_value=[])
    @patch("scanner.checks.dependency_audit.os.path.isfile")
    def test_runs_npm_when_package_json_exists(self, mock_isfile, mock_npm, mock_pip):
        mock_isfile.side_effect = lambda p: "package.json" in p

        run("/fake")
        mock_npm.assert_called_once_with("/fake")
        mock_pip.assert_not_called()

    @patch("scanner.checks.dependency_audit._pip_audit", return_value=[])
    @patch("scanner.checks.dependency_audit._npm_audit", return_value=[])
    @patch("scanner.checks.dependency_audit.os.path.isfile")
    def test_runs_pip_when_requirements_exists(self, mock_isfile, mock_npm, mock_pip):
        mock_isfile.side_effect = lambda p: "requirements.txt" in p

        run("/fake")
        mock_pip.assert_called_once_with("/fake")
        mock_npm.assert_not_called()

    @patch("scanner.checks.dependency_audit._pip_audit", return_value=[])
    @patch("scanner.checks.dependency_audit._npm_audit", return_value=[])
    @patch("scanner.checks.dependency_audit.os.path.isfile", return_value=True)
    def test_runs_both_when_both_exist(self, mock_isfile, mock_npm, mock_pip):
        run("/fake")
        mock_npm.assert_called_once()
        mock_pip.assert_called_once()
