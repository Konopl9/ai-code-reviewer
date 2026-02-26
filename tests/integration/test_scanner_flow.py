"""Integration test — scanner flow with mocked checks and GitHub API."""

import os
import tempfile
from unittest.mock import MagicMock, patch, call

from scanner.main import main as scanner_main, _print_summary, _create_issues, _format_issue_body
from scanner.models import Finding, ScanResult, Severity


class TestScannerFlow:
    """End-to-end scanner flow with mocked externals."""

    @patch("scanner.main.send_digest")
    @patch("scanner.main.Github")
    @patch.dict("os.environ", {
        "REPO_NAME": "Konopl9/test-repo",
        "GITHUB_TOKEN": "ghp_fake",
        "TELEGRAM_BOT_TOKEN": "",
        "TELEGRAM_CHAT_ID": "",
        "SCAN_CATEGORIES": "secrets,config",
        "CREATE_ISSUES": "false",
        "SCAN_PATH": "",
    })
    def test_scan_with_secrets_and_config(self, mock_github_cls, mock_digest):
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["SCAN_PATH"] = tmp

            # Create a file with a secret
            with open(os.path.join(tmp, "config.py"), "w") as f:
                f.write('AWS_KEY = "AKIA1234567890ABCDEF"\nDEBUG = True\n')

            gh = MagicMock()
            mock_github_cls.return_value = gh
            gh_repo = MagicMock()
            gh.get_repo.return_value = gh_repo

            # Should not exit(1) since no critical in config (secret is critical though)
            with pytest.raises(SystemExit) as exc:
                scanner_main()
            assert exc.value.code == 1  # critical secret found

            mock_digest.assert_called_once()
            findings_arg = mock_digest.call_args[0][0]
            assert len(findings_arg) >= 1

    @patch("scanner.main.send_digest")
    @patch("scanner.main.Github")
    @patch.dict("os.environ", {
        "REPO_NAME": "Konopl9/test-repo",
        "GITHUB_TOKEN": "ghp_fake",
        "SCAN_CATEGORIES": "config",
        "CREATE_ISSUES": "false",
        "SCAN_PATH": "",
    })
    def test_clean_scan_exits_zero(self, mock_github_cls, mock_digest):
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["SCAN_PATH"] = tmp
            # Empty dir — no issues
            gh = MagicMock()
            mock_github_cls.return_value = gh
            gh.get_repo.return_value = MagicMock()

            # Should complete without SystemExit
            scanner_main()
            mock_digest.assert_called_once()


class TestCreateIssues:
    def test_creates_issues_for_critical_and_high(self):
        gh_repo = MagicMock()
        gh_repo.get_labels.return_value = [MagicMock(name="security")]
        gh_repo.get_issues.return_value = []

        findings = [
            Finding("Critical bug", "desc", Severity.CRITICAL, "secret", "f.py"),
            Finding("High vuln", "desc", Severity.HIGH, "dependency"),
            Finding("Medium note", "desc", Severity.MEDIUM, "config"),
            Finding("Low item", "desc", Severity.LOW, "config"),
        ]

        _create_issues(gh_repo, findings)

        # Only critical and high should create issues
        assert gh_repo.create_issue.call_count == 2

    def test_skips_duplicate_titles(self):
        gh_repo = MagicMock()
        gh_repo.get_labels.return_value = []
        existing = MagicMock()
        existing.title = "Critical bug"
        gh_repo.get_issues.return_value = [existing]

        findings = [
            Finding("Critical bug", "desc", Severity.CRITICAL, "secret"),
            Finding("New issue", "desc", Severity.HIGH, "dependency"),
        ]

        _create_issues(gh_repo, findings)
        assert gh_repo.create_issue.call_count == 1
        assert gh_repo.create_issue.call_args[1]["title"] == "New issue"

    def test_no_actionable_findings(self):
        gh_repo = MagicMock()
        findings = [
            Finding("Info note", "desc", Severity.INFO, "config"),
            Finding("Low item", "desc", Severity.LOW, "config"),
        ]
        _create_issues(gh_repo, findings)
        gh_repo.create_issue.assert_not_called()


class TestFormatIssueBody:
    def test_contains_severity_and_description(self):
        finding = Finding(
            title="Test",
            description="Something is wrong",
            severity=Severity.CRITICAL,
            category="secret",
            file_path="secret.py",
            line_number=42,
            remediation="Fix it",
        )
        body = _format_issue_body(finding)
        assert "🔴" in body
        assert "CRITICAL" in body
        assert "Something is wrong" in body
        assert "`secret.py`" in body
        assert "42" in body
        assert "Fix it" in body

    def test_no_file_path(self):
        finding = Finding("T", "D", Severity.HIGH, "dep")
        body = _format_issue_body(finding)
        assert "File:" not in body


class TestPrintSummary:
    def test_prints_counts(self, capsys):
        result = ScanResult(
            repo="test/repo",
            findings=[
                Finding("A", "d", Severity.CRITICAL, "secret"),
                Finding("B", "d", Severity.HIGH, "dep"),
                Finding("C", "d", Severity.HIGH, "dep"),
            ],
            errors=["some error"],
        )
        _print_summary(result)
        output = capsys.readouterr().out
        assert "Critical: 1" in output
        assert "High:     2" in output
        assert "Total:       3" in output
        assert "Errors:   1" in output


# Need pytest import for SystemExit
import pytest
