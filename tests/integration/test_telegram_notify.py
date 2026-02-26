"""Tests for scanner.telegram — message formatting and sending."""

from unittest.mock import patch, MagicMock

from scanner.telegram import send_digest, _format_message, _send_message
from scanner.models import Finding, Severity


class TestFormatMessage:
    def test_contains_repo_name(self, sample_findings):
        msg = _format_message(sample_findings, "owner/repo", "")
        assert "owner/repo" in msg

    def test_severity_counts(self, sample_findings):
        msg = _format_message(sample_findings, "repo", "")
        assert "🔴 Critical: 1" in msg
        assert "🟠 High: 1" in msg
        assert "🟡 Medium: 1" in msg
        assert "🔵 Low: 0" in msg

    def test_top_findings_shown(self, sample_findings):
        msg = _format_message(sample_findings, "repo", "")
        assert "⚠️ Top findings:" in msg
        # critical + high should appear
        assert "AWS Access Key ID" in msg
        assert "lodash" in msg

    def test_issues_url_included(self, sample_findings):
        url = "https://github.com/owner/repo/issues?q=label%3Asecurity"
        msg = _format_message(sample_findings, "repo", url)
        assert url in msg

    def test_clean_scan_message(self, empty_findings):
        msg = _format_message(empty_findings, "repo", "")
        assert "✅ No vulnerabilities found!" in msg
        assert "⚠️ Top findings:" not in msg

    def test_date_present(self, empty_findings):
        msg = _format_message(empty_findings, "repo", "")
        assert "📅" in msg
        assert "UTC" in msg

    def test_max_five_top_findings(self):
        """Only up to 5 critical/high findings are shown."""
        findings = [
            Finding(f"Issue {i}", "desc", Severity.CRITICAL, "secret")
            for i in range(10)
        ]
        msg = _format_message(findings, "repo", "")
        # Count lines with 🔴 under "Top findings"
        lines = msg.split("\n")
        top_section = False
        top_count = 0
        for line in lines:
            if "⚠️ Top findings:" in line:
                top_section = True
                continue
            if top_section:
                if line.strip().startswith("🔴") or line.strip().startswith("🟠"):
                    top_count += 1
                elif line.strip() == "":
                    break
        assert top_count == 5


class TestSendDigest:
    def test_returns_false_without_credentials(self, sample_findings):
        result = send_digest(sample_findings, "repo", "", "", "")
        assert result is False

    def test_returns_false_without_chat_id(self, sample_findings):
        result = send_digest(sample_findings, "repo", "token", "", "")
        assert result is False

    @patch("scanner.telegram._send_message", return_value=True)
    def test_calls_send_with_formatted_message(self, mock_send, sample_findings):
        result = send_digest(sample_findings, "repo", "bot-token", "chat-123", "url")
        assert result is True
        mock_send.assert_called_once()
        args = mock_send.call_args[0]
        assert args[0] == "bot-token"
        assert args[1] == "chat-123"
        assert "repo" in args[2]


class TestSendMessage:
    @patch("scanner.telegram.urllib.request.urlopen")
    def test_successful_send(self, mock_urlopen):
        resp = MagicMock()
        resp.status = 200
        resp.__enter__ = MagicMock(return_value=resp)
        resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = resp

        result = _send_message("token", "chat", "hello")
        assert result is True

    @patch("scanner.telegram.urllib.request.urlopen")
    def test_failed_send(self, mock_urlopen):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("timeout")

        result = _send_message("token", "chat", "hello")
        assert result is False

    @patch("scanner.telegram.urllib.request.urlopen")
    def test_request_url_format(self, mock_urlopen):
        resp = MagicMock()
        resp.status = 200
        resp.__enter__ = MagicMock(return_value=resp)
        resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = resp

        _send_message("mytoken", "mychat", "msg")

        req = mock_urlopen.call_args[0][0]
        assert "api.telegram.org/botmytoken/sendMessage" in req.full_url
