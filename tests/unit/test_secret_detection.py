"""Tests for scanner.checks.secret_detection — regex patterns."""

import os
import tempfile

from scanner.checks.secret_detection import run, SECRET_PATTERNS, SKIP_EXTENSIONS, SKIP_DIRS
from scanner.models import Severity


def _scan_text(text: str, filename: str = "test.py"):
    """Helper: write text to a temp dir and run the scanner."""
    with tempfile.TemporaryDirectory() as tmp:
        filepath = os.path.join(tmp, filename)
        with open(filepath, "w") as f:
            f.write(text)
        return run(tmp)


class TestAWSPatterns:
    def test_aws_access_key_detected(self):
        findings = _scan_text('key = "AKIA1234567890ABCDEF"')
        assert any("AWS Access Key ID" in f.title for f in findings)
        assert findings[0].severity == Severity.CRITICAL

    def test_aws_key_too_short_not_detected(self):
        findings = _scan_text('key = "AKIA"')
        assert not any("AWS Access Key ID" in f.title for f in findings)

    def test_aws_secret_key_detected(self):
        secret = "A" * 40
        findings = _scan_text(f'aws_secret_access_key = "{secret}"')
        assert any("AWS Secret Access Key" in f.title for f in findings)

    def test_aws_secret_key_env_style(self):
        secret = "A" * 40
        findings = _scan_text(f"AWS_SECRET_ACCESS_KEY={secret}")
        assert any("AWS Secret Access Key" in f.title for f in findings)


class TestGitHubTokenPatterns:
    def test_ghp_token_detected(self):
        token = "ghp_" + "A" * 36
        findings = _scan_text(f'token = "{token}"')
        matched = [f for f in findings if "GitHub" in f.title]
        assert len(matched) >= 1
        assert matched[0].severity == Severity.CRITICAL

    def test_gho_token_detected(self):
        token = "gho_" + "a" * 36
        findings = _scan_text(f'GITHUB_TOKEN={token}')
        assert any("GitHub" in f.title for f in findings)

    def test_ghs_token_detected(self):
        token = "ghs_" + "x" * 36
        findings = _scan_text(f'token="{token}"')
        assert any("GitHub" in f.title for f in findings)

    def test_short_ghp_not_detected(self):
        findings = _scan_text('token = "ghp_short"')
        assert not any("GitHub" in f.title for f in findings)


class TestGoogleAPIKey:
    def test_google_api_key_detected(self):
        key = "AIza" + "A" * 35
        findings = _scan_text(f'GOOGLE_KEY="{key}"')
        assert any("Google API Key" in f.title for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings if "Google" in f.title)


class TestGenericPatterns:
    def test_generic_api_key_detected(self):
        findings = _scan_text('api_key = "abcdef1234567890abcdef"')
        assert any("Generic API Key" in f.title for f in findings)

    def test_generic_secret_detected(self):
        findings = _scan_text('secret = "mysupersecretvalue"')
        assert any("Generic Secret" in f.title for f in findings)

    def test_generic_password_detected(self):
        findings = _scan_text('password = "longenoughpassword"')
        assert any("Generic Secret" in f.title for f in findings)

    def test_short_password_not_detected(self):
        # Passwords < 8 chars should not match the Generic Secret pattern
        findings = _scan_text('password = "short"')
        assert not any("Generic Secret" in f.title for f in findings)


class TestPrivateKey:
    def test_rsa_private_key_detected(self):
        findings = _scan_text("-----BEGIN RSA PRIVATE KEY-----\ndata\n-----END RSA PRIVATE KEY-----")
        assert any("Private Key" in f.title for f in findings)
        assert findings[0].severity == Severity.CRITICAL

    def test_openssh_private_key_detected(self):
        findings = _scan_text("-----BEGIN OPENSSH PRIVATE KEY-----")
        assert any("Private Key" in f.title for f in findings)


class TestConnectionString:
    def test_postgres_connection_detected(self):
        findings = _scan_text('DB_URL="postgresql://user:pass@host:5432/db"')
        assert any("Connection String" in f.title for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings if "Connection" in f.title)

    def test_mongodb_connection_detected(self):
        findings = _scan_text('MONGO="mongodb+srv://user:pass@cluster.example.com/db"')
        assert any("Connection String" in f.title for f in findings)

    def test_redis_connection_detected(self):
        findings = _scan_text('REDIS_URL="redis://localhost:6379"')
        assert any("Connection String" in f.title for f in findings)


class TestSlackWebhook:
    def test_slack_webhook_detected(self):
        url = "https://hooks.slack.com/services/T0123ABCD/B0123ABCD/AbCdEf123456"
        findings = _scan_text(f'SLACK_URL="{url}"')
        assert any("Slack Webhook" in f.title for f in findings)


class TestTelegramBotToken:
    def test_telegram_token_detected(self):
        token = "123456789:ABCDefGHIjklMNOpqrsTUVwxyz_01234567"
        findings = _scan_text(f'BOT_TOKEN="{token}"')
        assert any("Telegram Bot Token" in f.title for f in findings)


class TestFileFiltering:
    def test_binary_files_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            for ext in [".png", ".jpg", ".zip", ".pdf"]:
                filepath = os.path.join(tmp, f"file{ext}")
                with open(filepath, "w") as f:
                    f.write('secret = "AKIA1234567890ABCDEF"')
            findings = run(tmp)
            assert len(findings) == 0

    def test_skip_dirs_are_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            node_dir = os.path.join(tmp, "node_modules")
            os.makedirs(node_dir)
            filepath = os.path.join(node_dir, "secret.js")
            with open(filepath, "w") as f:
                f.write('const key = "AKIA1234567890ABCDEF";')
            findings = run(tmp)
            assert len(findings) == 0

    def test_finding_metadata(self):
        findings = _scan_text('key = "AKIA1234567890ABCDEF"', "config.py")
        assert len(findings) >= 1
        f = findings[0]
        assert f.category == "secret"
        assert f.file_path == "config.py"
        assert f.line_number == 1
        assert f.remediation != ""
