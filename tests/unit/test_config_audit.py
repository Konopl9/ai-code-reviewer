"""Tests for scanner.checks.config_audit."""

import os
import tempfile

from scanner.checks.config_audit import run, _check_debug_mode, _check_cors_wildcard, _check_docker_compose, _check_env_files
from scanner.models import Severity


def _scan_with_file(filename: str, content: str):
    """Helper: create a file in a temp dir and run the full config audit."""
    with tempfile.TemporaryDirectory() as tmp:
        filepath = os.path.join(tmp, filename)
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w") as f:
            f.write(content)
        return run(tmp)


class TestDebugMode:
    def test_debug_true_detected(self):
        findings = _scan_with_file("settings.py", 'DEBUG = True')
        assert any("Debug mode" in f.title for f in findings)
        assert any(f.severity == Severity.MEDIUM for f in findings if "Debug" in f.title)

    def test_flask_debug_detected(self):
        findings = _scan_with_file(".env", "FLASK_DEBUG=1")
        assert any("Debug mode" in f.title for f in findings)

    def test_node_env_development_detected(self):
        findings = _scan_with_file(".env", 'NODE_ENV=development')
        assert any("Debug mode" in f.title for f in findings)

    def test_debug_false_not_flagged(self):
        findings = _scan_with_file("settings.py", 'DEBUG = False')
        assert not any("Debug mode" in f.title for f in findings)

    def test_production_node_env_not_flagged(self):
        findings = _scan_with_file(".env", 'NODE_ENV=production')
        assert not any("Debug mode" in f.title for f in findings)


class TestCORSWildcard:
    def test_cors_star_detected(self):
        findings = _scan_with_file("app.py", 'CORS(app, origins="*")')
        assert any("CORS wildcard" in f.title for f in findings)

    def test_allow_any_origin_detected(self):
        findings = _scan_with_file("Startup.cs", "builder.Services.AddCors(o => o.AllowAnyOrigin());")
        assert any("CORS wildcard" in f.title for f in findings)

    def test_access_control_wildcard_detected(self):
        findings = _scan_with_file("server.js", 'res.setHeader("Access-Control-Allow-Origin", "*")')
        assert any("CORS wildcard" in f.title for f in findings)

    def test_specific_origin_not_flagged(self):
        findings = _scan_with_file("app.py", 'CORS(app, origins="https://example.com")')
        assert not any("CORS wildcard" in f.title for f in findings)


class TestDockerCompose:
    def test_exposed_port_detected(self):
        compose = """\
services:
  web:
    image: nginx
    ports:
      - "8080:80"
"""
        findings = _scan_with_file("docker-compose.yml", compose)
        assert any("Exposed port" in f.title for f in findings)

    def test_privileged_mode_detected(self):
        compose = """\
services:
  app:
    image: myapp
    privileged: true
"""
        findings = _scan_with_file("docker-compose.yml", compose)
        priv = [f for f in findings if "Privileged" in f.title]
        assert len(priv) == 1
        assert priv[0].severity == Severity.HIGH

    def test_no_compose_file_no_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            findings = _check_docker_compose(tmp)
            assert findings == []


class TestEnvFiles:
    def test_env_file_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_path = os.path.join(tmp, ".env")
            with open(env_path, "w") as f:
                f.write("SECRET=abc")
            findings = _check_env_files(tmp)
            assert len(findings) == 1
            assert findings[0].severity == Severity.HIGH
            assert "Environment file" in findings[0].title

    def test_env_local_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_path = os.path.join(tmp, ".env.local")
            with open(env_path, "w") as f:
                f.write("KEY=val")
            findings = _check_env_files(tmp)
            assert len(findings) == 1

    def test_no_env_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            findings = _check_env_files(tmp)
            assert findings == []


class TestRunIntegration:
    def test_full_run_finds_multiple_issues(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Create settings.py with DEBUG
            with open(os.path.join(tmp, "settings.py"), "w") as f:
                f.write('DEBUG = True\n')
            # Create .env file
            with open(os.path.join(tmp, ".env"), "w") as f:
                f.write("SECRET=value\n")
            # Create docker-compose.yml
            with open(os.path.join(tmp, "docker-compose.yml"), "w") as f:
                f.write('services:\n  web:\n    ports:\n      - "3000:3000"\n')

            findings = run(tmp)
            categories = {f.title.split("]")[0] + "]" for f in findings}
            assert "[config]" in categories
            assert len(findings) >= 3
