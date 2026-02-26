"""Shared fixtures for the AI Code Reviewer test suite."""

import pytest

from scanner.models import Finding, Severity, ScanResult


# ---------------------------------------------------------------------------
# Sample PR diffs
# ---------------------------------------------------------------------------

SMALL_DIFF = """\
## src/app.py
```diff
@@ -1,3 +1,5 @@
 import os
+import subprocess
+
 def run(cmd):
-    os.system(cmd)
+    subprocess.run(cmd, shell=True)
```"""

SECURITY_DIFF = """\
## config/settings.py
```diff
@@ -10,6 +10,8 @@
 DATABASE_URL = os.environ["DATABASE_URL"]
+API_KEY = "AKIA1234567890ABCDEF"
+DEBUG = True
```

## src/auth.py
```diff
@@ -5,7 +5,7 @@
 def login(user, password):
-    query = db.prepare("SELECT * FROM users WHERE name = ?")
+    query = f"SELECT * FROM users WHERE name = '{user}'"
     return db.execute(query)
```"""

MULTI_FILE_DIFF = """\
## src/models.py
```diff
@@ -1,4 +1,6 @@
 class User:
     def __init__(self, name):
         self.name = name
+        self.email = None
+        self.role = "viewer"
```

## src/api.py
```diff
@@ -10,6 +10,12 @@
 @app.route("/users")
 def list_users():
-    return jsonify(users)
+    page = int(request.args.get("page", 1))
+    per_page = int(request.args.get("per_page", 50))
+    start = (page - 1) * per_page
+    return jsonify(users[start:start + per_page])
```"""


@pytest.fixture
def small_diff():
    return SMALL_DIFF


@pytest.fixture
def security_diff():
    return SECURITY_DIFF


@pytest.fixture
def multi_file_diff():
    return MULTI_FILE_DIFF


# ---------------------------------------------------------------------------
# Mock Gemini review response
# ---------------------------------------------------------------------------

GEMINI_REVIEW_JSON = """\
{
  "summary": "Found 1 critical SQL injection vulnerability.",
  "findings": [
    {
      "file": "src/auth.py",
      "line": 8,
      "severity": "critical",
      "category": "security",
      "title": "SQL Injection",
      "description": "User input is interpolated directly into SQL query."
    }
  ],
  "verdict": "request_changes"
}"""


@pytest.fixture
def gemini_review_json():
    return GEMINI_REVIEW_JSON


# ---------------------------------------------------------------------------
# Scanner findings fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_findings():
    return [
        Finding(
            title="[secret] AWS Access Key ID in config.py",
            description="Potential AWS Access Key ID found at line 5",
            severity=Severity.CRITICAL,
            category="secret",
            file_path="config.py",
            line_number=5,
            remediation="Remove the secret and rotate the credential.",
        ),
        Finding(
            title="[npm] lodash: CVE-2021-23337",
            description="Prototype Pollution in lodash",
            severity=Severity.HIGH,
            category="dependency",
            file_path="package.json",
            remediation="Fix available via `npm audit fix`",
        ),
        Finding(
            title="[config] Debug mode enabled: DEBUG=True",
            description="Debug mode appears to be enabled in settings.py",
            severity=Severity.MEDIUM,
            category="config",
            file_path="settings.py",
            remediation="Disable debug mode in production configurations.",
        ),
    ]


@pytest.fixture
def empty_findings():
    return []


@pytest.fixture
def sample_scan_result(sample_findings):
    return ScanResult(repo="Konopl9/ai-code-reviewer", findings=sample_findings)
