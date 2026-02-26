"""Tests for reviewer.main — diff parsing and review posting."""

import json
from unittest.mock import MagicMock, patch

from reviewer.main import get_pr_diff, post_review, REVIEW_LEVEL_TOKENS


class TestGetPrDiff:
    """Test get_pr_diff extracts patches and file lists."""

    def _make_file(self, filename, patch):
        f = MagicMock()
        f.filename = filename
        f.patch = patch
        return f

    def test_extracts_files_with_patches(self):
        gh = MagicMock()
        pr_mock = MagicMock()
        repo_mock = MagicMock()
        gh.get_repo.return_value = repo_mock
        repo_mock.get_pull.return_value = pr_mock

        files = [
            self._make_file("src/app.py", "@@ -1 +1 @@\n+print('hi')"),
            self._make_file("README.md", None),  # no patch
            self._make_file("src/util.py", "@@ -5 +5 @@\n+x = 1"),
        ]
        pr_mock.get_files.return_value = files

        diff, file_list, pr = get_pr_diff(gh, "owner/repo", 1)

        assert "src/app.py" in diff
        assert "src/util.py" in diff
        assert "README.md" not in diff
        assert file_list == ["src/app.py", "src/util.py"]
        assert pr is pr_mock

    def test_empty_pr_returns_empty(self):
        gh = MagicMock()
        pr_mock = MagicMock()
        repo_mock = MagicMock()
        gh.get_repo.return_value = repo_mock
        repo_mock.get_pull.return_value = pr_mock
        pr_mock.get_files.return_value = []

        diff, file_list, pr = get_pr_diff(gh, "owner/repo", 1)
        assert diff == ""
        assert file_list == []


class TestPostReview:
    """Test post_review formatting and GitHub API calls."""

    def test_approve_when_no_findings(self):
        pr = MagicMock()
        post_review(pr, [], "Looks good!", "approve", 10, "critical")
        pr.create_review.assert_called_once()
        call_kwargs = pr.create_review.call_args
        assert call_kwargs[1]["event"] == "APPROVE"
        assert "✅ No issues found" in call_kwargs[1]["body"]

    def test_request_changes_with_critical(self):
        pr = MagicMock()
        findings = [
            {"severity": "critical", "category": "security",
             "title": "SQL Injection", "file": "app.py", "line": 10,
             "description": "Bad query"}
        ]
        post_review(pr, findings, "Found issues", "request_changes", 10, "critical")
        call_kwargs = pr.create_review.call_args
        assert call_kwargs[1]["event"] == "REQUEST_CHANGES"

    def test_approve_when_only_info_and_fail_on_critical(self):
        pr = MagicMock()
        findings = [
            {"severity": "info", "title": "Minor note", "file": "x.py",
             "line": 1, "description": "nit", "category": "best-practices"}
        ]
        post_review(pr, findings, "Minor notes", "request_changes", 10, "critical")
        call_kwargs = pr.create_review.call_args
        assert call_kwargs[1]["event"] == "APPROVE"

    def test_max_comments_truncation(self):
        pr = MagicMock()
        findings = [
            {"severity": "warning", "title": f"Issue {i}", "file": "a.py",
             "line": i, "description": f"desc {i}", "category": "bugs"}
            for i in range(20)
        ]
        post_review(pr, findings, "Many issues", "request_changes", 5, "warning")
        body = pr.create_review.call_args[1]["body"]
        assert "15 more findings omitted" in body

    def test_fallback_to_comment_on_github_error(self):
        from github import GithubException

        pr = MagicMock()
        pr.create_review.side_effect = GithubException(403, "Forbidden", None)
        post_review(pr, [], "ok", "approve", 10, "critical")
        pr.create_issue_comment.assert_called_once()

    def test_severity_counts_in_body(self):
        pr = MagicMock()
        findings = [
            {"severity": "critical", "title": "A", "file": "a.py",
             "line": 1, "description": "d", "category": "security"},
            {"severity": "warning", "title": "B", "file": "b.py",
             "line": 2, "description": "d", "category": "bugs"},
            {"severity": "warning", "title": "C", "file": "c.py",
             "line": 3, "description": "d", "category": "bugs"},
        ]
        post_review(pr, findings, "Mixed", "request_changes", 10, "critical")
        body = pr.create_review.call_args[1]["body"]
        assert "🔴 1 critical" in body
        assert "🟡 2 warning" in body


class TestReviewLevelTokens:
    """Verify review level token map."""

    def test_quick_token_count(self):
        assert REVIEW_LEVEL_TOKENS["quick"] == 1000

    def test_standard_token_count(self):
        assert REVIEW_LEVEL_TOKENS["standard"] == 4000

    def test_thorough_token_count(self):
        assert REVIEW_LEVEL_TOKENS["thorough"] == 8000
