"""Integration test — full reviewer flow with mocked GitHub + Gemini."""

import json
from unittest.mock import MagicMock, patch

from reviewer.main import main as reviewer_main, build_prompt, post_review


GEMINI_RESPONSE_TEXT = json.dumps({
    "summary": "SQL injection vulnerability detected in auth module.",
    "findings": [
        {
            "file": "src/auth.py",
            "line": 8,
            "severity": "critical",
            "category": "security",
            "title": "SQL Injection",
            "description": "User input is directly interpolated into SQL query string.",
        }
    ],
    "verdict": "request_changes",
})


class TestReviewerFlow:
    """End-to-end reviewer flow with all external calls mocked."""

    @patch.dict("os.environ", {
        "GEMINI_API_KEY": "fake-key",
        "GITHUB_TOKEN": "ghp_fake",
        "REPO_FULL_NAME": "owner/repo",
        "PR_NUMBER": "42",
        "REVIEW_LEVEL": "standard",
        "CATEGORIES": "security,bugs",
        "MAX_COMMENTS": "10",
        "FAIL_ON": "critical",
    })
    @patch("reviewer.main.genai")
    @patch("reviewer.main.Github")
    def test_full_flow_posts_review(self, mock_github_cls, mock_genai):
        # Setup GitHub mock
        gh = MagicMock()
        mock_github_cls.return_value = gh
        repo = MagicMock()
        gh.get_repo.return_value = repo
        pr = MagicMock()
        repo.get_pull.return_value = pr

        file_mock = MagicMock()
        file_mock.filename = "src/auth.py"
        file_mock.patch = "@@ -5,7 +5,7 @@\n-safe\n+unsafe"
        pr.get_files.return_value = [file_mock]

        # Setup Gemini mock
        model_mock = MagicMock()
        mock_genai.GenerativeModel.return_value = model_mock
        response_mock = MagicMock()
        response_mock.text = GEMINI_RESPONSE_TEXT
        model_mock.generate_content.return_value = response_mock

        reviewer_main()

        # Verify review was posted
        pr.create_review.assert_called_once()
        review_body = pr.create_review.call_args[1]["body"]
        assert "SQL Injection" in review_body or "SQL injection" in review_body
        assert pr.create_review.call_args[1]["event"] == "REQUEST_CHANGES"

    @patch.dict("os.environ", {
        "GEMINI_API_KEY": "fake-key",
        "GITHUB_TOKEN": "ghp_fake",
        "REPO_FULL_NAME": "owner/repo",
        "PR_NUMBER": "42",
    })
    @patch("reviewer.main.genai")
    @patch("reviewer.main.Github")
    def test_empty_diff_posts_comment(self, mock_github_cls, mock_genai):
        gh = MagicMock()
        mock_github_cls.return_value = gh
        repo = MagicMock()
        gh.get_repo.return_value = repo
        pr = MagicMock()
        repo.get_pull.return_value = pr
        pr.get_files.return_value = []  # no files changed

        reviewer_main()

        pr.create_issue_comment.assert_called_once()
        assert "No code changes" in pr.create_issue_comment.call_args[0][0]

    @patch.dict("os.environ", {
        "GEMINI_API_KEY": "fake-key",
        "GITHUB_TOKEN": "ghp_fake",
        "REPO_FULL_NAME": "owner/repo",
        "PR_NUMBER": "42",
    })
    @patch("reviewer.main.genai")
    @patch("reviewer.main.Github")
    def test_markdown_wrapped_json_parsed(self, mock_github_cls, mock_genai):
        gh = MagicMock()
        mock_github_cls.return_value = gh
        repo = MagicMock()
        gh.get_repo.return_value = repo
        pr = MagicMock()
        repo.get_pull.return_value = pr

        file_mock = MagicMock()
        file_mock.filename = "app.py"
        file_mock.patch = "@@ -1 +1 @@\n+pass"
        pr.get_files.return_value = [file_mock]

        model_mock = MagicMock()
        mock_genai.GenerativeModel.return_value = model_mock
        response_mock = MagicMock()
        # Gemini sometimes wraps JSON in markdown code blocks
        response_mock.text = f"```json\n{GEMINI_RESPONSE_TEXT}\n```"
        model_mock.generate_content.return_value = response_mock

        reviewer_main()

        pr.create_review.assert_called_once()

    @patch.dict("os.environ", {
        "GEMINI_API_KEY": "fake-key",
        "GITHUB_TOKEN": "ghp_fake",
        "REPO_FULL_NAME": "owner/repo",
        "PR_NUMBER": "42",
    })
    @patch("reviewer.main.genai")
    @patch("reviewer.main.Github")
    def test_invalid_json_falls_back_to_comment(self, mock_github_cls, mock_genai):
        gh = MagicMock()
        mock_github_cls.return_value = gh
        repo = MagicMock()
        gh.get_repo.return_value = repo
        pr = MagicMock()
        repo.get_pull.return_value = pr

        file_mock = MagicMock()
        file_mock.filename = "app.py"
        file_mock.patch = "@@ -1 +1 @@\n+pass"
        pr.get_files.return_value = [file_mock]

        model_mock = MagicMock()
        mock_genai.GenerativeModel.return_value = model_mock
        response_mock = MagicMock()
        response_mock.text = "This is not valid JSON at all."
        model_mock.generate_content.return_value = response_mock

        reviewer_main()

        pr.create_issue_comment.assert_called_once()
        pr.create_review.assert_not_called()
