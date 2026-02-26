"""Tests for reviewer.main severity/verdict classification."""

from reviewer.main import post_review
from unittest.mock import MagicMock


class TestSeverityClassifier:
    """Verify that severity + fail_on logic works correctly."""

    def _findings(self, *severities):
        return [
            {"severity": s, "title": f"F-{s}", "file": "f.py",
             "line": 1, "description": "desc", "category": "bugs"}
            for s in severities
        ]

    def test_critical_blocks_when_fail_on_critical(self):
        pr = MagicMock()
        post_review(pr, self._findings("critical"), "s", "request_changes", 10, "critical")
        assert pr.create_review.call_args[1]["event"] == "REQUEST_CHANGES"

    def test_warning_blocks_when_fail_on_warning(self):
        pr = MagicMock()
        post_review(pr, self._findings("warning"), "s", "request_changes", 10, "warning")
        assert pr.create_review.call_args[1]["event"] == "REQUEST_CHANGES"

    def test_info_blocks_when_fail_on_info(self):
        pr = MagicMock()
        post_review(pr, self._findings("info"), "s", "request_changes", 10, "info")
        assert pr.create_review.call_args[1]["event"] == "REQUEST_CHANGES"

    def test_warning_does_not_block_when_fail_on_critical(self):
        pr = MagicMock()
        post_review(pr, self._findings("warning"), "s", "request_changes", 10, "critical")
        assert pr.create_review.call_args[1]["event"] == "APPROVE"

    def test_info_does_not_block_when_fail_on_warning(self):
        pr = MagicMock()
        post_review(pr, self._findings("info"), "s", "request_changes", 10, "warning")
        assert pr.create_review.call_args[1]["event"] == "APPROVE"

    def test_approve_verdict_never_requests_changes(self):
        pr = MagicMock()
        post_review(pr, self._findings("critical"), "s", "approve", 10, "critical")
        assert pr.create_review.call_args[1]["event"] == "APPROVE"

    def test_mixed_severities_highest_wins(self):
        pr = MagicMock()
        post_review(pr, self._findings("info", "warning", "critical"), "s", "request_changes", 10, "critical")
        assert pr.create_review.call_args[1]["event"] == "REQUEST_CHANGES"

    def test_no_findings_always_approves(self):
        pr = MagicMock()
        post_review(pr, [], "clean", "request_changes", 10, "critical")
        assert pr.create_review.call_args[1]["event"] == "APPROVE"
