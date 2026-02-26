"""Tests for reviewer.main.build_prompt."""

from reviewer.main import build_prompt


class TestBuildPrompt:
    """Verify that build_prompt assembles correct prompts."""

    def test_includes_all_default_categories(self, security_diff):
        categories = ["security", "bugs", "performance", "best-practices"]
        prompt = build_prompt(security_diff, categories, "standard")

        assert "🔒 **Security**" in prompt
        assert "🐛 **Bugs**" in prompt
        assert "⚡ **Performance**" in prompt
        assert "📐 **Best Practices**" in prompt

    def test_single_category(self, small_diff):
        prompt = build_prompt(small_diff, ["security"], "quick")
        assert "🔒 **Security**" in prompt
        assert "🐛 **Bugs**" not in prompt

    def test_review_level_quick(self, small_diff):
        prompt = build_prompt(small_diff, ["security"], "quick")
        assert "Focus only on critical issues" in prompt

    def test_review_level_standard(self, small_diff):
        prompt = build_prompt(small_diff, ["security"], "standard")
        assert "Review thoroughly but stay focused" in prompt

    def test_review_level_thorough(self, small_diff):
        prompt = build_prompt(small_diff, ["security"], "thorough")
        assert "Deep review" in prompt

    def test_unknown_level_falls_back_to_standard(self, small_diff):
        prompt = build_prompt(small_diff, ["security"], "unknown_level")
        assert "Review thoroughly but stay focused" in prompt

    def test_diff_is_embedded(self, security_diff):
        prompt = build_prompt(security_diff, ["security"], "standard")
        assert "AKIA1234567890ABCDEF" in prompt
        assert "src/auth.py" in prompt

    def test_json_output_format_described(self, small_diff):
        prompt = build_prompt(small_diff, [], "standard")
        assert '"findings"' in prompt
        assert '"severity"' in prompt
        assert '"verdict"' in prompt

    def test_empty_categories_still_has_rules(self, small_diff):
        prompt = build_prompt(small_diff, [], "standard")
        assert "Only report REAL issues" in prompt
        assert "Severity:" in prompt
