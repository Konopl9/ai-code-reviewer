"""AI Code Reviewer — Gemini-powered PR review."""

import json
import os
import sys
import time

import google.generativeai as genai
from github import Github, GithubException

REVIEW_LEVEL_TOKENS = {"quick": 1000, "standard": 4000, "thorough": 8000}
MAX_RETRIES = 3
RETRY_DELAY = 60


def get_pr_diff(gh: Github, repo_name: str, pr_number: int) -> tuple:
    """Fetch PR diff and file list."""
    repo = gh.get_repo(repo_name)
    pr = repo.get_pull(pr_number)
    files = pr.get_files()

    diff_parts = []
    file_list = []
    for f in files:
        if f.patch:
            diff_parts.append(f"## {f.filename}\n```diff\n{f.patch}\n```")
            file_list.append(f.filename)

    return "\n\n".join(diff_parts), file_list, pr


def build_prompt(diff: str, categories: list[str], review_level: str) -> str:
    """Build the review prompt."""
    cat_instructions = []
    if "security" in categories:
        cat_instructions.append(
            "🔒 **Security**: SQL injection, path traversal, XSS, hardcoded secrets, "
            "auth bypass, command injection, unsafe deserialization, SSRF"
        )
    if "bugs" in categories:
        cat_instructions.append(
            "🐛 **Bugs**: Null/None references, off-by-one errors, race conditions, "
            "unhandled exceptions, type mismatches, logic errors"
        )
    if "performance" in categories:
        cat_instructions.append(
            "⚡ **Performance**: N+1 queries, unnecessary loops, missing indexes, "
            "large allocations, blocking calls in async code"
        )
    if "best-practices" in categories:
        cat_instructions.append(
            "📐 **Best Practices**: Dead code, DRY violations, missing error handling, "
            "poor naming, missing input validation"
        )

    depth = {
        "quick": "Focus only on critical issues. Be very concise.",
        "standard": "Review thoroughly but stay focused on real problems.",
        "thorough": "Deep review. Check edge cases, error paths, and subtle issues.",
    }.get(review_level, "Review thoroughly but stay focused on real problems.")

    return f"""You are an expert code reviewer. Review this PR diff and find real issues.

{depth}

## Categories to check:
{chr(10).join(cat_instructions)}

## Rules:
- Only report REAL issues, not style preferences
- Each finding must reference a specific file and line from the diff
- Use diff line numbers (lines starting with + are additions)
- Severity: 🔴 critical, 🟡 warning, 🔵 info
- If no issues found, say so explicitly

## Output format (JSON):
{{
  "summary": "Brief overall assessment",
  "findings": [
    {{
      "file": "path/to/file.py",
      "line": 42,
      "severity": "critical",
      "category": "security",
      "title": "Short title",
      "description": "What's wrong and how to fix it"
    }}
  ],
  "verdict": "approve" or "request_changes"
}}

## PR Diff:
{diff}
"""


def post_review(pr, findings: list, summary: str, verdict: str, max_comments: int, fail_on: str):
    """Post the review to GitHub."""
    severity_order = {"critical": 0, "warning": 1, "info": 2}
    fail_threshold = severity_order.get(fail_on, 0)

    has_blocking = any(
        severity_order.get(f.get("severity", "info"), 2) <= fail_threshold
        for f in findings
    )

    event = "REQUEST_CHANGES" if has_blocking and verdict == "request_changes" else "APPROVE"

    # Build summary body
    counts = {"critical": 0, "warning": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1

    severity_icons = {"critical": "🔴", "warning": "🟡", "info": "🔵"}
    count_parts = [f"{severity_icons[s]} {c} {s}" for s, c in counts.items() if c > 0]
    count_line = " | ".join(count_parts) if count_parts else "✅ No issues found"

    body = f"## AI Code Review\n\n{summary}\n\n**Findings:** {count_line}\n"

    if findings:
        body += "\n### Details\n"
        for i, f in enumerate(findings[:max_comments]):
            icon = severity_icons.get(f.get("severity", "info"), "🔵")
            body += (
                f"\n{icon} **{f.get('title', 'Issue')}** ({f.get('category', 'general')})\n"
                f"- File: `{f.get('file', '?')}` line {f.get('line', '?')}\n"
                f"- {f.get('description', '')}\n"
            )

        if len(findings) > max_comments:
            body += f"\n_...and {len(findings) - max_comments} more findings omitted._\n"

    body += f"\n---\n_Reviewed by [AI Code Reviewer](https://github.com/Konopl9/ai-code-reviewer) using Gemini_"

    try:
        pr.create_review(body=body, event=event)
        print(f"✅ Posted review: {event} ({len(findings)} findings)")
    except GithubException as e:
        print(f"⚠️ Failed to post review: {e}. Falling back to comment.")
        pr.create_issue_comment(body)


def main():
    api_key = os.environ["GEMINI_API_KEY"]
    github_token = os.environ["GITHUB_TOKEN"]
    repo_name = os.environ["REPO_FULL_NAME"]
    pr_number = int(os.environ["PR_NUMBER"])
    review_level = os.environ.get("REVIEW_LEVEL", "standard")
    categories = os.environ.get("CATEGORIES", "security,bugs,performance,best-practices").split(",")
    max_comments = int(os.environ.get("MAX_COMMENTS", "10"))
    fail_on = os.environ.get("FAIL_ON", "critical")

    # Setup clients — set env var before configure for SDK compatibility
    os.environ["GOOGLE_API_KEY"] = api_key
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-2.0-flash")
    gh = Github(github_token)

    # Get diff
    diff, files, pr = get_pr_diff(gh, repo_name, pr_number)

    if not diff.strip():
        print("No code changes to review.")
        pr.create_issue_comment("## AI Code Review\n\n✅ No code changes to review.")
        return

    print(f"Reviewing {len(files)} files at level '{review_level}'...")
    print(f"Categories: {', '.join(categories)}")

    # Generate review
    prompt = build_prompt(diff, categories, review_level)
    max_tokens = REVIEW_LEVEL_TOKENS.get(review_level, 4000)

    response = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = model.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(
                    max_output_tokens=max_tokens,
                    temperature=0.1,
                ),
            )
            break
        except Exception as e:
            if "429" in str(e) and attempt < MAX_RETRIES:
                print(f"⚠️ Rate limited (attempt {attempt}/{MAX_RETRIES}). Retrying in {RETRY_DELAY}s...")
                time.sleep(RETRY_DELAY)
            else:
                raise

    if response is None:
        print("⚠️ Failed to get response from Gemini after retries.")
        return

    # Parse response
    text = response.text.strip()
    # Extract JSON from markdown code blocks if present
    if "```json" in text:
        text = text.split("```json")[1].split("```")[0].strip()
    elif "```" in text:
        text = text.split("```")[1].split("```")[0].strip()

    try:
        result = json.loads(text)
    except json.JSONDecodeError:
        print(f"⚠️ Failed to parse Gemini response as JSON. Posting raw response.")
        pr.create_issue_comment(f"## AI Code Review\n\n{response.text}")
        return

    findings = result.get("findings", [])
    summary = result.get("summary", "Review complete.")
    verdict = result.get("verdict", "approve")

    post_review(pr, findings, summary, verdict, max_comments, fail_on)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"⚠️ AI Code Reviewer failed (non-blocking): {e}")
        sys.exit(0)
