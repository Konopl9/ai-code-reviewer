"""Security scanner orchestrator.

Runs configured checks against a target repository, creates GitHub issues
for critical/high findings, and sends a Telegram digest.
"""

import os
import sys
from typing import List

from github import Github, GithubException

from scanner.models import Finding, ScanResult, Severity
from scanner.checks import dependency_audit, secret_detection, config_audit
from scanner.telegram import send_digest

CHECK_MODULES = {
    "dependencies": dependency_audit,
    "secrets": secret_detection,
    "config": config_audit,
}


def main() -> None:
    repo_name = os.environ.get("REPO_NAME", "")
    github_token = os.environ.get("GITHUB_TOKEN", "")
    telegram_bot_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    telegram_chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
    scan_categories = os.environ.get("SCAN_CATEGORIES", "dependencies,secrets,config")
    create_issues = os.environ.get("CREATE_ISSUES", "true").lower() == "true"
    scan_path = os.environ.get("SCAN_PATH", os.getcwd())

    if not repo_name:
        print("Error: REPO_NAME environment variable is required.")
        sys.exit(1)
    if not github_token:
        print("Error: GITHUB_TOKEN environment variable is required.")
        sys.exit(1)

    categories = [c.strip() for c in scan_categories.split(",") if c.strip()]
    print(f"🔐 Starting security scan for {repo_name}")
    print(f"📂 Scan path: {scan_path}")
    print(f"📋 Categories: {', '.join(categories)}")

    result = ScanResult(repo=repo_name)

    for category in categories:
        module = CHECK_MODULES.get(category)
        if not module:
            print(f"⚠️ Unknown scan category: {category}")
            continue

        print(f"\n▶ Running {category} checks...")
        try:
            findings = module.run(scan_path)
            result.findings.extend(findings)
            print(f"  Found {len(findings)} issue(s)")
        except Exception as e:
            error_msg = f"Error in {category} check: {e}"
            print(f"  ❌ {error_msg}")
            result.errors.append(error_msg)

    _print_summary(result)

    gh = Github(github_token)
    try:
        gh_repo = gh.get_repo(repo_name)
    except GithubException as e:
        print(f"Error accessing repo {repo_name}: {e}")
        sys.exit(1)

    if create_issues:
        _create_issues(gh_repo, result.findings)

    issues_url = f"https://github.com/{repo_name}/issues?q=label%3Asecurity"
    send_digest(result.findings, repo_name, telegram_bot_token, telegram_chat_id, issues_url)

    critical_count = sum(1 for f in result.findings if f.severity == Severity.CRITICAL)
    if critical_count > 0:
        print(f"\n⛔ {critical_count} critical finding(s) detected!")
        sys.exit(1)

    print("\n✅ Security scan complete.")


def _print_summary(result: ScanResult) -> None:
    counts = {s: 0 for s in Severity}
    for f in result.findings:
        counts[f.severity] += 1

    print(f"\n{'='*50}")
    print(f"📊 Scan Summary for {result.repo}")
    print(f"{'='*50}")
    print(f"  🔴 Critical: {counts[Severity.CRITICAL]}")
    print(f"  🟠 High:     {counts[Severity.HIGH]}")
    print(f"  🟡 Medium:   {counts[Severity.MEDIUM]}")
    print(f"  🔵 Low:      {counts[Severity.LOW]}")
    print(f"  ℹ️  Info:     {counts[Severity.INFO]}")
    print(f"  Total:       {len(result.findings)}")
    if result.errors:
        print(f"  ⚠️  Errors:   {len(result.errors)}")
    print(f"{'='*50}")


def _create_issues(gh_repo, findings: List[Finding]) -> None:
    """Create GitHub issues for Critical and High severity findings."""
    actionable = [
        f for f in findings
        if f.severity in (Severity.CRITICAL, Severity.HIGH)
    ]
    if not actionable:
        print("\nNo critical/high findings — no issues to create.")
        return

    _ensure_labels(gh_repo)
    existing_titles = _get_existing_issue_titles(gh_repo)

    created = 0
    skipped = 0
    for finding in actionable:
        if finding.title in existing_titles:
            skipped += 1
            continue

        body = _format_issue_body(finding)
        labels = ["security", finding.severity.value]

        try:
            gh_repo.create_issue(
                title=finding.title,
                body=body,
                labels=labels,
            )
            created += 1
            existing_titles.add(finding.title)
        except GithubException as e:
            print(f"  Failed to create issue '{finding.title}': {e}")

    print(f"\n📝 Issues: {created} created, {skipped} skipped (duplicates)")


def _ensure_labels(gh_repo) -> None:
    """Ensure security-related labels exist."""
    desired = {
        "security": "d93f0b",
        "critical": "b60205",
        "high": "e99695",
        "medium": "fbca04",
        "low": "0e8a16",
    }
    existing = {label.name for label in gh_repo.get_labels()}
    for name, color in desired.items():
        if name not in existing:
            try:
                gh_repo.create_label(name=name, color=color)
            except GithubException:
                pass  # Label might have been created concurrently


def _get_existing_issue_titles(gh_repo) -> set:
    """Get titles of existing open issues with the security label."""
    titles = set()
    try:
        issues = gh_repo.get_issues(state="open", labels=["security"])
        for issue in issues:
            titles.add(issue.title)
    except GithubException:
        pass
    return titles


def _format_issue_body(finding: Finding) -> str:
    severity_icons = {
        Severity.CRITICAL: "🔴",
        Severity.HIGH: "🟠",
        Severity.MEDIUM: "🟡",
        Severity.LOW: "🔵",
        Severity.INFO: "ℹ️",
    }
    icon = severity_icons.get(finding.severity, "")
    lines = [
        f"## {icon} {finding.severity.value.upper()} — {finding.category}",
        "",
        f"**Description:** {finding.description}",
        "",
    ]
    if finding.file_path:
        lines.append(f"**File:** `{finding.file_path}`")
    if finding.line_number:
        lines.append(f"**Line:** {finding.line_number}")
    if finding.remediation:
        lines.append("")
        lines.append(f"### Remediation")
        lines.append(finding.remediation)

    lines.extend(["", "---", "*Created by [AI Code Reviewer — Security Scanner](https://github.com/Konopl9/ai-code-reviewer)*"])
    return "\n".join(lines)


if __name__ == "__main__":
    # Allow running from the repo root by adding parent to path
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    main()
