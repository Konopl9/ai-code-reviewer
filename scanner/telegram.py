"""Telegram digest notification."""

import json
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import List

from scanner.models import Finding, Severity


def send_digest(
    findings: List[Finding],
    repo: str,
    bot_token: str,
    chat_id: str,
    issues_url: str = "",
) -> bool:
    """Send a Telegram digest message summarizing scan findings."""
    if not bot_token or not chat_id:
        print("Telegram credentials not configured, skipping notification.")
        return False

    message = _format_message(findings, repo, issues_url)
    return _send_message(bot_token, chat_id, message)


def _format_message(
    findings: List[Finding], repo: str, issues_url: str
) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1

    # Top critical/high findings
    top_findings = [
        f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
    ][:5]

    lines = [
        f"🔐 Security Scan: {repo}",
        f"📅 {now}",
        "",
        f"🔴 Critical: {counts[Severity.CRITICAL]}",
        f"🟠 High: {counts[Severity.HIGH]}",
        f"🟡 Medium: {counts[Severity.MEDIUM]}",
        f"🔵 Low: {counts[Severity.LOW]}",
        f"ℹ️ Info: {counts[Severity.INFO]}",
        "",
    ]

    if top_findings:
        lines.append("⚠️ Top findings:")
        for f in top_findings:
            icon = "🔴" if f.severity == Severity.CRITICAL else "🟠"
            lines.append(f"  {icon} {f.title}")
        lines.append("")

    if not findings:
        lines.append("✅ No vulnerabilities found!")
        lines.append("")

    if issues_url:
        lines.append(f"📋 Full details: {issues_url}")

    return "\n".join(lines)


def _send_message(bot_token: str, chat_id: str, message: str) -> bool:
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = json.dumps({
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        print(f"Failed to send Telegram message: {e}")
        return False
