# 🔍 AI Code Reviewer

AI-powered GitHub Action that reviews pull requests for security vulnerabilities, bugs, performance issues, and best practices using Google Gemini.

## Usage

```yaml
# .github/workflows/ai-review.yml
name: AI Code Review

on:
  pull_request:
    types: [opened, synchronize]

permissions:
  pull-requests: write
  contents: read

jobs:
  ai-review:
    runs-on: ubuntu-latest
    steps:
      - uses: Konopl9/ai-code-reviewer@main
        with:
          gemini-api-key: ${{ secrets.GEMINI_API_KEY }}
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `gemini-api-key` | ✅ | — | Google Gemini API key |
| `github-token` | ❌ | `github.token` | GitHub token for posting reviews |
| `review-level` | ❌ | `standard` | `quick` \| `standard` \| `thorough` |
| `categories` | ❌ | all | `security,bugs,performance,best-practices` |
| `max-comments` | ❌ | `10` | Max findings to post |
| `fail-on` | ❌ | `critical` | Severity that triggers REQUEST_CHANGES |

## Review Categories

- 🔒 **Security** — SQL injection, XSS, path traversal, hardcoded secrets, auth bypass
- 🐛 **Bugs** — Null refs, off-by-one, race conditions, unhandled exceptions
- ⚡ **Performance** — N+1 queries, unnecessary loops, missing indexes
- 📐 **Best Practices** — Dead code, DRY violations, missing error handling

## Review Output

The action posts a GitHub PR review with:
- **Summary** with severity counts (🔴 critical / 🟡 warning / 🔵 info)
- **Inline findings** with file, line, and fix suggestions
- **Verdict**: APPROVE (no criticals) or REQUEST_CHANGES (has criticals)

## License

MIT
