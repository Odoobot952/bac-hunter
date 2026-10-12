"""
Turns a finding into a ready-to-paste curl command and a short Markdown
block, so every flagged issue already has report-grade evidence attached
instead of needing to be manually reconstructed later.
"""

from __future__ import annotations
import shlex


def to_curl(method: str, url: str, headers: dict, body: str = "") -> str:
    parts = ["curl", "-i", "-X", method, shlex.quote(url)]
    for key, value in headers.items():
        parts += ["-H", shlex.quote(f"{key}: {value}")]
    if body:
        parts += ["--data", shlex.quote(body)]
    return " ".join(parts)


def finding_to_markdown(
    title: str,
    severity: str,
    description: str,
    curl_cmd: str,
    status_code: int,
    response_snippet: str,
) -> str:
    return f"""## {title}

**Severity:** {severity}

**Description:**
{description}

**Proof of Concept:**
```bash
{curl_cmd}
```

**Observed response:** `HTTP {status_code}`
```
{response_snippet}
```
"""
