from __future__ import annotations

import json
from pathlib import Path

PROMPT_VERSION = "2026-04-26.1"

SYSTEM_PROMPT = """You are cull, a defensive malware scanner for npm and Python packages.

Inspect the supplied package file chunk for malicious supply-chain behavior.
Return only a JSON object with:
  level: clean | suspicious | malicious
  confidence: low | medium | high
  summary: empty when clean, otherwise 1-3 specific sentences explaining the overall verdict
  findings: empty when clean, otherwise 1-5 findings with indicator, snippet, explanation

Rules:
- Mark malicious when code clearly steals credentials, downloads and executes payloads, propagates packages, persists, mines crypto, wipes data, or exfiltrates files/env vars.
- Mark suspicious when code has strong malware signals but no complete proof.
- Mark clean when behavior is normal package code.
- The indicator list in the user prompt is guidance, not a whitelist. Novel malware may not match those strings.
- Reason from behavior and intent: install-time side effects, unexpected network/process/file access, obfuscation, persistence, destructive actions, credential access, and code that does much more than the package should.
- For each non-clean finding, explain why the evidence is suspicious or malicious in detail. Connect the snippet to the behavior, describe likely impact, and say what additional context would change confidence.
- Do not invent line numbers. Use short code snippets as evidence.
"""

USER_PROMPT_TEMPLATE = """Package: {package}@{version}
Ecosystem: {ecosystem}
File: {path}
Chunk: {chunk_index}/{chunk_count}

Indicator examples to consider (not exhaustive; still reason about novel malicious behavior):
{iocs}

Code:
```
{code}
```
"""


def build_user_prompt(
    *,
    package: str,
    version: str,
    ecosystem: str,
    path: str,
    chunk_index: int,
    chunk_count: int,
    code: str,
) -> str:
    return USER_PROMPT_TEMPLATE.format(
        package=package,
        version=version,
        ecosystem=ecosystem,
        path=path,
        chunk_index=chunk_index,
        chunk_count=chunk_count,
        iocs=_render_iocs(),
        code=code,
    )


def _render_iocs() -> str:
    groups: dict[str, list[str]] = {}
    for item in _load_iocs():
        indicator = str(item.get("indicator", "other"))
        value = str(item.get("value", "")).strip()
        description = str(item.get("description", "")).strip()
        if not value:
            continue
        detail = f"{value} ({description})" if description else value
        groups.setdefault(indicator, []).append(detail)

    lines: list[str] = []
    for indicator in sorted(groups):
        values = "; ".join(groups[indicator])
        lines.append(f"- {indicator}: {values}")
    return "\n".join(lines)


def _load_iocs() -> list[dict[str, object]]:
    path = Path(__file__).with_name("iocs.json")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    items = data.get("items") if isinstance(data, dict) else None
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, dict)]
