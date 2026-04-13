"""
Codeproof Diff Reviewer — standalone version.

Sends a git diff to multiple LLMs sequentially, collects structured findings,
deduplicates by (file + category), and ranks by severity.

Public API
----------
    get_pr_diff(repo_dir, base_ref, head_ref)   -> str
    review_diff_single(diff_text, model, llm_client)  -> list[dict]
    review_diff_multi(diff_text, llm_client, models)  -> list[dict]
    deduplicate_findings(all_findings)                -> list[dict]
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_DIFF_CHARS = 8000

_SEVERITY_RANK: Dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}

DEFAULT_MODELS = [
    "anthropic/claude-sonnet-4-6",
    "google/gemini-2.5-flash",
]

_REVIEW_PROMPT = """You are a senior software engineer performing a code review. Analyze the following git diff and identify issues.

Focus on:
- Security vulnerabilities (injection, auth bypass, insecure data handling)
- Missing error handling or exception propagation
- Logic bugs and edge cases
- Resource leaks (file handles, connections not closed)
- Performance problems
- Code quality issues (unclear naming, missing validation)

Return ONLY a JSON array of findings. Each finding must have exactly these fields:
- "file": filename affected (string, or "" if general)
- "line": line number (integer or null)
- "severity": one of "critical", "high", "medium", "low"
- "category": short category label e.g. "security", "error-handling", "logic", "performance", "style"
- "finding": concise description of the issue (1-2 sentences)
- "why_it_matters": why this is a problem (1-2 sentences)
- "suggestion": concrete fix or improvement (1-2 sentences)

If you find no issues, return an empty array: []

Do not include any text before or after the JSON array.

Git diff to review:
```
__DIFF__
```"""

# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------


def get_pr_diff(
    repo_dir: "str | Path",
    base_ref: str,
    head_ref: str,
) -> str:
    """
    Run ``git diff base...head`` and return the diff text.

    Truncates to MAX_DIFF_CHARS with a note if the diff is too large.
    Returns empty string on error.
    """
    repo_path = Path(repo_dir).resolve()
    try:
        result = subprocess.run(
            ["git", "diff", f"{base_ref}...{head_ref}"],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        if result.returncode != 0:
            print(f"\n[DEBUG] Git diff error: {result.stderr.strip()}")
            return ""

        diff_text = result.stdout
        if len(diff_text) > MAX_DIFF_CHARS:
            safe_pos = diff_text.rfind("\n", 0, MAX_DIFF_CHARS)
            if safe_pos == -1:
                safe_pos = MAX_DIFF_CHARS
            diff_text = (
                diff_text[:safe_pos]
                + "\n\n[diff truncated — showing first ~8000 chars]"
            )

        return diff_text

    except subprocess.TimeoutExpired:
        log.warning("git diff timed out after 30s")
        return ""
    except FileNotFoundError:
        log.warning("git not found in PATH")
        return ""
    except Exception as exc:
        log.warning("get_pr_diff unexpected error: %s", exc)
        return ""


def review_diff_single(
    diff_text: str,
    model: str,
    llm_client: Any,
) -> List[Dict[str, Any]]:
    """
    Send a diff to one LLM model and return a list of structured findings.

    Returns empty list on any error (invalid JSON, timeout, API failure).

    Each finding dict has keys:
        file, line, severity, category, finding, why_it_matters, suggestion.
    """
    if not diff_text or not diff_text.strip():
        return []

    prompt = _REVIEW_PROMPT.replace("__DIFF__", diff_text)
    messages = [{"role": "user", "content": prompt}]

    try:
        response_msg, _usage = llm_client.chat(
            messages=messages,
            model=model,
            tools=None,
            reasoning_effort="low",
            max_tokens=8192,
        )

        content = response_msg.get("content") or ""
        if not content:
            log.warning("review_diff_single: empty response from %s", model)
            return []

        content = content.strip()
        if content.startswith("```"):
            lines = content.split("\n")
            inner_lines = lines[1:]
            if inner_lines and inner_lines[-1].strip() == "```":
                inner_lines = inner_lines[:-1]
            content = "\n".join(inner_lines).strip()

        findings = json.loads(content)

        if not isinstance(findings, list):
            log.warning("review_diff_single: model %s returned non-list JSON", model)
            return []

        valid_findings = []
        for item in findings:
            if not isinstance(item, dict):
                continue
            finding = _normalise_finding(item, model)
            if finding:
                valid_findings.append(finding)

        log.info(
            "review_diff_single: %s returned %d findings", model, len(valid_findings)
        )
        return valid_findings

    except json.JSONDecodeError as exc:
        log.warning("review_diff_single: %s returned invalid JSON: %s", model, exc)
        return []
    except Exception as exc:
        log.warning(
            "review_diff_single: %s raised %s: %s", model, type(exc).__name__, exc
        )
        return []


def review_diff_multi(
    diff_text: str,
    llm_client: Any,
    models: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """
    Send diff to multiple models sequentially; return merged, deduplicated findings.

    Models are called one at a time. LLM errors are silently skipped — never raises.
    Returns empty list if diff is empty or all models fail.

    Args:
        diff_text:  Output of get_pr_diff().
        llm_client: LLMClient instance.
        models:     Model IDs. Defaults to DEFAULT_MODELS (claude-sonnet + gemini-flash).

    Returns:
        Deduplicated findings sorted by severity (critical first).
    """
    if not diff_text or not diff_text.strip():
        log.info("review_diff_multi: empty diff, skipping")
        return []

    if models is None:
        models = DEFAULT_MODELS

    models_to_use = models[:2]  # cap at 2 for cost control
    all_findings: List[Dict[str, Any]] = []
    models_used: List[str] = []

    for model in models_to_use:
        log.info("review_diff_multi: querying %s", model)
        findings = review_diff_single(diff_text, model, llm_client)
        if findings:
            for f in findings:
                f["_source_model"] = model
            all_findings.extend(findings)
            models_used.append(model)
        else:
            log.info("review_diff_multi: %s returned no findings", model)

    if not all_findings:
        return []

    merged = deduplicate_findings(all_findings)

    for f in merged:
        f["_models_used"] = models_used

    return merged


def deduplicate_findings(all_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deduplicate findings across models.

    Groups by (file, category). Within each group keeps the highest-severity
    finding and sets models_agreed to the count of distinct source models.

    Returns findings sorted by severity descending (critical → low).
    """
    if not all_findings:
        return []

    groups: Dict[tuple, List[Dict[str, Any]]] = {}
    for finding in all_findings:
        file_key = str(finding.get("file") or "")
        category_key = str(finding.get("category") or "").lower()
        key = (file_key, category_key)
        groups.setdefault(key, []).append(finding)

    merged: List[Dict[str, Any]] = []
    for (file_key, category_key), group in groups.items():
        source_models = {f.get("_source_model") for f in group if f.get("_source_model")}
        models_agreed = max(len(source_models), 1)

        def _sort_key(f: Dict[str, Any]) -> tuple:
            sev = _SEVERITY_RANK.get(str(f.get("severity") or "").lower(), 0)
            explanation_len = len(str(f.get("why_it_matters") or "")) + len(
                str(f.get("finding") or "")
            )
            return (sev, explanation_len)

        best = max(group, key=_sort_key)

        merged.append({
            "file": best.get("file") or "",
            "line": best.get("line"),
            "severity": str(best.get("severity") or "low").lower(),
            "category": str(best.get("category") or "general").lower(),
            "finding": best.get("finding") or "",
            "why_it_matters": best.get("why_it_matters") or "",
            "suggestion": best.get("suggestion") or "",
            "models_agreed": models_agreed,
        })

    merged.sort(
        key=lambda f: _SEVERITY_RANK.get(str(f.get("severity") or "").lower(), 0),
        reverse=True,
    )
    return merged


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _normalise_finding(item: Dict[str, Any], model: str) -> Optional[Dict[str, Any]]:
    """Validate and normalise a single finding dict from an LLM response."""
    finding_text = (
        item.get("finding")
        or item.get("description")
        or item.get("issue")
        or ""
    )
    if not finding_text:
        return None

    severity = str(item.get("severity") or "low").lower()
    if severity not in _SEVERITY_RANK:
        severity = "low"

    line = item.get("line")
    if line is not None:
        try:
            line = int(line)
        except (TypeError, ValueError):
            line = None

    return {
        "file": str(item.get("file") or ""),
        "line": line,
        "severity": severity,
        "category": str(item.get("category") or "general").lower(),
        "finding": str(finding_text),
        "why_it_matters": str(item.get("why_it_matters") or ""),
        "suggestion": str(item.get("suggestion") or ""),
        "_source_model": model,
    }
