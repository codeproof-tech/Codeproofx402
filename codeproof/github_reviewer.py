"""
Codeproof GitHub Reviewer — standalone version.

Fetches PR metadata, runs the verify pipeline, and posts a review
comment via the GitHub REST API.

Required env vars:
    GITHUB_TOKEN         — GitHub personal access token (repo + PR write scope)
    OPENROUTER_API_KEY   — (or ANTHROPIC_API_KEY / OPENAI_API_KEY for direct routing)

Optional env vars:
    CODEPROOF_MODEL      — LLM model for diff review

Public API
----------
    parse_pr_url(pr_url)                              -> (owner, repo, pr_number)
    fetch_pr_info(owner, repo, pr_number)             -> dict
    checkout_pr_branch(repo_dir, branch)              -> bool
    post_review_comment(owner, repo, pr_number, ...)  -> review_url
    review_pr(repo_dir, owner, repo, pr_number)       -> dict
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .diff_reviewer import DEFAULT_MODELS, get_pr_diff, review_diff_multi
from .llm_client import LLMClient
from .pr_coach import enrich_findings
from .verify_pipeline import run_verify_pipeline

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

_GH_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")
_BRANCH_RE = re.compile(r"^[A-Za-z0-9_.\-/]+$")


def _validate_github_input(owner: str, repo: str, pr_number: int) -> None:
    if not owner or not _GH_NAME_RE.match(owner):
        raise ValueError(f"Invalid owner format: {owner!r}")
    if not repo or not _GH_NAME_RE.match(repo):
        raise ValueError(f"Invalid repo format: {repo!r}")
    if not isinstance(pr_number, int) or pr_number <= 0:
        raise ValueError(f"pr_number must be a positive integer, got: {pr_number!r}")


def _validate_branch(branch: str) -> None:
    if not branch or not _BRANCH_RE.match(branch):
        raise ValueError(f"Invalid branch name: {branch!r}")


def _scrub_token(text: str) -> str:
    token = os.environ.get("GITHUB_TOKEN", "")
    if token and token in text:
        text = text.replace(token, "***REDACTED***")
    return text


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_VERDICT_EVENT = {
    "PASS": "APPROVE",
    "FAIL": "REQUEST_CHANGES",
    "ERROR": "COMMENT",
}

# ---------------------------------------------------------------------------
# Internal subprocess helper
# ---------------------------------------------------------------------------


def _run(args: List[str], cwd: Optional[Path] = None) -> Tuple[int, str]:
    """Run a subprocess; return (returncode, combined stdout+stderr)."""
    try:
        result = subprocess.run(
            args,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=30,
        )
        out = "\n".join(filter(None, [result.stdout.strip(), result.stderr.strip()]))
        return result.returncode, out
    except subprocess.TimeoutExpired:
        return 1, f"Command timed out after 30s: {' '.join(args)}"
    except FileNotFoundError as exc:
        return 1, f"Command not found: {exc}"
    except Exception as exc:
        return 1, f"Subprocess error: {exc}"


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------


def fetch_pr_info(owner: str, repo: str, pr_number: int) -> Dict[str, Any]:
    """
    Fetch PR metadata from GitHub via the REST API (curl + GITHUB_TOKEN).

    Returns a dict with at least:
        head_branch, head_sha, base_branch, title, state, html_url

    Raises RuntimeError on API failure.
    """
    _validate_github_input(owner, repo, pr_number)
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("GITHUB_TOKEN environment variable is not set")

    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}"
    rc, out = _run([
        "curl", "-s", "-w", "\n%{http_code}",
        "-H", f"Authorization: Bearer {token}",
        "-H", "Accept: application/vnd.github+json",
        url,
    ])
    if rc != 0:
        raise RuntimeError(f"GitHub API request failed: {_scrub_token(out)}")

    body, _, status_line = out.rpartition("\n")
    if status_line.strip() and not status_line.strip().startswith("2"):
        raise RuntimeError(
            f"GitHub API returned HTTP {status_line.strip()}: {_scrub_token(body[:500])}"
        )

    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Failed to parse GitHub API response: {exc}") from exc

    return {
        "head_branch": data["head"]["ref"],
        "head_sha": data["head"]["sha"],
        "base_branch": data["base"]["ref"],
        "base_sha": data["base"]["sha"],
        "title": data.get("title", ""),
        "state": data.get("state", ""),
        "html_url": data.get("html_url", ""),
    }


def checkout_pr_branch(repo_dir: Path, branch: str, pr_number: Optional[int] = None) -> bool:
    """
    Fetch and checkout the PR's head branch.
    Returns True on success, False on failure.
    """
    _validate_branch(branch)
    repo_dir = Path(repo_dir)

    if pr_number:
        rc, out = _run(["git", "fetch", "origin", f"pull/{pr_number}/head:{branch}"], cwd=repo_dir)
        if rc == 0:
            rc_chk, out_chk = _run(["git", "checkout", branch], cwd=repo_dir)
            if rc_chk == 0:
                return True

    rc, out = _run(["git", "fetch", "origin"], cwd=repo_dir)
    if rc != 0:
        log.warning("git fetch failed: %s", out)
        return False

    rc, out = _run(["git", "checkout", branch], cwd=repo_dir)
    if rc != 0:
        rc, out = _run(
            ["git", "checkout", "-b", branch, f"origin/{branch}"],
            cwd=repo_dir,
        )
        if rc != 0:
            log.warning("git checkout %s failed: %s", branch, out)
            return False

    return True


def post_review_comment(
    owner: str,
    repo: str,
    pr_number: int,
    body: str,
    verdict: str,
) -> str:
    """
    Post a PR review via GitHub API (curl + GITHUB_TOKEN).

    Verdict mapping:
        PASS  → APPROVE
        FAIL  → REQUEST_CHANGES
        ERROR → COMMENT

    Falls back to issue comment on 422 (self-review scenario).

    Returns the HTML URL of the posted review.
    Raises RuntimeError on failure.
    """
    _validate_github_input(owner, repo, pr_number)
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("GITHUB_TOKEN environment variable is not set")

    event = _VERDICT_EVENT.get(verdict, "COMMENT")
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/reviews"
    payload = json.dumps({"body": body, "event": event})

    rc, out = _run([
        "curl", "-s", "-w", "\n%{http_code}",
        "-X", "POST",
        "-H", f"Authorization: Bearer {token}",
        "-H", "Accept: application/vnd.github+json",
        "-H", "Content-Type: application/json",
        "-d", payload,
        url,
    ])
    if rc != 0:
        raise RuntimeError(f"Failed to post review: {_scrub_token(out)}")

    resp_body, _, status_line = out.rpartition("\n")
    status_code = status_line.strip()

    if status_code == "422":
        # Self-review — fall back to issue comment
        log.warning("Received 422 on reviews endpoint, falling back to issue comment")
        fallback_url = (
            f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments"
        )
        fb_rc, fb_out = _run([
            "curl", "-s", "-w", "\n%{http_code}",
            "-X", "POST",
            "-H", f"Authorization: Bearer {token}",
            "-H", "Accept: application/vnd.github+json",
            "-H", "Content-Type: application/json",
            "-d", json.dumps({"body": body}),
            fallback_url,
        ])
        if fb_rc != 0:
            raise RuntimeError(f"Failed to post fallback comment: {_scrub_token(fb_out)}")
        fb_body, _, fb_status = fb_out.rpartition("\n")
        if fb_status.strip() and not fb_status.strip().startswith("2"):
            raise RuntimeError(
                f"GitHub API returned HTTP {fb_status.strip()} for fallback comment"
            )
        try:
            return json.loads(fb_body).get(
                "html_url", f"https://github.com/{owner}/{repo}/pull/{pr_number}"
            )
        except json.JSONDecodeError:
            return f"https://github.com/{owner}/{repo}/pull/{pr_number}"

    if status_code and not status_code.startswith("2"):
        raise RuntimeError(
            f"GitHub API returned HTTP {status_code} when posting review: {resp_body[:500]}"
        )

    try:
        return json.loads(resp_body).get(
            "html_url", f"https://github.com/{owner}/{repo}/pull/{pr_number}"
        )
    except json.JSONDecodeError:
        return f"https://github.com/{owner}/{repo}/pull/{pr_number}"


def review_pr(
    repo_dir: "str | Path",
    owner: str,
    repo: str,
    pr_number: int,
    dry_run: bool = False,
    output_file: str = "review.md",
) -> Dict[str, Any]:
    """
    Full PR review orchestration.

    Steps:
        1. Fetch PR metadata from GitHub
        2. Run verify pipeline on base branch (fitness baseline)
        3. Checkout PR head branch
        4. Run verify pipeline on head branch
        5. Run multi-model diff review (best-effort)
        6. Post result as PR review comment
        7. Return to base branch

    Args:
        repo_dir:  Path to the locally cloned repository.
        owner:     GitHub repository owner.
        repo:      GitHub repository name.
        pr_number: Pull request number.

    Returns:
        dict with keys: verdict, fitness, base_fitness, fitness_delta,
        review_url, pr_url.

    Raises RuntimeError if a critical step fails.
    """
    repo_path = Path(repo_dir).resolve()

    # Step 1 — PR metadata
    pr_info = fetch_pr_info(owner, repo, pr_number)
    head_branch = pr_info["head_branch"]
    base_branch = pr_info["base_branch"]
    pr_url = pr_info["html_url"]

    # Step 2 — baseline verify (best-effort)
    base_result = None
    try:
        base_result = run_verify_pipeline(repo_dir=repo_path)
    except Exception as exc:
        log.warning("Base branch verify failed (skipping delta): %s", exc)

    # Step 3 — checkout PR branch
    if not checkout_pr_branch(repo_path, head_branch, pr_number):
        raise RuntimeError(f"Failed to checkout PR branch: {head_branch}")

    review_url = pr_url

    try:
        # Step 4 — verify on head
        result = run_verify_pipeline(repo_dir=repo_path)

        if base_result is not None:
            result.base_fitness = base_result.fitness
            result.fitness_delta = round(result.fitness - base_result.fitness, 4)

        # Step 5 — diff review (best-effort)
        try:
            diff_text = get_pr_diff(repo_path, pr_info["base_sha"], pr_info["head_sha"])
            if diff_text:
                findings = review_diff_multi(diff_text, LLMClient())
                result.findings = enrich_findings(findings)
                result.models_used = DEFAULT_MODELS[:2]
        except Exception as exc:
            log.warning("Diff review failed (skipping): %s", exc)

        # Step 6 — post review
        body = result.to_markdown()
        
        if dry_run:
            out_path = Path(output_file).resolve()
            out_path.write_text(body, encoding="utf-8")
            log.info("Dry run enabled. Review saved to %s", out_path)
            review_url = f"file://{out_path}"
        else:
            review_url = post_review_comment(owner, repo, pr_number, body, result.verdict)

        return {
            "verdict": result.verdict,
            "fitness": result.fitness,
            "base_fitness": result.base_fitness,
            "fitness_delta": result.fitness_delta,
            "review_url": review_url,
            "pr_url": pr_url,
        }
    finally:
        # Step 7 — always return to base branch
        _run(["git", "checkout", base_branch], cwd=repo_path)


# ---------------------------------------------------------------------------
# URL parsing helper
# ---------------------------------------------------------------------------

_PR_URL_RE = re.compile(
    r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/pull/(\d+)"
)


def parse_pr_url(pr_url: str) -> Tuple[str, str, int]:
    """
    Parse a GitHub PR URL into (owner, repo, pr_number).

    Raises ValueError for invalid URLs.

    Example::

        owner, repo, num = parse_pr_url("https://github.com/acme/myrepo/pull/42")
    """
    m = _PR_URL_RE.match(pr_url.strip().rstrip("/"))
    if not m:
        raise ValueError(
            f"Invalid PR URL {pr_url!r}. "
            f"Expected: https://github.com/owner/repo/pull/N"
        )
    return m.group(1), m.group(2), int(m.group(3))
