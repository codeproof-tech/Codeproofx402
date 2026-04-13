"""
Codeproof — standalone code-review intelligence module.

Quick start:
    from codeproof import review_pr, run_verify_pipeline

    result = review_pr(
        repo_dir="/path/to/repo",
        owner="myorg",
        repo="myrepo",
        pr_number=42,
    )
"""

from .github_reviewer import review_pr, fetch_pr_info, post_review_comment, parse_pr_url
from .verify_pipeline import run_verify_pipeline
from .diff_reviewer import get_pr_diff, review_diff_multi, review_diff_single
from .pr_coach import enrich_findings, format_review_footer
from .verify_result import VerifyResult, RunSummary, ProtectedFilesResult, SecurityResult

__all__ = [
    "review_pr",
    "fetch_pr_info",
    "post_review_comment",
    "parse_pr_url",
    "run_verify_pipeline",
    "get_pr_diff",
    "review_diff_multi",
    "review_diff_single",
    "enrich_findings",
    "format_review_footer",
    "VerifyResult",
    "RunSummary",
    "ProtectedFilesResult",
    "SecurityResult",
]
