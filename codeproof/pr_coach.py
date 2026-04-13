"""
Codeproof PR Coach — standalone version.

Post-processing layer that enriches raw findings and formats the
review footer.

Public API
----------
    enrich_findings(findings)            -> list[dict]
    enrich_security_findings(sec_result) -> list[dict]
    format_review_footer(models, tests, duration) -> str
"""

from __future__ import annotations

from typing import Any, Dict, List

PRODUCT_NAME = "Codeproof"


def enrich_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Enrich findings with default explanations/suggestions if missing.

    Normalises severity strings to lowercase.
    Does NOT mutate the input dicts — returns enriched copies.

    Args:
        findings: List of finding dicts (file, severity, category, finding, …).

    Returns:
        New list of enriched dicts.
    """
    enriched = []
    for raw in findings:
        f = dict(raw)  # shallow copy — never mutate caller's data
        f["severity"] = (f.get("severity") or "low").lower()
        if not f.get("why_it_matters") or len(f["why_it_matters"]) < 10:
            f["why_it_matters"] = (
                f"This is a {f.get('category', 'code quality')} issue detected "
                f"with {f['severity']} severity."
            )
        if not f.get("suggestion"):
            f["suggestion"] = (
                f"Review this code with respect to "
                f"{f.get('category', 'code quality')} best practices."
            )
        enriched.append(f)
    return enriched


def enrich_security_findings(
    security_result: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Convert security scan results (CVEs, secrets) into the standard finding format.

    Expected structure for *security_result*::

        {
            "pip_audit": {
                "vulns": [
                    {
                        "package": "requests",
                        "version": "2.27.0",
                        "id": "CVE-2023-32681",
                        "description": "...",
                        "severity": "high",
                        "fix_version": "2.31.0",
                    },
                    ...
                ]
            },
            "detect_secrets": {
                "results": {
                    "path/to/file.py": {
                        "matches": [
                            {"path": "path/to/file.py", "type": "AWS Access Key", "line": 42},
                            ...
                        ]
                    }
                }
            }
        }

    Returns:
        List of finding dicts in the canonical Codeproof format.
    """
    findings: List[Dict[str, Any]] = []

    # CVE findings
    pip_audit = security_result.get("pip_audit") or {}
    for vuln in pip_audit.get("vulns") or []:
        pkg = vuln.get("package", "unknown")
        ver = vuln.get("version", "unknown")
        fix = vuln.get("fix_version")
        v_id = vuln.get("id", "unknown")
        
        is_npm = str(v_id).startswith("npm-")
        file_name = "package.json" if is_npm else "requirements.txt"
        display_id = v_id.replace("npm-", "NPM Advisory: ") if is_npm else v_id

        findings.append({
            "file": file_name,
            "severity": (vuln.get("severity") or "high").lower(),
            "category": "security/cve",
            "finding": (
                f"Known vulnerability in {pkg} {ver}: {display_id}"
            ),
            "why_it_matters": f"Vulnerability: {vuln.get('description', 'N/A')}",
            "suggestion": (
                f"Upgrade {pkg} to "
                f"{'version ' + fix if fix else 'a compatible version'} to mitigate."
            ),
            "cve_id": v_id,
            "package": pkg,
            "version": ver,
            "fix_version": fix,
        })

    # Secret findings
    detect_secrets = security_result.get("detect_secrets") or {}
    for _file_path, result in (detect_secrets.get("results") or {}).items():
        for match in result.get("matches") or []:
            findings.append({
                "file": match.get("path"),
                "severity": "critical",  # secrets are always critical
                "category": "security/secret",
                "finding": (
                    f"Potential secret or credential detected in "
                    f"file '{match.get('path')}'"
                ),
                "why_it_matters": (
                    f"Secrets in code can lead to unauthorised access and data "
                    f"breaches. Detected type: {match.get('type', 'unknown')}"
                ),
                "suggestion": (
                    "Remove the secret from code. If already committed, rotate "
                    "any associated credentials immediately. Use environment "
                    "variables or a secrets manager instead."
                ),
                "secret_type": match.get("type"),
                "line_number": match.get("line"),
            })

    return findings


def format_review_footer(
    models_used: int,
    test_total: int,
    duration_sec: float,
) -> str:
    """
    Return a branded Markdown footer for the review comment.

    Example output::

        ---
        _Reviewed by **Codeproof** · 2 models · 47 tests · 12.4s_
    """
    return (
        f"---\n"
        f"_Reviewed by **{PRODUCT_NAME}** "
        f"· {models_used} model{'s' if models_used != 1 else ''} "
        f"· {test_total} test{'s' if test_total != 1 else ''} "
        f"· {duration_sec:.1f}s_"
    )
