"""
Codeproof Verify Result — standalone version.

Structured result contract for the verify pipeline.

Requires:
    pip install pydantic>=2

Public API
----------
    RunSummary              — nested counts from the test runner
    ProtectedFilesResult    — protected-file check outcome
    SecurityResult          — pip-audit + detect-secrets scan outcome
    VerifyResult            — top-level pipeline result (Pydantic model)
    validate_verify_result  — standalone schema validator
"""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, ValidationError

from .pr_coach import enrich_security_findings, format_review_footer

# ---------------------------------------------------------------------------
# Nested models
# ---------------------------------------------------------------------------


class RunSummary(BaseModel):
    total: int
    passed: int
    failed: int
    errors: int


class ProtectedFilesResult(BaseModel):
    clean: bool
    violations: List[str] = Field(default_factory=list)


class SecurityResult(BaseModel):
    """Outcome from pip-audit + detect-secrets scans."""

    cve_count: int = 0
    secrets_found: int = 0
    cve_findings: List[Dict[str, Any]] = Field(default_factory=list)
    secret_files: List[str] = Field(default_factory=list)
    pip_audit_skipped: bool = False
    detect_secrets_skipped: bool = False


# ---------------------------------------------------------------------------
# Main result model
# ---------------------------------------------------------------------------


class VerifyResult(BaseModel):
    """Validated, typed result from run_verify_pipeline()."""

    repo: str
    verdict: Literal["PASS", "FAIL", "ERROR"]
    fitness: float = Field(ge=0.0, le=1.0)
    test_summary: RunSummary
    protected_files: ProtectedFilesResult
    security: SecurityResult = Field(default_factory=SecurityResult)
    details: str = ""
    timestamp: str
    duration_sec: float = 0.0
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    models_used: List[str] = Field(default_factory=list)
    base_fitness: Optional[float] = None
    fitness_delta: Optional[float] = None

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VerifyResult":
        """Parse and validate a plain dict; raises ValueError on bad data."""
        try:
            return cls.model_validate(data)
        except ValidationError as exc:
            raise ValueError(f"Invalid VerifyResult data: {exc}") from exc

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain dict (round-trips through from_dict)."""
        return self.model_dump()

    # ------------------------------------------------------------------
    # Human-readable Markdown report
    # ------------------------------------------------------------------

    def to_markdown(self) -> str:
        """Return a GitHub PR-ready Markdown review comment."""
        return _format_markdown(self)


# ---------------------------------------------------------------------------
# Private Markdown formatting
# ---------------------------------------------------------------------------

_VERDICT_ICON: Dict[str, str] = {
    "PASS": "✅",
    "FAIL": "❌",
    "ERROR": "⚠️",
}

_SEVERITY_EMOJI: Dict[str, str] = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
}

_SEVERITY_ORDER = ["critical", "high", "medium", "low"]

_SEVERITY_RANK: Dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}

_BAR_LENGTH = 10


def _fitness_bar(fitness: float) -> str:
    filled = round(fitness * _BAR_LENGTH)
    return "█" * filled + "░" * (_BAR_LENGTH - filled)


def _fitness_score_line(r: VerifyResult) -> str:
    bar = _fitness_bar(r.fitness)
    if r.fitness_delta is not None and r.base_fitness is not None:
        sign = "+" if r.fitness_delta >= 0 else ""
        icon = "✅" if r.fitness_delta >= 0 else "⚠️"
        return (
            f"**Fitness Score:** {bar} "
            f"{r.base_fitness:.2f} → {r.fitness:.2f} "
            f"({sign}{r.fitness_delta:.2f} {icon})"
        )
    return f"**Fitness Score:** {bar} {r.fitness:.2f}"


def _format_markdown(r: VerifyResult) -> str:
    icon = _VERDICT_ICON.get(r.verdict, "❓")
    lines: List[str] = [
        f"## Verification Result: {icon} {r.verdict}",
        "",
        _fitness_score_line(r),
        "",
        "### Test Summary",
        "",
        "| Metric | Count |",
        "| --- | --- |",
        f"| Total | {r.test_summary.total} |",
        f"| Passed | {r.test_summary.passed} |",
        f"| Failed | {r.test_summary.failed} |",
        f"| Errors | {r.test_summary.errors} |",
        "",
    ]

    # Protected files
    lines += ["### Protected Files", ""]
    if r.protected_files.clean:
        lines.append("**Status:** Clean ✅")
    else:
        lines += ["**Status:** Violations Found ❌", "", "**Violations:**"]
        for v in r.protected_files.violations:
            lines.append(f"- `{v}`")
    lines.append("")

    # Security
    lines += ["### 🔒 Security", ""]
    sec = r.security

    if sec.pip_audit_skipped:
        lines.append("**CVEs:** ⚠️ pip-audit not available — skipped")
    elif sec.cve_count == 0:
        lines.append("**CVEs:** ✅ No known vulnerabilities")
    else:
        word = "vulnerability" if sec.cve_count == 1 else "vulnerabilities"
        lines.append(f"**CVEs:** {sec.cve_count} {word} found")
        if sec.cve_findings:
            lines += [
                "",
                "| Package | Version | Vulnerability ID |",
                "| --- | --- | --- |",
            ]
            for f in sec.cve_findings:
                v_id = str(f.get('id', 'unknown'))
                display_id = v_id.replace('npm-', 'NPM: ') if v_id.startswith('npm-') else v_id
                lines.append(
                    f"| {f.get('name', 'unknown')} "
                    f"| {f.get('version', 'unknown')} "
                    f"| {display_id} |"
                )

    lines.append("")

    if sec.detect_secrets_skipped:
        lines.append("**Secrets:** ⚠️ detect-secrets not available — skipped")
    elif sec.secrets_found == 0:
        lines.append("**Secrets:** ✅ No secrets detected")
    else:
        word = "secret" if sec.secrets_found == 1 else "secrets"
        lines.append(f"**Secrets:** {sec.secrets_found} potential {word} detected")
        for path in sec.secret_files:
            lines.append(f"- `{path}`")
    lines.append("")

    # Details
    if r.details:
        lines += ["### Details", "", r.details, ""]

    # Code Review Findings
    n_models = len(r.models_used)
    review_header = (
        f"### 🔍 Code Review ({n_models} model{'s' if n_models != 1 else ''})"
        if n_models > 0
        else "### 🔍 Code Review"
    )
    lines += [review_header, ""]

    # Merge enriched security findings into findings list
    sec_findings = enrich_security_findings({
        "pip_audit": {
            "vulns": [
                {
                    "package": f.get("name", "unknown"),
                    "version": f.get("version", "unknown"),
                    "id": f.get("id", "unknown"),
                    "description": f.get("description", ""),
                    "severity": f.get("severity", "high"),
                    "fix_version": f.get("fix_version"),
                }
                for f in sec.cve_findings
            ]
        }
        if not sec.pip_audit_skipped and sec.cve_count > 0
        else {"vulns": []},
        "detect_secrets": {
            "results": {
                path: {
                    "matches": [
                        {"path": path, "type": "Secret", "line": None}
                    ]
                }
                for path in sec.secret_files
            }
        }
        if not sec.detect_secrets_skipped and sec.secrets_found > 0
        else {"results": {}},
    })
    all_findings = list(r.findings) + sec_findings

    if not all_findings:
        lines.append("No issues found.")
    else:
        by_severity: Dict[str, List[Dict[str, Any]]] = {
            sev: [] for sev in _SEVERITY_ORDER
        }
        for f in all_findings:
            sev = str(f.get("severity") or "low").lower()
            if sev not in by_severity:
                sev = "low"
            by_severity[sev].append(f)

        for sev in _SEVERITY_ORDER:
            group = by_severity[sev]
            if not group:
                continue
            emoji = _SEVERITY_EMOJI.get(sev, "⚪")
            lines += [f"**{emoji} {sev.capitalize()}**", ""]
            for f in group:
                file_ref = f.get("file") or ""
                line_ref = f.get("line")
                if file_ref and line_ref is not None:
                    location = f"`{file_ref}:{line_ref}`"
                elif file_ref:
                    location = f"`{file_ref}`"
                elif line_ref is not None:
                    location = f"line {line_ref}"
                else:
                    location = ""

                agreed = f.get("models_agreed", 1)
                agreed_badge = (
                    f" *(agreed by {agreed} models)*" if agreed > 1 else ""
                )

                finding_text = f.get("finding") or ""
                why = f.get("why_it_matters") or ""
                suggestion = f.get("suggestion") or ""

                if location:
                    lines.append(f"- {location} — {finding_text}{agreed_badge}")
                else:
                    lines.append(f"- {finding_text}{agreed_badge}")
                if why:
                    lines.append(f"  - **Why:** {why}")
                if suggestion:
                    lines.append(f"  - **Fix:** {suggestion}")
            lines.append("")

    lines.append(
        f"*Timestamp: {r.timestamp} | Duration: {r.duration_sec:.2f}s*"
    )
    lines.append("")
    lines.append(
        format_review_footer(
            len(r.models_used), r.test_summary.total, r.duration_sec
        )
    )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Standalone validator
# ---------------------------------------------------------------------------


def validate_verify_result(
    data: Dict[str, Any],
) -> "tuple[bool, List[str]]":
    """
    Validate a plain dict against the VerifyResult schema.

    Returns:
        (True, [])              — data is valid
        (False, [error, …])    — data is invalid; list describes each problem
    """
    try:
        VerifyResult.model_validate(data)
        return True, []
    except ValidationError as exc:
        return False, [
            f"{' → '.join(str(loc) for loc in err['loc'])}: {err['msg']}"
            for err in exc.errors()
        ]
