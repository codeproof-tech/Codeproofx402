"""
Codeproof Verify Pipeline — standalone polyglot version.

Run a full policy-based verification pass on a local repository and return
a structured verdict with a fitness score.

Requirements
------------
    pip install pydantic>=2 openai>=1

Pipeline steps
--------------
  1. Detect project type (Python/Node.js) and setup isolated environments
  2. Load (or auto-generate) repo_policy.yaml from the repo
  3. Run all test commands; parse and sum pass/fail counts
  4. Check for protected file modifications via git diff
  5. Run security scans: isolated pip-audit + npm audit + detect-secrets
  6. Compute weighted fitness score (0.0-1.0)
  7. Return structured VerifyResult
"""

from __future__ import annotations

import os
import shutil
import sys
import json
import logging
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .verify_result import SecurityResult, VerifyResult

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PASS_THRESHOLD = 0.7

_WEIGHTS: Dict[str, float] = {
    "test_pass_rate": 0.50,
    "protected_files_clean": 0.25,
    "security": 0.15,
    "policy_compliance": 0.10,
}

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run(
    args: List[str],
    cwd: Optional[Path] = None,
    timeout: int = 300,
) -> Tuple[int, str]:
    """Run a subprocess; return (returncode, combined stdout+stderr)."""
    try:
        result = subprocess.run(
            args,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        out = "\n".join(
            filter(None, [result.stdout.strip(), result.stderr.strip()])
        )
        return result.returncode, out
    except subprocess.TimeoutExpired:
        return 1, f"Command timed out after {timeout}s: {' '.join(args)}"
    except FileNotFoundError as exc:
        return 1, f"Command not found: {exc}"
    except Exception as exc:
        return 1, f"Subprocess error: {exc}"


def _run_shell(
    cmd: str,
    cwd: Optional[Path] = None,
    timeout: int = 300,
    env: Optional[Dict[str, str]] = None, 
) -> Tuple[int, str]:
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            cwd=str(cwd) if cwd else None,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        out = "\n".join(
            filter(None, [result.stdout.strip(), result.stderr.strip()])
        )
        return result.returncode, out
    except subprocess.TimeoutExpired:
        return 1, f"Command timed out after {timeout}s: {cmd}"
    except Exception as exc:
        return 1, f"Shell error: {exc}"


# ---------------------------------------------------------------------------
# Environment Setup (Polyglot)
# ---------------------------------------------------------------------------

def _setup_python_env(repo_dir: Path) -> Optional[Path]:
    """Detect Python markers, create .venv_codeproof, install deps, return bin path."""
    markers = ["requirements.txt", "pyproject.toml", "setup.py", "Pipfile"]
    if not any((repo_dir / m).exists() for m in markers):
        return None

    venv_dir = repo_dir / ".venv_codeproof"
    log.info("Setting up isolated Python venv at %s", venv_dir)
    
    subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], check=True)
    bin_dir = venv_dir / ("Scripts" if os.name == "nt" else "bin")
    pip_exe = str(bin_dir / "pip")

    try:
        subprocess.run([pip_exe, "install", "pip-audit", "pytest"], cwd=repo_dir, capture_output=True, check=True)

        if (repo_dir / "requirements.txt").exists():
            res = subprocess.run([pip_exe, "install", "-r", "requirements.txt"], cwd=repo_dir, capture_output=True, text=True)
            if res.returncode != 0:
                log.warning(f"pip install -r requirements.txt failed: {res.stderr[:500]}")
                
        elif (repo_dir / "pyproject.toml").exists() or (repo_dir / "setup.py").exists():
            res = subprocess.run([pip_exe, "install", "-e", ".[test]"], cwd=repo_dir, capture_output=True, text=True)
            if res.returncode != 0:
                res_fallback = subprocess.run([pip_exe, "install", "-e", "."], cwd=repo_dir, capture_output=True, text=True)
                if res_fallback.returncode != 0:
                    log.warning(f"pip install -e . failed: {res_fallback.stderr[:500]}")
                    print(f"\n[WARNING] Failed to install project dependencies. Tests may fail.\nError: {res_fallback.stderr[:300]}...\n")
                    
    except Exception as exc:
        log.warning("Failed to setup venv tools: %s", exc)

    return bin_dir


def _setup_node_env(repo_dir: Path) -> bool:
    """Detect package.json, run npm install, return True if found."""
    if not (repo_dir / "package.json").exists():
        return False
    
    log.info("Setting up Node.js environment (npm install) in %s", repo_dir)
    _run_shell("npm install", cwd=repo_dir)
    return True


# ---------------------------------------------------------------------------
# Policy loading / auto-generation
# ---------------------------------------------------------------------------

def _load_verify_policy(repo_dir: Path, python_bin: Optional[Path], node_setup: bool) -> Dict[str, Any]:
    policy_path = repo_dir / "repo_policy.yaml"
    if policy_path.exists():
        raw = policy_path.read_text(encoding="utf-8", errors="replace")
        return _parse_verify_policy(raw, source="loaded")
    return _generate_minimal_policy(repo_dir, python_bin, node_setup)


def _parse_verify_policy(text: str, source: str = "loaded") -> Dict[str, Any]:
    policy: Dict[str, Any] = {
        "test_commands": [],
        "protected_files": [],
        "quality_rules": [],
        "source": source,
    }
    current_list_key: Optional[str] = None

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if stripped.startswith("- ") and current_list_key:
            val = stripped[2:].strip().strip("'\"")
            policy[current_list_key].append(val)
            continue

        if ":" in stripped:
            key, _, val = stripped.partition(":")
            key = key.strip()
            val = val.strip()

            if key in ("protected_files", "quality_rules", "test_commands"):
                current_list_key = key
                if val and not val.startswith("#"):
                    v = val.strip().strip("'\"")
                    if v:
                        policy[key].append(v)
            elif key == "test_command": # Backwards compatibility
                current_list_key = None
                if val:
                    policy["test_commands"].append(val.strip("'\""))
            else:
                current_list_key = None

    return policy


def _generate_minimal_policy(repo_dir: Path, python_bin: Optional[Path], node_setup: bool) -> Dict[str, Any]:
    """Auto-detect test commands based on prepared environments."""
    test_commands = []

    if python_bin:
        pytest_exe = str(python_bin / "pytest")
        test_commands.append(f'"{pytest_exe}" --tb=short -q')

    if node_setup:
        package_json_path = repo_dir / "package.json"
        has_valid_test = False
        if package_json_path.exists():
            try:
                import json
                with open(package_json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    test_script = data.get("scripts", {}).get("test", "")
                    if test_script and "no test specified" not in test_script.lower():
                        has_valid_test = True
            except Exception:
                pass
        
        if has_valid_test:
            test_commands.append("npm test")

    protected: List[str] = []
    for candidate in ["repo_policy.yaml", ".github/workflows"]:
        if (repo_dir / candidate).exists():
            protected.append(candidate)

    return {
        "test_commands": test_commands,
        "protected_files": protected,
        "quality_rules": [],
        "source": "generated",
    }


# ---------------------------------------------------------------------------
# Step 2: Run tests
# ---------------------------------------------------------------------------

def _step_run_tests(repo_dir: Path, test_commands: List[str]) -> Tuple[Dict[str, Any], str]:
    if not test_commands:
        return {"total": 0, "passed": 0, "failed": 0, "errors": 0}, "No test command configured or detected."

    summary = {"total": 0, "passed": 0, "failed": 0, "errors": 0}
    details_parts = []

    import os
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo_dir)

    for cmd in test_commands:
        rc, output = _run_shell(cmd, cwd=repo_dir, env=env)
        parsed = _parse_test_output(output)

        if parsed["total"] == 0 and rc == 0:
            parsed = {"total": 1, "passed": 1, "failed": 0, "errors": 0}
        elif parsed["total"] == 0 and rc != 0:
            if 'Missing script: "test"' in output or "no tests ran" in output or "no test specified" in output:
                parsed = {"total": 0, "passed": 0, "failed": 0, "errors": 0}
            else:
                parsed = {"total": 1, "passed": 0, "failed": 1, "errors": 0}

        summary["total"] += parsed["total"]
        summary["passed"] += parsed["passed"]
        summary["failed"] += parsed["failed"]
        summary["errors"] += parsed["errors"]
        details_parts.append(f"$ {cmd}\n{output[:1000]}")

    return summary, "\n\n".join(details_parts)[:2000]


def _parse_test_output(output: str) -> Dict[str, Any]:
    total = passed = failed = errors = 0

    for label, pattern in [
        ("passed", r"(\d+)\s+passed"),
        ("failed", r"(\d+)\s+failed"),
        ("errors", r"(\d+)\s+error"),
    ]:
        m = re.search(pattern, output, re.IGNORECASE)
        if m:
            val = int(m.group(1))
            if label == "passed":
                passed = val
            elif label == "failed":
                failed = val
            else:
                errors = val

    m = re.search(r"(\d+)\s+total", output, re.IGNORECASE)
    if m:
        total = int(m.group(1))

    m = re.search(r"Ran\s+(\d+)\s+tests?", output, re.IGNORECASE)
    if m:
        total = int(m.group(1))
        m2 = re.search(r"failures=(\d+)", output, re.IGNORECASE)
        if m2:
            failed = int(m2.group(1))
        m3 = re.search(r"errors=(\d+)", output, re.IGNORECASE)
        if m3:
            errors = int(m3.group(1))
        passed = max(0, total - failed - errors)

    if total == 0:
        total = passed + failed + errors

    return {"total": total, "passed": passed, "failed": failed, "errors": errors}


# ---------------------------------------------------------------------------
# Step 3: Protected files
# ---------------------------------------------------------------------------

def _step_check_protected_files(repo_dir: Path, protected_files: List[str], base_ref: str = "HEAD") -> Tuple[bool, List[str]]:
    if not protected_files:
        return True, []

    rc, diff_output = _run(["git", "diff", "--name-only", base_ref], cwd=repo_dir)
    if rc != 0:
        return True, []

    changed = {line.strip() for line in diff_output.splitlines() if line.strip()}
    violations = [
        pf for pf in protected_files
        if any(ch == pf or ch.startswith(pf.rstrip("/") + "/") for ch in changed)
    ]
    return len(violations) == 0, violations


# ---------------------------------------------------------------------------
# Step 4: Security scans
# ---------------------------------------------------------------------------

def _run_pip_audit(repo_dir: Path, python_bin: Optional[Path]) -> Dict[str, Any]:
    import shutil
    pip_audit_exe = shutil.which("pip-audit")
    if not pip_audit_exe:
        host_scripts_dir = Path(sys.executable).parent
        pip_audit_exe = str(host_scripts_dir / "pip-audit" + (".exe" if os.name == "nt" else ""))

    if not pip_audit_exe:
        return {"cve_count": 0, "findings": [], "skipped": True, "reason": "pip-audit not found globally"}

    audit_args = [pip_audit_exe, "--format", "json", "--progress-spinner", "off"]
    
    if (repo_dir / "requirements.txt").exists():
        audit_args.extend(["-r", "requirements.txt"])
    elif (repo_dir / "pyproject.toml").exists() or (repo_dir / "setup.py").exists():
        audit_args.append(".")
    else:
        return {"cve_count": 0, "findings": [], "skipped": True, "reason": "No dep files found"}

    try:
        result = subprocess.run(
            audit_args,
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
            timeout=120,
        )
        raw = result.stdout.strip() or result.stderr.strip()
        if not raw:
            return {"cve_count": 0, "findings": [], "skipped": False}

        data = json.loads(raw)
        cve_count = 0
        findings: List[Dict[str, Any]] = []

        for dep in data.get("dependencies", []):
            pkg_name = dep.get("name", "unknown")
            if pkg_name.lower() in ("pip", "setuptools", "wheel"):
                continue

            for vuln in dep.get("vulns", []):
                cve_count += 1
                fix_versions = vuln.get("fix_versions", [])
                findings.append({
                    "name": pkg_name,
                    "version": dep.get("version", "unknown"),
                    "id": vuln.get("id", "unknown"),
                    "fix_versions": fix_versions,
                    "fix_version": fix_versions[0] if fix_versions else None,
                    "description": vuln.get("description", ""),
                    "severity": "high",
                })

        return {"cve_count": cve_count, "findings": findings, "skipped": False}
    except Exception as exc:
        return {"cve_count": 0, "findings": [], "skipped": True, "reason": str(exc)}


def _run_npm_audit(repo_dir: Path, node_setup: bool) -> Dict[str, Any]:
    if not node_setup:
        return {"cve_count": 0, "findings": [], "skipped": True, "reason": "No Node.js environment configured"}

    rc, output = _run_shell("npm audit --json", cwd=repo_dir, timeout=120)
    try:
        data = json.loads(output)
        vulns = data.get("vulnerabilities", {})
        cve_count = len(vulns)
        findings = []
        
        for pkg, info in vulns.items():
            findings.append({
                "name": pkg,
                "version": "unknown",
                "id": f"npm-{pkg}",
                "description": f"npm audit finding. Severity: {info.get('severity', 'high')}",
                "severity": info.get("severity", "high"),
            })
        return {"cve_count": cve_count, "findings": findings, "skipped": False}
    except Exception as exc:
        return {"cve_count": 0, "findings": [], "skipped": True, "reason": str(exc)}


def _run_detect_secrets(repo_dir: Path) -> Dict[str, Any]:
    detect_secrets_exe = shutil.which("detect-secrets")
    
    if not detect_secrets_exe:
        host_scripts_dir = Path(sys.executable).parent
        if (host_scripts_dir / "detect-secrets.exe").exists():
            detect_secrets_exe = str(host_scripts_dir / "detect-secrets.exe")
        elif (host_scripts_dir / "detect-secrets").exists():
            detect_secrets_exe = str(host_scripts_dir / "detect-secrets")

    if not detect_secrets_exe:
        return {"secrets_found": 0, "files": [], "skipped": True, "reason": "Not found"}

    try:
        result = subprocess.run(
            [detect_secrets_exe, "scan", str(repo_dir)],
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
            timeout=60,
        )
        
        stdout_text = result.stdout.strip()
        if not stdout_text:
            return {"secrets_found": 0, "files": [], "skipped": False}

        data = json.loads(stdout_text)
        results = data.get("results", {})
        files_with_secrets = list(results.keys())
        secrets_found = sum(len(v) for v in results.values())

        return {"secrets_found": secrets_found, "files": files_with_secrets, "skipped": False}
        
    except Exception as exc:
        return {"secrets_found": 0, "files": [], "skipped": True, "reason": str(exc)}


# ---------------------------------------------------------------------------
# Step 5: Scoring
# ---------------------------------------------------------------------------

def _compute_security_score(total_cve: int, secrets_found: int, skipped_all_cve: bool, secrets_skipped: bool) -> float:
    if skipped_all_cve and secrets_skipped:
        return 0.5

    score = 1.0
    if not skipped_all_cve:
        score -= 0.2 * total_cve
    if not secrets_skipped:
        score -= 0.3 * secrets_found

    return max(0.0, score)


def _compute_fitness(test_summary: Dict[str, Any], protected_clean: bool, policy_loaded: bool, security_score: float = 0.5) -> float:
    total = test_summary.get("total", 0)
    passed = test_summary.get("passed", 0)
    
    # If no tests exist (total == 0), don't penalise the pass rate.
    test_pass_rate = (min(1.0, passed / total) if total > 0 else 1.0)

    fitness = (
        _WEIGHTS["test_pass_rate"] * test_pass_rate
        + _WEIGHTS["protected_files_clean"] * (1.0 if protected_clean else 0.0)
        + _WEIGHTS["security"] * security_score
        + _WEIGHTS["policy_compliance"] * (1.0 if policy_loaded else 0.5)
    )
    return round(min(1.0, max(0.0, fitness)), 4)


def _determine_verdict(fitness: float, violations: List[str]) -> str:
    return "PASS" if fitness >= PASS_THRESHOLD and not violations else "FAIL"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_verify_pipeline(repo_dir: "str | Path", base_ref: str = "HEAD") -> "VerifyResult":
    t_start = time.monotonic()
    repo_path = Path(repo_dir).resolve()
    timestamp = _utc_now()

    try:
        if not repo_path.exists():
            raise FileNotFoundError(f"Repository directory not found: {repo_path}")

        # Step 1: Prepare Environments (Polyglot Isolation)
        python_bin = _setup_python_env(repo_path)
        node_setup = _setup_node_env(repo_path)

        # Step 2: Policy
        policy = _load_verify_policy(repo_path, python_bin, node_setup)
        policy_loaded = policy["source"] == "loaded"
        test_commands: List[str] = policy.get("test_commands", [])
        protected_files: List[str] = policy.get("protected_files", [])

        # Step 3: Tests
        test_summary, test_details = _step_run_tests(repo_path, test_commands)

        # Step 4: Protected files
        protected_clean, violations = _step_check_protected_files(repo_path, protected_files, base_ref=base_ref)

        # Step 5: Security
        pip_audit_result = _run_pip_audit(repo_path, python_bin)
        npm_audit_result = _run_npm_audit(repo_path, node_setup)
        detect_secrets_result = _run_detect_secrets(repo_path)

        # Merge Python and JS vulnerabilities into the existing schema
        total_cve = pip_audit_result.get("cve_count", 0) + npm_audit_result.get("cve_count", 0)
        all_cve_findings = pip_audit_result.get("findings", []) + npm_audit_result.get("findings", [])
        skipped_all_cve = pip_audit_result.get("skipped", False) and npm_audit_result.get("skipped", False)

        security = SecurityResult(
            cve_count=total_cve,
            secrets_found=detect_secrets_result.get("secrets_found", 0),
            cve_findings=all_cve_findings,
            secret_files=detect_secrets_result.get("files", []),
            pip_audit_skipped=skipped_all_cve,
            detect_secrets_skipped=detect_secrets_result.get("skipped", False),
        )

        # Step 6: Fitness
        security_score = _compute_security_score(
            total_cve, 
            detect_secrets_result.get("secrets_found", 0), 
            skipped_all_cve, 
            detect_secrets_result.get("skipped", False)
        )
        fitness = _compute_fitness(test_summary, protected_clean, policy_loaded, security_score)

        # Step 7: Verdict
        verdict = _determine_verdict(fitness, violations)

        detail_parts = [test_details]
        if not policy_loaded:
            detail_parts.append("No repo_policy.yaml found — auto-generated minimal policy.")
        if violations:
            detail_parts.append(f"Protected file violations: {', '.join(violations)}")

        duration = round(time.monotonic() - t_start, 4)
        return VerifyResult.from_dict({
            "repo": str(repo_path),
            "verdict": verdict,
            "fitness": fitness,
            "test_summary": test_summary,
            "protected_files": {"clean": protected_clean, "violations": violations},
            "security": security.model_dump(),
            "details": "\n".join(detail_parts),
            "timestamp": timestamp,
            "duration_sec": duration,
        })

    except Exception as exc:
        log.exception("verify_pipeline: unhandled error for %s", repo_dir)
        duration = round(time.monotonic() - t_start, 4)
        return VerifyResult.from_dict({
            "repo": str(repo_path),
            "verdict": "ERROR",
            "fitness": 0.0,
            "test_summary": {"total": 0, "passed": 0, "failed": 0, "errors": 0},
            "protected_files": {"clean": True, "violations": []},
            "security": SecurityResult().model_dump(),
            "details": f"Pipeline error: {exc}",
            "timestamp": timestamp,
            "duration_sec": duration,
        })