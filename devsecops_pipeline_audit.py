#!/usr/bin/env python3
"""
DevSecOps CI/CD Pipeline Configuration Auditor

Checks local GitHub Actions workflow files for common DevSecOps pipeline
signals: Trivy scanning, SonarQube analysis, explicit security-gate steps,
and potentially risky workflow permissions or trigger patterns.

This is a lightweight static review helper, not a replacement for running
Trivy, SonarQube, GitHub security features, or a full workflow security audit.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

WORKFLOW_DIRS = {".github/workflows"}
SKIP_DIRS = {".git", "node_modules", "venv", ".venv"}

@dataclass
class Finding:
    severity: str
    rule_id: str
    file: str
    line: int
    message: str
    recommendation: str

def read_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []

def find_workflows(root: Path) -> list[Path]:
    if root.is_file():
        return [root] if root.suffix.lower() in {".yml", ".yaml"} else []
    results = []
    for p in root.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in {".yml", ".yaml"}:
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if ".github" in p.parts and "workflows" in p.parts:
            results.append(p)
    return sorted(results)

def audit_workflow(path: Path, root: Path) -> tuple[list[Finding], dict[str, bool]]:
    lines = read_lines(path)
    text = "\n".join(lines)
    findings: list[Finding] = []
    try:
        name = str(path.relative_to(root if root.is_dir() else root.parent))
    except ValueError:
        name = str(path)

    signals = {
        "trivy": bool(re.search(r"(?i)\btrivy\b", text)),
        "sonarqube": bool(re.search(r"(?i)\bsonar(?:cloud|qube)?\b", text)),
        "security_gate": bool(re.search(r"(?i)(security.?gate|wait.?for.?quality.?gate|exit.?code|continue-on-error\s*:\s*false)", text)),
        "least_privilege_permissions": bool(re.search(r"(?m)^\s*permissions\s*:", text)),
    }

    for lineno, line in enumerate(lines, start=1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if re.search(r"(?i)^\s*permissions\s*:\s*write-all\b", line):
            findings.append(Finding("HIGH", "DSC001", name, lineno,
                "Workflow grants write-all permissions.",
                "Use the minimum required permissions at workflow or job scope, such as contents: read."))
        if re.search(r"(?i)^\s*pull_request_target\s*:", line):
            findings.append(Finding("HIGH", "DSC002", name, lineno,
                "Workflow uses pull_request_target, which needs careful review for untrusted contributions.",
                "Avoid checking out or executing untrusted pull-request code with elevated secrets or write permissions."))
        if re.search(r"(?i)^\s*continue-on-error\s*:\s*true\b", line):
            findings.append(Finding("MEDIUM", "DSC003", name, lineno,
                "A step is configured to continue after an error; verify this does not bypass a security gate.",
                "For required security scans, ensure failures block promotion or deployment."))
        if re.search(r"(?i)^\s*secrets\.[A-Z0-9_]+\s*:", line):
            findings.append(Finding("MEDIUM", "DSC004", name, lineno,
                "Secret-like reference appears in a mapping key; confirm no credentials are hard-coded.",
                "Use GitHub Actions secrets or OIDC-based short-lived credentials, and never commit secret values."))
        if re.search(r"(?i)uses:\s*[^#\s]+@(?:main|master|latest)\b", line):
            findings.append(Finding("MEDIUM", "DSC005", name, lineno,
                "An action reference uses a mutable branch/tag.",
                "Pin third-party actions to a reviewed full commit SHA and update through a controlled process."))

    if not signals["trivy"]:
        findings.append(Finding("MEDIUM", "DSC101", name, 1,
            "No Trivy reference found in this workflow.",
            "If container, filesystem, or IaC scanning is in scope, add a suitable Trivy scan step."))
    if not signals["sonarqube"]:
        findings.append(Finding("MEDIUM", "DSC102", name, 1,
            "No SonarQube/SonarCloud reference found in this workflow.",
            "If code-quality analysis is required, add the approved scanner and configure project credentials securely."))
    if not signals["security_gate"]:
        findings.append(Finding("MEDIUM", "DSC103", name, 1,
            "No explicit security/quality gate signal found.",
            "Configure scan failures or quality-gate failures to fail the workflow before deployment."))

    return findings, signals

def main() -> int:
    parser = argparse.ArgumentParser(description="Audit GitHub Actions workflows for DevSecOps pipeline signals.")
    parser.add_argument("path", nargs="?", default=".", help="Repository directory or workflow YAML file")
    parser.add_argument("--json", dest="json_out", help="Write findings and workflow signals to JSON")
    parser.add_argument("--fail-on", choices=["HIGH", "MEDIUM", "LOW", "NEVER"], default="HIGH",
                        help="Exit non-zero when findings at or above this severity exist")
    args = parser.parse_args()

    root = Path(args.path).resolve()
    if not root.exists():
        print(f"Error: path does not exist: {root}", file=sys.stderr)
        return 2
    workflows = find_workflows(root)
    if not workflows:
        print("No GitHub Actions workflow YAML files found under .github/workflows (or supplied YAML file).")
        return 0

    all_findings: list[Finding] = []
    summaries = []
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    for workflow in workflows:
        findings, signals = audit_workflow(workflow, root)
        all_findings.extend(findings)
        summaries.append({"file": str(workflow), "signals": signals})

    all_findings.sort(key=lambda f: (order.get(f.severity, 9), f.file, f.line))
    print(f"DevSecOps CI/CD Pipeline Audit — scanned {len(workflows)} workflow(s); {len(all_findings)} finding(s).")
    for f in all_findings:
        print(f"[{f.severity}] {f.rule_id} {f.file}:{f.line} — {f.message}")
        print(f"  Recommendation: {f.recommendation}")
    if not all_findings:
        print("No configured checks raised findings. This is not proof that the pipeline is secure.")

    if args.json_out:
        payload = {"workflows": summaries, "findings": [asdict(f) for f in all_findings]}
        Path(args.json_out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"JSON report written to: {args.json_out}")

    threshold = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "NEVER": 99}[args.fail_on]
    return 1 if any(order.get(f.severity, 9) <= threshold for f in all_findings) else 0

if __name__ == "__main__":
    raise SystemExit(main())
