# DEVSECOPS-CI-CD-PIPELINE
DEVSECOPS CI/CD PIPELINE
DevSecOps CI/CD Pipeline
A lightweight project demonstrating security gates in a GitHub Actions CI/CD workflow using Trivy for vulnerability/configuration scanning and SonarQube/SonarCloud for code analysis. Includes a Python static auditor that reviews workflow YAML for expected security signals and common pipeline risks.
Scope note: The Python tool audits workflow configuration text only. It does not execute Trivy, connect to SonarQube, inspect a live GitHub repository, or prove that a pipeline is secure.
Project files
devsecops_pipeline_audit.py — static GitHub Actions workflow auditor.
requirements.txt — no external Python packages are required.
Requirements.pdf — runtime and optional tooling requirements.
Project_Report.pdf — project report with the supplied logo.
logo.png — supplied logo asset.
Requirements
Python 3.10+
GitHub repository with Actions enabled (for CI workflow execution)
Optional: Trivy CLI/action and SonarQube or SonarCloud project
Configure tokens/URLs in GitHub repository secrets or variables; do not commit credentials
Run the local workflow auditor
python devsecops_pipeline_audit.py .
Export findings and workflow signals to JSON:
python devsecops_pipeline_audit.py . --json devsecops-audit.json
Use the stricter threshold to fail when medium findings are present:
python devsecops_pipeline_audit.py . --fail-on MEDIUM
The tool looks under .github/workflows for .yml and .yaml files. It checks for Trivy, SonarQube/SonarCloud, security-gate signals, broad workflow permissions, pull_request_target, mutable action references, and continue-on-error: true.
Example GitHub Actions workflow
Create .github/workflows/devsecops.yml and adapt the approved action versions and project settings for your environment:
```yaml
name: DevSecOps CI
on:
  push:
    branches: [main]
  pull_request:


permissions:
  contents: read


jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4


      - name: Run Trivy filesystem scan
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: fs
          scan-ref: .
          severity: HIGH,CRITICAL
          exit-code: '1'


      - name: SonarQube scan
        uses: SonarSource/sonarqube-scan-action@v5
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
        with:
          args: >
            -Dsonar.projectKey=${{ vars.SONAR_PROJECT_KEY }}


      # Configure your SonarQube server/quality-gate integration as required.
      # Ensure the workflow waits for the quality gate and fails on rejection.
```

Action versions above are illustrative. For production, review the vendor documentation and pin third-party actions to full commit SHAs according to your organization's policy. SonarQube server configuration varies by deployment; do not assume the scan step alone enforces a quality gate.
Security best practices
Use least-privilege permissions at workflow/job scope.
Pin third-party actions to reviewed full commit SHAs.
Treat pull-request code as untrusted; avoid exposing secrets to forked PR workflows.
Configure Trivy severity thresholds and fail behavior to match your risk policy.
Configure SonarQube quality-gate waiting/enforcement explicitly.
Store credentials in GitHub Secrets or use OIDC for short-lived cloud credentials.
Review and remediate findings before deployment; do not simply suppress scan failures.
Exit codes
0 — no finding at or above the configured threshold, or no workflow files found.
1 — at least one finding at or above the configured threshold.
2 — supplied path does not exist.
License
Add the license required by your institution or project owner before public redistribution.
