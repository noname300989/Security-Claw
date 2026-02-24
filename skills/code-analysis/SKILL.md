---
name: code-analysis
description: |
  Static and dynamic code analysis (SAST/DAST) for identifying security vulnerabilities in
  application source code and running systems. Supports Python, JavaScript, Java, Go, PHP,
  Ruby, and TypeScript. Performs taint analysis, secret detection, dependency CVE scanning,
  insecure function detection, hardcoded credential identification, and unsafe deserialization
  pattern detection. Integrates Semgrep for SAST, Bandit for Python, ESLint security rules
  for JavaScript, TruffleHog/Gitleaks for secrets, and OWASP Dependency-Check for SCA.
metadata:
  {
    "openclaw":
      {
        "emoji": "🧬",
        "requires": { "bins": ["python3", "semgrep"] },
        "install":
          [
            {
              "id": "pip-sast",
              "kind": "shell",
              "cmd": "pip3 install semgrep bandit safety",
              "bins": ["semgrep", "bandit"],
              "label": "Install SAST tools (semgrep, bandit, safety)",
            },
            {
              "id": "brew-secrets",
              "kind": "shell",
              "cmd": "brew install trufflehog gitleaks",
              "bins": ["trufflehog", "gitleaks"],
              "label": "Install secret scanners (brew)",
            },
          ],
      },
  }
---

# Code Analysis — Static & Dynamic Security Analysis

Automated SAST/DAST/SCA to find vulnerabilities directly in source code and running applications.

## Analysis Types

| Type              | Tool                    | Coverage                             |
| ----------------- | ----------------------- | ------------------------------------ |
| **SAST**          | Semgrep                 | Multi-language taint analysis        |
| **SAST (Python)** | Bandit                  | Python-specific security issues      |
| **Secrets**       | TruffleHog, Gitleaks    | Keys, tokens, passwords in code      |
| **SCA**           | Safety, OWASP Dep-Check | Vulnerable dependencies              |
| **DAST**          | nuclei, ZAP             | Running application vulnerabilities  |
| **IaC Scanning**  | Semgrep, checkov        | Terraform, CloudFormation misconfigs |

---

## Capabilities

### 1. Multi-Language SAST (Semgrep)

Scan source code for security vulnerabilities across all major languages.

**Usage:**

> Scan the /src directory for OWASP Top 10 vulnerabilities

```bash
# Full OWASP Top 10 scan
semgrep --config=p/owasp-top-ten ./src

# Language-specific security packs
semgrep --config=p/python-security ./src         # Python
semgrep --config=p/javascript ./src              # JS/Node.js
semgrep --config=p/java ./src                    # Java/Spring
semgrep --config=p/golang-security ./src         # Go
semgrep --config=p/php ./src                     # PHP

# JWT / auth patterns
semgrep --config=p/jwt ./src

# API security
semgrep --config=p/flask-secure-defaults ./src
semgrep --config=p/django-security ./src

# Output as SARIF for CI/CD
semgrep --config=p/owasp-top-ten ./src --sarif > sast_results.sarif

# Show only HIGH severity
semgrep --config=p/owasp-top-ten ./src --severity=ERROR
```

---

### 2. Python Security Analysis (Bandit)

Deep Python-specific static analysis for insecure patterns.

**Usage:**

> Analyze Python codebase at ./app for security issues

```bash
# Full scan with HTML report
bandit -r ./app -f html -o bandit_report.html

# High-severity only
bandit -r ./app --severity-level high

# Specific test IDs
bandit -r ./app -t B101,B102,B105,B106,B107  # hardcoded passwords
bandit -r ./app -t B201,B301,B302            # deserialization

# JSON output for integration
bandit -r ./app -f json -o bandit.json

# CWE mapping
bandit -r ./app --format json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for r in data['results']:
    print(f\"[{r['issue_severity']}] {r['issue_text']}\")
    print(f\"  File: {r['filename']}:{r['line_number']}\")
    print(f\"  CWE:  {r.get('issue_cwe',{}).get('id','?')}\")
"
```

**Common findings:** SQL injection, shell injection, unsafe YAML load, hardcoded passwords, weak crypto.

---

### 3. Secret & Credential Detection

Find accidentally committed secrets, API keys, tokens, and passwords.

**Usage:**

> Scan the target GitHub repository for leaked credentials and API keys

```bash
# TruffleHog — full git history scan (highest accuracy)
trufflehog git file://./repo --only-verified

# TruffleHog — live GitHub org scan
trufflehog github --org=target-org --only-verified --json > secrets.json

# Gitleaks — fast pattern-based scan
gitleaks detect --source ./repo --report-format json --report-path leaks.json
gitleaks detect --source ./repo --verbose  # show context

# Detect in environment files
grep -rni "api_key\|secret\|password\|token\|private_key" \
  --include="*.env" --include="*.json" --include="*.yaml" ./
```

---

### 4. Dependency / SCA Scanning

Identify known CVEs in project dependencies.

**Usage:**

> Scan Python and Node.js dependencies for known CVEs

```bash
# Python — Safety
safety check -r requirements.txt --json

# Python — pip-audit (more comprehensive)
pip3 install pip-audit
pip-audit -r requirements.txt -f json -o pip_audit.json

# Node.js — npm audit
npm audit --json > npm_audit.json

# OWASP Dependency-Check (Java/multi-language)
dependency-check --project "Target App" \
  --scan ./lib --format JSON --out dep_check_report

# Trivy (container + OS packages)
brew install trivy
trivy fs ./  # filesystem scan
trivy image target:latest  # Docker image
```

---

### 5. IaC Security Scanning

Find misconfigurations in Terraform, CloudFormation, Kubernetes, and Dockerfiles.

**Usage:**

> Scan the Terraform configurations for cloud security misconfigurations

```bash
# Checkov — multi-framework IaC scanner
pip3 install checkov
checkov -d ./terraform --framework terraform --check CKV_AWS_* --compact
checkov -d ./k8s --framework kubernetes --compact

# Semgrep IaC rules
semgrep --config=p/terraform-security ./terraform
semgrep --config=p/dockerfile-security .

# Terrascan
pip3 install terrascan
terrascan scan -i terraform -d ./terraform
```

---

### 6. Dynamic Application Security Testing (DAST)

Test a running application for vulnerabilities.

**Usage:**

> Run DAST against the running application at https://target.com

```bash
# Nuclei (template-based DAST)
nuclei -u https://target.com \
  -severity critical,high \
  -t cves/ -t exposures/ -t misconfiguration/ \
  -o dast_findings.txt

# OWASP ZAP (interactive proxy + scanner)
docker run -t owasp/zap2docker-stable \
  zap-baseline.py -t https://target.com -r zap_report.html

# ZAP API scan (for REST APIs)
docker run -t owasp/zap2docker-stable \
  zap-api-scan.py -t https://target.com/swagger.json -f openapi
```

---

### 7. Custom Semgrep Rules

Write targeted rules for application-specific patterns.

**Usage:**

> Create a custom Semgrep rule to detect unsafe database queries in the codebase

```yaml
# custom_rules/unsafe_db.yaml
rules:
  - id: unsafe-string-format-sql
    patterns:
      - pattern: |
          db.execute("..." % ...)
      - pattern: |
          db.execute(f"...{...}...")
    message: "Potential SQL injection via string formatting. Use parameterized queries."
    languages: [python]
    severity: ERROR
    metadata:
      owasp: "A03:2021 Injection"
      cwe: "CWE-89"
```

```bash
semgrep --config=custom_rules/unsafe_db.yaml ./src
```

---

## Usage from Red Team Agent

```
Scan the /src directory for OWASP Top 10 vulnerabilities using Semgrep
Run Bandit on the Python application code and report high-severity findings
Search the target GitHub repo for leaked API keys and credentials
Check Python requirements.txt for dependencies with known CVEs
Scan the Dockerfile and Kubernetes configs for security misconfigurations
Run a full DAST scan against https://target.com
```
