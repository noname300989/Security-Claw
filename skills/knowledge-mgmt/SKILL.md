---
name: knowledge-mgmt
description: |
  Structured findings database and attack documentation system. Manages the entire engagement
  knowledge lifecycle: create findings with OWASP/ATT&CK mappings, search existing documentation,
  generate executive and technical reports, build attack chain timelines, export to SARIF/JSON/Markdown,
  and maintain a searchable vulnerability knowledge base that persists across engagement phases.
  Integrates with attack-graph for cross-domain finding correlation and risk prioritization.
metadata:
  {
    "openclaw":
      {
        "emoji": "📚",
        "requires": { "bins": ["python3"] },
        "install":
          [
            {
              "id": "pip-km-deps",
              "kind": "shell",
              "cmd": "pip3 install rich pyyaml jinja2",
              "bins": [],
              "label": "Install knowledge management dependencies (pip)",
            },
          ],
      },
  }
---

# Knowledge Management — Findings Database & Attack Documentation

Structured engagement documentation from raw findings through final deliverable reports.

## Data Model

```
Engagement
├── metadata (target, scope, dates, assessors)
├── findings[]
│   ├── id, title, severity (Critical/High/Medium/Low/Info)
│   ├── owasp_id, cwe_id, cvss_score, mitre_technique
│   ├── description, evidence, affected_assets
│   ├── remediation (short + long term)
│   ├── business_impact
│   └── status (open / accepted_risk / remediated / in_progress)
├── attack_chains[]
│   └── findings[] → ordered attack path
└── reports[]
    ├── executive_summary.md
    └── technical_report.md
```

## Capabilities

### 1. Create & Save a Finding

Document a confirmed vulnerability with full context.

**Usage:**

> Create a new Critical finding for the SQL injection found in the id parameter at /api/items

**Finding Template (YAML):**

```yaml
# findings/CLAW-2026-001-sqli.yaml
id: CLAW-2026-001
title: "SQL Injection in /api/items?id Parameter"
severity: CRITICAL
status: open

target:
  url: "https://target.com/api/items"
  parameter: "id"
  affected_versions: "All"

vulnerability:
  type: "SQL Injection (Error-Based)"
  owasp: "A03:2021 Injection"
  cwe: "CWE-89"
  cvss_score: 9.8
  cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  mitre_technique: "T1190"

description: |
  The `id` parameter in the `/api/items` endpoint is vulnerable to SQL injection.
  The application directly concatenates user input into a SQL query without sanitization.

evidence: |
  Payload:    1' AND 1=1--
  Response:   200 OK — Full item list returned
  Payload:    1' AND 1=2--
  Response:   200 OK — Empty list (boolean-based blind confirmed)
  Payload:    1' ORDER BY 10--
  Response:   500 — "Column index out of range" (column count enumerated: 9)

proof_of_concept: |
  curl "https://target.com/api/items?id=1' ORDER BY 1--"
  sqlmap -u "https://target.com/api/items?id=1" --dbs --batch

business_impact: |
  An attacker can extract the entire database including user credentials, PII,
  payment data, and proprietary business data. Full database compromise is trivial.

remediation:
  short_term: "Disable the vulnerable endpoint or add WAF rule immediately"
  long_term: |
    1. Replace string concatenation with parameterized queries / prepared statements
    2. Implement input validation — reject non-numeric values for numeric parameters
    3. Apply least-privilege database account (read-only where possible)
    4. Enable query logging and anomaly detection
  references:
    - "https://owasp.org/www-community/attacks/SQL_Injection"
    - "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
```

---

### 2. Query Findings Database

Search, filter, and retrieve findings across the engagement.

**Usage:**

> Show all Critical and High findings discovered so far

```bash
# List all findings by severity
python3 skills/knowledge-mgmt/km.py list --severity CRITICAL,HIGH

# Search by keyword
python3 skills/knowledge-mgmt/km.py search "SQL injection"

# Filter by OWASP category
python3 skills/knowledge-mgmt/km.py filter --owasp "A03:2021"

# Filter by status
python3 skills/knowledge-mgmt/km.py list --status open

# Get a specific finding
python3 skills/knowledge-mgmt/km.py get CLAW-2026-001
```

---

### 3. Generate Executive Report

Produce a professional executive summary for non-technical stakeholders.

**Usage:**

> Generate an executive summary report for all findings discovered in this engagement

**Executive Report Structure:**

```markdown
# Penetration Test Executive Summary

**Engagement:** Target Corp — External + Internal Assessment
**Period:** 2026-02-10 to 2026-02-21
**Assessor:** OpenClaw Red Team

## Risk Snapshot

| Severity    | Count |
| ----------- | ----- |
| 🔴 Critical | 3     |
| 🟠 High     | 7     |
| 🟡 Medium   | 12    |
| 🟢 Low      | 8     |

## Top 3 Critical Risks

1. SQL Injection (CVSS 9.8) — Database fully compromised
2. SSRF to AWS Metadata (CVSS 9.1) — Cloud credentials exposed
3. Domain Admin via Kerberoasting (CVSS 8.8) — Full AD compromise

## Business Impact Summary

[Plain-language impact statement for each critical finding]

## Remediation Priority

[Executive roadmap with effort/impact matrix]
```

```bash
python3 skills/knowledge-mgmt/km.py report --type executive --output executive_summary.md
```

---

### 4. Generate Technical Report

Produce a detailed technical report for the engineering/security team.

**Usage:**

> Generate a full technical penetration test report including all findings with PoC evidence

**Technical Report Structure:**

```markdown
# Technical Penetration Test Report

## 1. Scope & Methodology

## 2. Attack Narrative — Attack Chain Timeline

## 3. Findings (sorted by severity)

### CLAW-2026-001 — SQL Injection [CRITICAL]

- Description, Evidence, PoC, Remediation

## 4. OWASP Coverage Matrix

## 5. MITRE ATT&CK Coverage Map

## 6. Remediation Roadmap

## 7. Appendices (raw tool output, screenshots)
```

```bash
python3 skills/knowledge-mgmt/km.py report --type technical --output technical_report.md
```

---

### 5. Attack Chain Documentation

Document multi-step attack chains showing how individual findings chain together.

**Usage:**

> Document the attack chain from initial SSRF to domain admin

**Attack Chain YAML:**

```yaml
# attack_chains/full_compromise.yaml
id: CHAIN-001
title: "SSRF → IMDS → Cloud Credentials → Domain Admin"
risk: CRITICAL
steps:
  - order: 1
    finding: CLAW-2026-003
    action: "Exploit SSRF in /fetch endpoint"
    technique: T1190
    outcome: "Access to AWS Instance Metadata Service"

  - order: 2
    finding: CLAW-2026-006
    action: "Retrieve IAM credentials from EC2 metadata"
    technique: T1552.005
    outcome: "AWS IAM credentials for prod-deployer role"

  - order: 3
    finding: CLAW-2026-009
    action: "Use AWS creds to read Secrets Manager for AD credentials"
    technique: T1555.006
    outcome: "Active Directory service account credentials"

  - order: 4
    finding: CLAW-2026-012
    action: "Kerberoast high-privilege SPN with obtained creds"
    technique: T1558.003
    outcome: "Domain Admin hash cracked offline"

  - order: 5
    finding: null
    action: "DCSync to dump all Domain Controller hashes"
    technique: T1003.006
    outcome: "Full domain compromise"
```

---

### 6. SARIF Export (CI/CD Integration)

```bash
# Export findings as SARIF for GitHub/GitLab security dashboard
python3 skills/knowledge-mgmt/km.py export --format sarif --output results.sarif

# Upload to GitHub
gh api repos/{owner}/{repo}/code-scanning/sarifs \
  -f commit_sha=$(git rev-parse HEAD) \
  -f ref=refs/heads/main \
  -f sarif=$(cat results.sarif | gzip | base64)
```

---

### 7. Remediation Tracker

```bash
# Update finding status
python3 skills/knowledge-mgmt/km.py update CLAW-2026-001 --status remediated

# Generate remediation progress dashboard
python3 skills/knowledge-mgmt/km.py dashboard

# Export remediation roadmap
python3 skills/knowledge-mgmt/km.py roadmap --output remediation_plan.md
```

---

## Usage from Red Team Agent

```
Create a new Critical finding for the SQL injection at https://target.com/api/items?id=1
Show me all Critical and High findings discovered so far
Generate the executive summary report
Generate the full technical penetration test report with all findings
Document the attack chain from SSRF to domain admin
Export all findings as SARIF for GitHub security dashboard
Update finding CLAW-2026-001 status to remediated
```
