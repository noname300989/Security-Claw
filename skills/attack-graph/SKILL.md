---
name: attack-graph
description: |
  Hybrid enterprise attack graph construction and analysis skill. Builds a unified knowledge
  graph connecting findings from Web, API, Cloud, Active Directory, Network, and AI attack
  surfaces. Identifies multi-hop attack chains, prioritizes by CVSS + blast radius, and
  generates executive-level and technical reports. Supports MITRE ATT&CK Navigator export,
  SARIF output for CI/CD integration, and BloodHound-compatible Cypher queries.
metadata:
  {
    "openclaw":
      {
        "emoji": "🕸️",
        "requires": { "bins": ["python3"] },
        "install":
          [
            {
              "id": "pip-networkx",
              "kind": "shell",
              "cmd": "pip3 install networkx matplotlib",
              "bins": [],
              "label": "Install networkx graph library (pip)"
            }
          ],
      },
  }
---

# Hybrid Enterprise Attack Graph Skill

Intelligently correlates findings across all domains to construct multi-hop attack chains
and prioritize remediation by business impact.

## Capabilities

### 1. Finding Correlation & Attack Path Synthesis
Connect findings across Web, API, Cloud, AD, Network, and AI domains into unified attack paths.

**Usage:**
> Analyze all discovered findings and construct the highest-risk attack chains

**Example Chain:**
```
[Web] SSRF in /api/fetch
    → [Cloud] Metadata endpoint access → IAM credentials
    → [Cloud] S3 data exfiltration
    → [AD] Lateral movement via stolen service account
    → [AD] Kerberoasting → Domain Admin
```

**Output:** Prioritized attack graph with blast radius estimation.

---

### 2. MITRE ATT&CK Mapping
Automatically map all findings to ATT&CK Tactics, Techniques, and Sub-techniques.

**Usage:**
> Map all current findings to MITRE ATT&CK and generate a Navigator layer

**Output Formats:**
- ATT&CK Navigator JSON layer
- Markdown report by tactic
- CSV for ingestion into SIEM/SOAR

---

### 3. Risk Prioritization Engine
Score and prioritize findings by CVSS base score, exploitability, and business blast radius.

**Usage:**
> Prioritize the discovered vulnerabilities by risk to the business

**Scoring Factors:**
- CVSS v3.1 base score
- Exploitability (proof-of-concept available?)
- Blast radius (how many systems affected?)
- Data sensitivity (PII, credentials, IP)
- Position in kill chain (initial access vs. persistence)

---

### 4. Cross-Domain Attack Chain Analysis
Identify attack paths that cross security domains (e.g., Web → Cloud → AD).

**Usage:**
> Find attack paths from external web access to complete domain compromise

**Analysis Types:**
- Shortest path to Domain Admin
- Highest-impact path (by data sensitivity)
- Most stealthy path (lowest alert score)

---

### 5. Executive Report Generation
Generate structured, professional penetration test reports.

**Usage:**
> Generate a penetration test report for the assessment of target.com

**Report Sections:**
1. Executive Summary
2. Scope & Methodology
3. Risk Summary (by severity)
4. Detailed Findings (with CVSS, evidence, remediation)
5. Attack Graph visualization
6. MITRE ATT&CK heatmap
7. Remediation Roadmap

**Output Formats:** Markdown, HTML, JSON (SARIF)

---

### 6. Remediation Roadmap Generation
Produce actionable, prioritized remediation recommendations with implementation guidance.

**Usage:**
> Generate a prioritized remediation roadmap for all discovered findings

**Grouping Strategy:**
- Quick wins (< 1 day, high risk reduction)
- Short-term (1 week, architectural fixes)
- Long-term (strategic security improvements)

---

### 7. CI/CD Security Gate Integration
Export findings in SARIF format for GitHub Advanced Security / GitLab Security Dashboard integration.

**Usage:**
> Export findings in SARIF format for CI/CD pipeline integration

**Supported Outputs:**
- SARIF v2.1.0 (GitHub, Azure DevOps)
- JUnit XML (Jenkins, CircleCI)
- SonarQube generic issue format

---

## Example Attack Graphs

```
EXTERNAL ATTACKER
       │
       ▼
[Web] XSS → Session Hijack → Auth Bypass
       │
       ▼
[API] BOLA → Sensitive Data Access
       │
       ▼
[Cloud] Keys in API Response → S3 Bucket Access
       │
       ▼
[AD] Service Account Credentials → Kerberoasting
       │
       ▼
DOMAIN ADMIN COMPROMISE
```

```
[AI] Prompt Injection → LLM Tool Abuse
       │
       ▼
[MCP] Tool Poisoning → File System Access
       │
       ▼
[Network] Internal Service Discovery
       │
       ▼
[AD] Pass-the-Hash → Lateral Movement
```
