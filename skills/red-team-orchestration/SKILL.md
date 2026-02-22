---
name: red-team-orchestration
description: |
  Master Red Team Orchestration skill that coordinates all offensive domains into coherent
  multi-phase penetration test campaigns. Manages engagement scope, orchestrates attack phase
  sequencing (Recon → Initial Access → Privilege Escalation → Lateral Movement → Impact),
  enforces operational security (OPSEC) controls, tracks discovered artifacts, and synthesizes
  cross-domain findings into unified attack chains. This is the top-level skill invoked by the
  Red Team Agent to coordinate all other offensive skills.
metadata:
  {
    "openclaw":
      {
        "emoji": "🎯",
        "requires": { "bins": ["python3"] },
        "install": [],
      },
  }
---

# Red Team Orchestration Core

The master orchestration skill responsible for coordinating full-scope red team engagements.

## Engagement Phases

```
Phase 0: Scoping & Rules of Engagement
Phase 1: Reconnaissance & Surface Discovery
Phase 2: Initial Access (Web/API/Network)
Phase 3: Exploitation & Post-Exploitation
Phase 4: Privilege Escalation (Cloud/AD)
Phase 5: Lateral Movement
Phase 6: Persistence
Phase 7: Data Exfiltration (simulated)
Phase 8: Reporting & Debrief
```

## Capabilities

### 1. Engagement Kickoff & Scoping
Define target scope, rules of engagement, and engagement parameters before any active testing.

**Usage:**
> Start a new red team engagement for target.com with scope: *.target.com, 192.168.1.0/24

**Scope Validation:**
- Confirm all IPs/domains are in scope before testing
- Enforce OOB (out-of-band) scope checking
- Log all scope decisions for audit trail

---

### 2. Attack Phase Orchestration
Coordinate skill execution across the full kill chain in a logical, realistic sequence.

**Usage:**
> Run a full red team assessment against the defined engagement scope

**Default Sequence:**
1. `web-api-offensive` → Surface discovery, auth bypass, IDOR, SSRF
2. `network-offensive` → Port scanning, service exploitation, MITM
3. `ai-offensive` → LLM/API prompt injection, MCP testing
4. `cloud-offensive` → IAM escalation, bucket exposure, container escape
5. `ad-offensive` → Kerberoasting, BloodHound, DCSync
6. `attack-graph` → Correlation, chain building, report generation

---

### 3. OPSEC Control Enforcement
Apply operational security controls to minimize detection during the engagement.

**OPSEC Checklist:**
- [ ] Rotate User-Agent strings and source IPs
- [ ] Use jittered timing between requests
- [ ] Avoid triggering known IDS/WAF signatures
- [ ] Use legitimate-looking command patterns
- [ ] Limit noisy tools to after-hours windows
- [ ] Sanitize all tool outputs before logging

---

### 4. Artifact & Evidence Management
Track all discovered credentials, hashes, tokens, and artifacts during the engagement.

**Usage:**
> Show all credentials and access tokens discovered in this engagement

**Tracked Artifacts:**
- Credentials (username:password pairs)
- NTLM hashes
- API keys and tokens
- SSH private keys
- JWT tokens
- Cloud IAM credentials

---

### 5. Engagement Progress Tracking
Real-time tracking of which attack phases have been completed and what remains.

**Usage:**
> Show current engagement status and what phases are complete

**Output:** Phase completion matrix with findings count per phase.

---

### 6. Finding Deduplication & Severity Normalization
Normalize findings from all skills to a consistent severity framework (Critical/High/Medium/Low/Info).

**Severity Mapping:**
- **Critical**: RCE, Auth bypass to admin, DCSync, Domain Admin
- **High**: SQLi, SSRF, Kerberoasting success, S3 data exposure
- **Medium**: IDOR, information disclosure, rate limit bypass
- **Low**: Verbose errors, missing security headers
- **Info**: Reconnaissance findings, open ports

---

### 7. Engagement Closure & Cleanup
Guide the systematic cleanup of any artifacts, backdoors, or temporary access created during testing.

**Usage:**
> Generate cleanup checklist for the completed engagement

**Cleanup Items:**
- Remove created user accounts
- Delete uploaded shells/backdoors
- Close tunnel connections
- Revoke temporary credentials
- Archive engagement artifacts securely

---

## OWASP Coverage Matrix

| Skill | OWASP Standards Covered |
|---|---|
| `web-api-offensive` | Web Top 10, API Top 10, WSTG v4.2 |
| `ai-offensive` | LLM Top 10, Agentic AI Top 10, MCP Top 10 |
| `cloud-offensive` | Cloud Top 10, MITRE ATT&CK Cloud |
| `ad-offensive` | MITRE ATT&CK Enterprise (Credential Access, Lateral Movement) |
| `network-offensive` | NIST SP 800-115, MITRE ATT&CK Network |
| `attack-graph` | Full ATT&CK coverage, CVSS v3.1, SARIF |

---

## Scope Enforcement Policy

> ⚠️ **CRITICAL**: Always verify all targets are in scope before any active testing.
> Only perform testing on systems you have explicit written authorization to test.
> Unauthorized testing is illegal and unethical.

The orchestrator will:
1. Refuse to test out-of-scope targets
2. Confirm scope at engagement start
3. Log every action with timestamps
4. Alert if targets outside scope are detected
