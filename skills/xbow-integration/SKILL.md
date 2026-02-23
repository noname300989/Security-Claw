---
name: xbow-integration
description: |
  Integration with the XBOW autonomous offensive security platform. Deploys hundreds
  of specialized AI agents simultaneously to autonomously discover and confidently exploit
  application vulnerabilities (SQLi, XSS, IDOR, SSRF). Findings are only surfaced once
  exploitability is confirmed through controlled, non-destructive challenges (zero false
  positives). Provides CI/CD-ready API integration for continuous testing.
metadata:
  {
    "openclaw":
      {
        "emoji": "🏹",
        "requires": { "bins": ["python3"] },
        "install":
          [
            {
              "id": "pip-xbow-deps",
              "kind": "shell",
              "cmd": "pip3 install requests rich pyyaml",
              "bins": [],
              "label": "Install XBOW API dependencies (pip)",
            },
          ],
      },
  }
---

# XBOW Platform Integration

Unleash the **XBOW** autonomous testing swarm. XBOW uses creative AI reasoning to explore attack paths, map the application surface, and generate reproducible, verified exploits.

This skill allows the OpenClaw Red Team Agent to command the XBOW swarm programmatically, delegating complex web application and API testing to a specialized fleet of AI hackers.

> 🔑 **Requirement:** You must configure `XBOW_API_KEY` in your `.env` file to authenticate with the XBOW public API.

---

## Capabilities

### 1. Launch Autonomous Swarm

Trigger a comprehensive security assessment against a target URL or API endpoint.

**Usage:**

> Launch an XBOW scan against https://target.com with auth headers

```bash
# Launch a basic scan
python3 skills/xbow-integration/scripts/xbow_client.py launch https://target.com

# Launch with authentication state
python3 skills/xbow-integration/scripts/xbow_client.py launch https://target.com --headers '{"Authorization": "Bearer token123"}'
```

---

### 2. Monitor Assessment Status

Track the progress of the XBOW agents as they map the application and hunt for vulnerabilities.

**Usage:**

> Check the status of XBOW scan ID 12345

```bash
python3 skills/xbow-integration/scripts/xbow_client.py status 12345
```

_Returns phase progress (e.g., surface mapping, discovering, exploiting, finalized)._

---

### 3. Retrieve Verified Exploits

XBOW only returns vulnerabilities if it can successfully exploit them non-destructively.

**Usage:**

> Get confirmed vulnerabilities from scan ID 12345

```bash
python3 skills/xbow-integration/scripts/xbow_client.py findings 12345
```

_Outputs JSON containing OWASP mapping, CVSS scores, remediation advice, and the exact proof-of-concept exploit used by the AI._

---

### 4. Generate Evidence Report

Generate a standardized Markdown report containing all verified findings from the XBOW engagement.

**Usage:**

> Generate a Markdown report for scan ID 12345

```bash
python3 skills/xbow-integration/scripts/xbow_client.py report 12345 --output xbow_report.md
```

---

## Agent Usage Examples

The OpenClaw Red Team Agent can invoke the `xbow_scan` native tool without touching the CLI:

```
Launch an XBOW assessment against api.staging.target.com and monitor it until completion.
Run XBOW against target.com using this session cookie, then show me any confirmed IDORs.
Check the status of our running XBOW scan and generate the final report if it's done.
```
