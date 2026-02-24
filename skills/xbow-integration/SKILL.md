---
name: xbow-integration
description: |
  Autonomous offensive security swarm — replicates XBOW capabilities using open-source tools.
  NO API KEY REQUIRED. Deploys parallel specialist agents (nuclei, sqlmap, dalfox, ffuf, httpx)
  to autonomously discover and confirm exploitable vulnerabilities (SQLi, XSS, IDOR, SSRF, CVEs).
  Only surfaces findings with confirmed PoC evidence (zero false positives).
  Produces OWASP-mapped Markdown reports with CVSS scores and remediation guidance.
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
              "label": "Install swarm dependencies (pip)",
            },
            {
              "id": "brew-nuclei",
              "kind": "shell",
              "cmd": "which nuclei || brew install nuclei",
              "bins": ["nuclei"],
              "label": "Install nuclei (CVE + OWASP scanner)",
            },
            {
              "id": "brew-httpx",
              "kind": "shell",
              "cmd": "which httpx || brew install httpx",
              "bins": ["httpx"],
              "label": "Install httpx (fingerprinting)",
            },
            {
              "id": "brew-ffuf",
              "kind": "shell",
              "cmd": "which ffuf || brew install ffuf",
              "bins": ["ffuf"],
              "label": "Install ffuf (endpoint discovery)",
            },
            {
              "id": "brew-sqlmap",
              "kind": "shell",
              "cmd": "which sqlmap || brew install sqlmap",
              "bins": ["sqlmap"],
              "label": "Install sqlmap (SQL injection)",
            },
            {
              "id": "brew-dalfox",
              "kind": "shell",
              "cmd": "which dalfox || brew install dalfox",
              "bins": ["dalfox"],
              "label": "Install dalfox (XSS confirmation)",
            },
          ],
      },
  }
---

# 🏹 XBOW-Equivalent Autonomous Pentesting Swarm

Orchestrates a **parallel multi-agent swarm** that replicates XBOW's core capabilities using entirely open-source tools.

> ✅ **No API key required.** Fully self-contained and free.

---

## How It Works (Mirrors XBOW Architecture)

| Phase                  | What Happens                             | Tools                                    |
| ---------------------- | ---------------------------------------- | ---------------------------------------- |
| **1. Surface Mapping** | Fingerprint + discover all endpoints     | `httpx`, `ffuf`                          |
| **2. Parallel Swarm**  | All agents attack simultaneously         | `nuclei`, `sqlmap`, `dalfox`, SSRF probe |
| **3. Exploit Confirm** | Filter to only confirmed PoCs (zero FPs) | Internal validator                       |
| **4. Report**          | OWASP-mapped Markdown report with CVSS   | Auto-generated                           |

---

## Capabilities

### 1. Launch Autonomous Swarm

```bash
# Basic scan
python3 skills/xbow-integration/scripts/xbow_client.py launch https://target.com

# Authenticated scan
python3 skills/xbow-integration/scripts/xbow_client.py launch https://target.com \
  --headers '{"Authorization": "Bearer token123"}' \
  --output report.md
```

### 2. Check Scan Status

```bash
python3 skills/xbow-integration/scripts/xbow_client.py status <scan_id>
```

Returns: phase, agents running, confirmed findings count, endpoints scanned.

### 3. Retrieve Confirmed Findings

```bash
python3 skills/xbow-integration/scripts/xbow_client.py findings <scan_id>
```

Returns structured JSON with OWASP mapping, CVSS, CWE, evidence, and remediation.

### 4. Generate Evidence Report

```bash
python3 skills/xbow-integration/scripts/xbow_client.py report <scan_id> --output pentest_report.md
```

---

## Agent Usage Examples

```
Launch an autonomous swarm scan against https://api.target.com and report confirmed findings.
Run XBOW-equivalent scan on https://staging.app.com with cookie auth and show any SQLi or SSRF.
Check status of scan abc123 and generate the final Markdown report.
```

---

## What Gets Scanned (Swarm Agents)

- **nuclei** — 9000+ CVE + OWASP templates (SQLi, XSS, SSRF, LFI, RCE, auth bypass, exposures)
- **sqlmap** — Autonomous SQL injection discovery and confirmation
- **dalfox** — XSS discovery and PoC confirmation
- **ssrf-probe** — Cloud metadata SSRF (AWS IMDS, GCP metadata)
- **ffuf** — Endpoint enumeration and discovery
- **httpx** — Tech fingerprinting and surface mapping

> All scans stored in `~/.openclaw/xbow-scans/` with full JSON state.
