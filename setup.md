# OpenClaw Offensive OS — Setup Guide

> ⚠️ **Legal Warning**: This platform contains offensive security tools. Only use on systems you have **explicit written authorization** to test. Unauthorized testing is illegal.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Quick Setup](#2-quick-setup)
3. [Manual Installation](#3-manual-installation)
   - [Phase 1 — Web & API Tools](#phase-1--web--api-tools)
   - [Phase 2 — Cloud Offensive Tools](#phase-2--cloud-offensive-tools)
   - [Phase 3 — Active Directory Tools](#phase-3--active-directory-tools)
   - [Phase 4 — Network Tools](#phase-4--network-tools)
4. [Configure the Red Team Agent](#4-configure-the-red-team-agent)
5. [Activate & Use](#5-activate--use)
6. [Phase Reference](#6-phase-reference)
7. [OWASP Coverage Matrix](#7-owasp-coverage-matrix)
8. [Troubleshooting](#8-troubleshooting)

---

## 1. Prerequisites

| Requirement | Version | Install |
|---|---|---|
| **Node.js** | >= 22.12.0 | `brew upgrade node` or `nvm install 22` |
| **pnpm** | >= 9.0 | `npm install -g pnpm` |
| **Homebrew** | Latest | [brew.sh](https://brew.sh) |
| **Python 3** | >= 3.10 | `brew install python3` |
| **Git** | Any | `brew install git` |

### Verify Prerequisites

```bash
node -v       # Must be >= v22.12.0
pnpm -v       # Any recent version
python3 --version  # >= 3.10
brew --version
```

---

## 2. Quick Setup

Run the all-in-one setup script:

```bash
# Make executable
chmod +x setup-offensive-os.sh

# Run the setup
./setup-offensive-os.sh
```

This will:
- ✅ Verify Node.js version
- ✅ Install all Phase 1–4 tools via Homebrew/pip
- ✅ Run `pnpm install` and `pnpm build`
- ✅ Generate `openclaw.json.template` with the Red Team Agent config

---

## 3. Manual Installation

### Phase 1 — Web & API Tools

```bash
# Core scanners
brew install nuclei sqlmap ffuf semgrep

# Subdomain & HTTP discovery
brew install amass subfinder httpx feroxbuster

# JWT testing
pip3 install jwt_tool

# Verify
nuclei -version
sqlmap --version
ffuf -V
jwt_tool -h
```

**Tools installed:**

| Tool | Purpose | OWASP Coverage |
|---|---|---|
| `nuclei` | Template-based vulnerability scanner | WSTG, API Security |
| `sqlmap` | SQL injection detection & exploitation | A03 Injection |
| `ffuf` | Web fuzzer (dirs, params, auth bypass) | A07 Auth Failures |
| `semgrep` | SAST for business logic flaws | A04 Insecure Design |
| `amass` | Subdomain enumeration | WSTG-INFO |
| `subfinder` | Fast subdomain discovery | WSTG-INFO |
| `httpx` | HTTP probing & fingerprinting | WSTG-INFO |
| `jwt_tool` | JWT security testing | A02 Crypto Failures |

---

### Phase 2 — Cloud Offensive Tools

```bash
# AWS CLI
brew install awscli

# Secret scanning
brew install trufflehog

# Cloud security assessment (pip)
pip3 install scoutsuite pacu

# Verify
aws --version
trufflehog --version
scout --help
```

**Tools installed:**

| Tool | Purpose | Cloud |
|---|---|---|
| `aws cli` | AWS enumeration & testing | AWS |
| `trufflehog` | Credential/secret leak scanning | All |
| `scout` (ScoutSuite) | Multi-cloud security audit | AWS/Azure/GCP |
| `pacu` | AWS exploitation framework | AWS |

---

### Phase 3 — Active Directory Tools

```bash
# Impacket suite (Kerberoasting, DCSync, etc.)
pip3 install impacket

# CrackMapExec (SMB, LDAP, WinRM)
brew install crackmapexec
# OR
pip3 install crackmapexec

# BloodHound Python ingestion
pip3 install bloodhound

# Kerbrute — download binary from GitHub releases
KERBRUTE_URL="https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_darwin_amd64"
curl -L "$KERBRUTE_URL" -o /usr/local/bin/kerbrute && chmod +x /usr/local/bin/kerbrute

# Verify
python3 -c "import impacket; print('impacket OK')"
crackmapexec --version
kerbrute --help
```

**Tools installed:**

| Tool | Purpose | ATT&CK Technique |
|---|---|---|
| `impacket` | Kerberoasting, DCSync, PtH, PtT | T1558, T1003, T1550 |
| `crackmapexec` | SMB/LDAP recon & lateral movement | T1021, T1046 |
| `bloodhound-python` | AD attack path ingestion | T1069, T1087 |
| `kerbrute` | Kerberos user enumeration | T1110 |

---

### Phase 4 — Network Tools

```bash
# Core network tools
brew install nmap masscan bettercap hydra

# DNS tools
brew install dnsx

# Verify
nmap --version
masscan --version
bettercap --version
```

**Tools installed:**

| Tool | Purpose | ATT&CK Technique |
|---|---|---|
| `nmap` | Port scanning, service fingerprinting, vuln scripts | T1046 |
| `masscan` | Ultra-fast port scanning (internet-scale) | T1046 |
| `bettercap` | MITM, ARP poisoning, traffic capture | T1557 |
| `hydra` | Credential brute-forcing | T1110 |

---

## 4. Configure the Red Team Agent

### Step 1 — Create OpenClaw Config Directory

```bash
mkdir -p ~/.openclaw
```

### Step 2 — Copy Agent Configuration

```bash
cp openclaw.json.template ~/.openclaw/openclaw.json
```

Or manually add this to your existing `~/.openclaw/openclaw.json`:

```json
{
  "agents": {
    "list": [
      {
        "id": "red-team",
        "name": "Red Team Agent",
        "emoji": "😈",
        "skills": [
          "red-team-orchestration",
          "web-api-offensive",
          "ai-offensive",
          "cloud-offensive",
          "ad-offensive",
          "network-offensive",
          "attack-graph"
        ],
        "identity": {
          "name": "Red Team",
          "emoji": "😈"
        }
      }
    ]
  }
}
```

### Step 3 — Configure API Keys

```bash
cp .env.example .env
```

Edit `.env` and set your LLM API key:

```bash
# For Anthropic Claude
ANTHROPIC_API_KEY=your_key_here

# For OpenAI GPT-4o
OPENAI_API_KEY=your_key_here

# For Google Gemini
GEMINI_API_KEY=your_key_here
```

---

## 5. Activate & Use

### Start the Red Team Agent

```bash
pnpm openclaw agent --activation red-team
```

### Example Prompts

**Phase 1 — Web Application Testing:**
```
Discover the attack surface for example.com and run full web vulnerability assessment
Test https://target.com/api/v1 for OWASP API Top 10 vulnerabilities
Check for SQL injection on https://target.com/search?q=test
Test JWT token: eyJhbGci... for manipulation vulnerabilities
```

**Phase 2 — Cloud Assessment:**
```
Scan AWS account for IAM privilege escalation paths using key AKIA...
Check for misconfigured S3 buckets for company: target-corp
Scan GitHub repos of target-org for leaked credentials
```

**Phase 3 — Active Directory:**
```
Enumerate Active Directory at DC: 192.168.1.10, Domain: corp.local
Perform Kerberoasting against corp.local using credentials user:password@dc.corp.local
Run BloodHound analysis and find path to Domain Admin
```

**Phase 4 — Network:**
```
Full network discovery and vulnerability scan of 192.168.1.0/24
Test SMB service at 192.168.1.10 for EternalBlue and credential attacks
Set up MITM attack on internal network segment 10.0.0.0/24
```

**Phase 5 — Attack Graph & Reporting:**
```
Correlate all findings and build the highest-risk attack chain
Generate executive penetration test report for the assessment
Map all findings to MITRE ATT&CK and generate Navigator layer
Create prioritized remediation roadmap
```

**Full Campaign:**
```
Start a full red team assessment for target.com with scope: *.target.com, 192.168.1.0/24
```

---

## 6. Phase Reference

### Platform Architecture

```
OpenClaw Offensive OS
├── skills/
│   ├── red-team-orchestration/  ← Master coordinator
│   ├── web-api-offensive/       ← Phase 1: Web & API
│   ├── ai-offensive/            ← Phase 1: AI/LLM/MCP
│   ├── cloud-offensive/         ← Phase 2: Cloud
│   ├── ad-offensive/            ← Phase 3: Active Directory
│   ├── network-offensive/       ← Phase 4: Network
│   └── attack-graph/            ← Phase 5: Correlation & Reporting
├── setup-offensive-os.sh        ← This setup script
├── openclaw.json.template       ← Agent configuration template
└── setup.md                     ← This guide
```

### Phase Summary

| Phase | Skills | OWASP / Framework | Key Tools |
|---|---|---|---|
| **1 — Web & API** | `web-api-offensive`, `ai-offensive` | OWASP Web Top 10, API Top 10, LLM Top 10, WSTG | Nuclei, SQLMap, ffuf, jwt_tool |
| **2 — Cloud** | `cloud-offensive` | OWASP Cloud Top 10, MITRE ATT&CK Cloud | ScoutSuite, Pacu, TruffleHog |
| **3 — Active Directory** | `ad-offensive` | MITRE ATT&CK Enterprise | Impacket, BloodHound, CME |
| **4 — Network** | `network-offensive` | NIST SP 800-115, MITRE ATT&CK | nmap, masscan, Bettercap |
| **5 — Attack Graph** | `attack-graph` | ATT&CK, CVSS v3.1, SARIF | networkx, custom analysis |
| **Orchestration** | `red-team-orchestration` | Full kill chain | All above |

---

## 7. OWASP Coverage Matrix

| OWASP Standard | Coverage |
|---|---|
| OWASP Web Top 10 (2021 + 2025 draft) | ✅ A01–A10 all covered |
| OWASP API Security Top 10 (2023) | ✅ API1–API10 all covered |
| OWASP LLM Top 10 (2025) | ✅ LLM01–LLM10 all covered |
| OWASP Agentic AI Top 10 | ✅ Agent hijacking, excessive agency |
| OWASP MCP Top 10 | ✅ MC1–MC5 test cases |
| OWASP WSTG v4.2 | ✅ INFO, AUTH, ATHZ, INPV, BUSL, SESS |
| MITRE ATT&CK Enterprise | ✅ All tactics from Recon → Impact |
| MITRE ATT&CK Cloud | ✅ IaaS, SaaS, containers |
| NIST SP 800-115 | ✅ Network assessment methodology |
| CIS Benchmarks | ✅ Validation against CIS controls |

---

## Threat Intelligence Scraper

The `threat-intel` skill bundles a live web scraper at `skills/threat-intel/scraper.py`.

### Install Dependencies

```bash
pip3 install requests beautifulsoup4 feedparser lxml rich
```

### Sources Scraped

| Source | Data |
|---|---|
| NVD API v2 | Latest CVEs with CVSS scores |
| CISA KEV | Known Exploited Vulnerabilities catalog |
| Exploit-DB | Public exploit code search |
| Packet Storm | New exploit/advisory releases (RSS) |
| OWASP Blog | Top 10 updates, new projects |
| Nuclei Templates | Latest community template commits (GitHub) |
| GitHub Advisories | OSS Security Advisories (npm, PyPI, etc.) |
| AlienVault OTX | Threat indicators (IPs, domains, hashes) |
| GreyNoise | Active internet-scanning campaigns |

### Usage

```bash
# Full intelligence briefing (last 7 days)
python3 skills/threat-intel/scraper.py

# Last 24 hours only
python3 skills/threat-intel/scraper.py --days 1

# Include HIGH severity CVEs too
python3 skills/threat-intel/scraper.py --severity HIGH

# JSON output (for piping to jq or another tool)
python3 skills/threat-intel/scraper.py --output json | jq .cisa_kev_additions

# Search Exploit-DB for a specific product
python3 skills/threat-intel/scraper.py --search "apache struts"

# Look up a specific CVE
python3 skills/threat-intel/scraper.py --cve CVE-2024-1234
```

### Use from Red Team Agent

```
Get today's threat intelligence briefing
Check if CVE-2025-12345 is in the CISA Known Exploited catalog
Search for public exploits for Apache Log4j
Pull the latest Nuclei templates released this week
Get the latest OWASP project updates
```

---

## 8. Troubleshooting

### Setup Script Fails

```bash
# If pnpm install fails — clear cache and retry
pnpm store prune
pnpm install

# If build fails — check Node version
node -v  # Must be >= 22.12.0
nvm use 22  # If using nvm
```

### Tool Not Found After Install

```bash
# Refresh shell PATH
source ~/.zshrc  # or ~/.bashrc

# Check brew prefix
brew --prefix
export PATH="$(brew --prefix)/bin:$PATH"
```

### Agent Not Recognized

```bash
# Verify config file
cat ~/.openclaw/openclaw.json | python3 -m json.tool

# Check skills are in path
ls skills/web-api-offensive/SKILL.md
ls skills/red-team-orchestration/SKILL.md
```

### Permission Errors on macOS

Some tools (nmap, masscan) require elevated privileges for raw sockets:

```bash
sudo nmap -sS TARGET  # SYN scan requires root
sudo masscan TARGET CIDR --rate 1000
```

---

## 9. Tool Invocation & Execution

OpenClaw employs a sophisticated agent-tool loop to execute complex offensive security workflows. Understanding this mechanism is key to extending the platform or troubleshooting execution.

### Agent-Tool Loop
When an agent is activated, it enters a continuous loop:
1.  **Reasoning**: The LLM analyzes the prompt and current state.
2.  **Tool Selection**: The LLM decides which tool to invoke (e.g., `exec`, `read`).
3.  **Execution**: OpenClaw captures the tool request and executes it locally or in a sandbox.
4.  **Feedback**: Tool results (standard output, errors, file contents) are fed back to the LLM.

### The `exec` Tool
The `exec` tool is the workhorse of OpenClaw, enabling shell command execution.
- **Backgrounding**: Supports long-running tasks via `yieldMs` or `background: true`.
- **PTY Support**: Can run commands requiring a TTY (like `nmap` or interactive shells).
- **Sandboxing**: Can be configured to run within a Docker container for isolation.

### Gateway & Security
The OpenClaw Gateway acts as a mediator for all tool invocations:
- **Approvals**: Sensitive commands (especially elevated ones) require manual operator approval.
- **Safe Bins**: A list of pre-verified binaries that can be executed without explicit approval.
- **Security Policies**: Enforces rules like `workspaceOnly` to prevent agents from accessing files outside their designated workspace.

### Tool Resolution & Plugins
Tools are dynamically assembled for each agent session:
- **Core Tools**: Standard tools like `read`, `write`, `edit`, and `exec`.
- **Plugin Tools**: Custom tools provided by OpenClaw plugins (e.g., `browser`, `web-search`).
- **Channel Tools**: Platform-specific tools for integrations like Slack or Discord.

---

## Security Checklist Before Every Engagement

- [ ] Written authorization obtained from target owner
- [ ] Engagement scope clearly defined and documented
- [ ] Target IPs/domains verified against scope list
- [ ] Emergency stop procedure agreed with client
- [ ] API keys stored securely in `.env` (not committed to git)
- [ ] VPN/tunnel configured if testing from external location
- [ ] Reporting templates prepared

---

*Generated by OpenClaw Offensive OS — Red Team Agent*
