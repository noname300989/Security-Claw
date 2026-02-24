---
name: distributed-workflows
description: |
  Distributed multi-agent orchestration engine for OpenClaw. Coordinates specialized sub-agents
  for parallel attack execution across all domains (Web, Cloud, AD, Network, AI). Agents
  automatically collaborate, share discoveries in a live findings bus, and hand off context
  between phases. The Red Team Agent uses this skill to spin up specialist agents, execute
  attack phases in parallel, and aggregate results — without any manual user intervention.
  All tools are auto-invoked through OpenClaw's execution engine.
metadata: { "openclaw": { "emoji": "🕸️", "requires": { "bins": ["python3"] }, "install": [] } }
---

# Distributed Workflows — Multi-Agent Attack Orchestration

The Red Team Agent orchestrates all work autonomously. You never need to run commands manually —
just describe what you want tested and the agent will execute, coordinate, and report everything.

> ✅ **OpenClaw auto-invokes all tools.** Ask the agent to do something; it handles everything.

---

## How Distributed Execution Works

```
User: "Run a full assessment on target.com"
       ↓
[Red Team Agent — Orchestrator]
       ↓ spawns parallel specialist agents
  ┌────────────────────────────────────────────┐
  │ Agent A: recon          (subfinder, amass) │
  │ Agent B: web-api        (nuclei, sqlmap)   │
  │ Agent C: cloud          (scout, pacu)      │
  │ Agent D: network        (nmap, masscan)    │
  │ Agent E: code-analysis  (semgrep, bandit)  │
  └────────────────────────────────────────────┘
       ↓ all agents write to findings bus
[Findings Bus — Shared Discovery State]
       ↓ attack-graph correlates findings
[Graph: SSRF → IMDS → Credentials → AD → Domain Admin]
       ↓
[knowledge-mgmt generates final report]
```

---

## Specialist Agent Roles

| Agent             | Skills Used                                       | Parallel?  |
| ----------------- | ------------------------------------------------- | ---------- |
| **Recon Agent**   | `recon`, `threat-intel`                           | ✅ Phase 1 |
| **Web Agent**     | `web-api-offensive`, `api-tester`, `vuln-scanner` | ✅ Phase 2 |
| **Cloud Agent**   | `cloud-offensive`                                 | ✅ Phase 2 |
| **Network Agent** | `network-offensive`                               | ✅ Phase 2 |
| **AD Agent**      | `ad-offensive`                                    | ✅ Phase 2 |
| **AI/LLM Agent**  | `ai-offensive`                                    | ✅ Phase 2 |
| **Code Agent**    | `code-analysis`                                   | ✅ Phase 2 |
| **Proxy Agent**   | `http-proxy`, `browser-automation`                | ✅ Phase 2 |
| **Graph Agent**   | `attack-graph`, `knowledge-mgmt`                  | 🔄 Phase 3 |

---

## Usage — Tell the Agent What You Want

The agent executes everything. You just describe the objective:

### Full Campaign

```
Run a complete red team assessment against target.com with scope: *.target.com, 192.168.1.0/24
```

The agent will:

1. Auto-install any missing tools via `setup-offensive-os.sh`
2. Run all recon (subfinder, amass, CT logs, httpx) — in parallel
3. Launch web, cloud, network, and AD agents simultaneously
4. Share discoveries between agents in real time
5. Correlate all findings and build attack chains
6. Generate executive and technical reports

### Targeted Workflows

```
Run web and API security assessment only, skip network and AD
```

```
Run recon only — passive, no active scanning
```

```
Perform cloud security assessment for AWS account with key AKIA...
```

```
Scan the GitHub org "target-org" for leaked secrets, then check for vulnerable dependencies
```

### Dynamic Agent Collaboration

```
If recon finds AWS S3 buckets, immediately hand them to the cloud agent for misconfiguration testing
```

The orchestrator automatically:

- Feeds recon output → web/cloud/network agents
- Feeds cloud creds found → AD agent for password spray
- Feeds code analysis findings → vuln-scanner for validation

---

## Parallel Execution Engine

The distributed engine uses Python `concurrent.futures` to run tools in parallel:

```python
# skills/distributed-workflows/orchestrator.py
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess, json, time
from dataclasses import dataclass
from typing import Callable

@dataclass
class AgentTask:
    name: str
    tool: str
    args: list[str]
    phase: int  # Lower phase runs first

class DistributedOrchestrator:
    def __init__(self, target: str, scope: list[str], workers: int = 8):
        self.target = target
        self.scope = scope
        self.workers = workers
        self.findings_bus: list[dict] = []  # Shared discovery state

    def run_tool(self, task: AgentTask) -> dict:
        """Execute a tool and return structured result."""
        start = time.time()
        try:
            result = subprocess.run(
                [task.tool] + task.args,
                capture_output=True, text=True, timeout=300
            )
            return {
                "agent": task.name,
                "tool": task.tool,
                "status": "success" if result.returncode == 0 else "error",
                "output": result.stdout[:5000],
                "error":  result.stderr[:500] if result.returncode != 0 else "",
                "elapsed": round(time.time() - start, 1),
            }
        except subprocess.TimeoutExpired:
            return {"agent": task.name, "status": "timeout", "tool": task.tool}
        except FileNotFoundError:
            return {"agent": task.name, "status": "tool_not_found", "tool": task.tool}

    def run_phase(self, tasks: list[AgentTask]) -> list[dict]:
        """Run all tasks in a phase in parallel."""
        results = []
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = {executor.submit(self.run_tool, t): t for t in tasks}
            for future in as_completed(futures):
                result = future.result()
                self.findings_bus.append(result)  # Share with all agents
                results.append(result)
                print(f"[{result['status'].upper()}] {result['agent']} "
                      f"({result.get('elapsed','?')}s)")
        return results

    def full_campaign(self) -> dict:
        """Execute full red team campaign against target."""
        print(f"\n{'='*60}")
        print(f"  🎯 OpenClaw Distributed Campaign: {self.target}")
        print(f"  Scope: {', '.join(self.scope)}")
        print(f"  Workers: {self.workers}")
        print(f"{'='*60}\n")

        # Phase 1: Recon (parallel across all recon tasks)
        print("[*] Phase 1: Reconnaissance")
        phase1 = [
            AgentTask("Recon:subfinder",  "subfinder", ["-d", self.target, "-silent"], phase=1),
            AgentTask("Recon:httpx",      "httpx",     ["-l", "/tmp/subs.txt", "-silent", "-status-code"], phase=1),
            AgentTask("Intel:cisa-kev",   "python3",   ["skills/threat-intel/scraper.py", "--days", "7", "--output", "json"], phase=1),
        ]
        phase1_results = self.run_phase(phase1)

        # Extract discovered subdomains from phase 1 for phase 2
        subs = self._extract_subdomains(phase1_results)

        # Phase 2: Multi-domain parallel attack
        print("\n[*] Phase 2: Parallel Attack Agents")
        phase2 = [
            AgentTask("Web:nuclei",      "nuclei",   ["-u", f"https://{self.target}", "-severity", "critical,high", "-silent", "-json"], phase=2),
            AgentTask("Web:sqlmap",      "python3",  ["skills/vuln-scanner/vuln_scanner.py", "--url", f"https://{self.target}", "--checks", "sqli,ssrf,headers", "--output", "json"], phase=2),
            AgentTask("Net:nmap",        "nmap",     ["-iL", "/tmp/live_hosts.txt", "--top-ports", "1000", "-sV", "--open", "-oG", "-"], phase=2),
            AgentTask("Cloud:trufflehog","trufflehog",["github", "--org", self.target.split(".")[0], "--json"], phase=2),
            AgentTask("Code:semgrep",    "semgrep",  ["--config=p/owasp-top-ten", ".", "--json"], phase=2),
        ]
        phase2_results = self.run_phase(phase2)

        # Phase 3: Correlation and reporting
        print("\n[*] Phase 3: Correlation & Report Generation")
        all_findings = self._aggregate_findings(phase1_results + phase2_results)

        return {
            "target": self.target,
            "phases_completed": 3,
            "total_findings": len(all_findings),
            "findings": all_findings,
            "raw_results": phase1_results + phase2_results,
        }

    def _extract_subdomains(self, results: list[dict]) -> list[str]:
        subs = []
        for r in results:
            if "Recon:subfinder" in r.get("agent", ""):
                subs = [line.strip() for line in r.get("output", "").split("\n") if line.strip()]
        return subs

    def _aggregate_findings(self, results: list[dict]) -> list[dict]:
        findings = []
        for r in results:
            if r.get("status") == "success" and r.get("output"):
                lines = r["output"].split("\n")
                for line in lines:
                    try:
                        item = json.loads(line)
                        findings.append({
                            "source": r["agent"],
                            "finding": item,
                        })
                    except json.JSONDecodeError:
                        pass
        return findings


if __name__ == "__main__":
    import argparse, json
    parser = argparse.ArgumentParser(description="OpenClaw Distributed Orchestrator")
    parser.add_argument("--target",  required=True, help="Target domain")
    parser.add_argument("--scope",   default="",    help="Comma-separated scope")
    parser.add_argument("--workers", type=int, default=8, help="Parallel workers")
    parser.add_argument("--output",  default="text", choices=["text","json"])
    args = parser.parse_args()

    orch = DistributedOrchestrator(
        target=args.target,
        scope=args.scope.split(",") if args.scope else [args.target],
        workers=args.workers,
    )
    results = orch.full_campaign()

    if args.output == "json":
        print(json.dumps(results, indent=2))
    else:
        print(f"\n✅ Campaign complete: {results['total_findings']} findings across {results['phases_completed']} phases")
```

---

## Auto-Install All Prerequisites

OpenClaw auto-installs all required tools before any phase runs:

```python
# skills/distributed-workflows/auto_install.py
import subprocess, shutil, sys

TOOLS = {
    "brew": {
        "nuclei":      "nuclei",
        "subfinder":   "subfinder",
        "httpx":       "httpx",
        "ffuf":        "ffuf",
        "amass":       "amass",
        "sqlmap":      "sqlmap",
        "semgrep":     "semgrep",
        "nmap":        "nmap",
        "masscan":     "masscan",
        "trufflehog":  "trufflehog",
        "gitleaks":    "gitleaks",
        "tmux":        "tmux",
        "bettercap":   "bettercap",
    },
    "pip3": {
        "mitmproxy":   "mitmproxy",
        "playwright":  "playwright",
        "impacket":    "impacket",
        "scapy":       "scapy",
        "bandit":      "bandit",
        "rich":        "rich",
        "requests":    "requests",
        "beautifulsoup4": "bs4",
        "feedparser":  "feedparser",
        "pyyaml":      "yaml",
        "jinja2":      "jinja2",
    }
}

def auto_install():
    missing_brew, missing_pip = [], []
    for pkg, binary in TOOLS["brew"].items():
        if not shutil.which(binary):
            missing_brew.append(pkg)
    for pkg, module in TOOLS["pip3"].items():
        try:
            __import__(module)
        except ImportError:
            missing_pip.append(pkg)

    if missing_brew:
        print(f"[*] Auto-installing {len(missing_brew)} brew tools: {', '.join(missing_brew)}")
        subprocess.run(["brew", "install"] + missing_brew, check=False)

    if missing_pip:
        print(f"[*] Auto-installing {len(missing_pip)} Python packages: {', '.join(missing_pip)}")
        subprocess.run([sys.executable, "-m", "pip", "install"] + missing_pip +
                       ["--break-system-packages", "-q"], check=False)

    # Playwright browsers
    if not shutil.which("playwright"):
        subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"], check=False)

    print("[✓] All prerequisites ready")

if __name__ == "__main__":
    auto_install()
```

---

## Findings Bus — Shared Discovery State

All agents write to and read from a shared findings bus so discoveries in one domain automatically feed other agents:

```python
# A cloud agent finds an AWS access key → immediately fed to AD agent
findings_bus.subscribe("cloud.credentials.found", lambda creds:
    ad_agent.test_password_spray(creds)
)

# Web agent finds SSRF → immediately triggers cloud metadata test
findings_bus.subscribe("web.ssrf.found", lambda ssrf_url:
    cloud_agent.test_imds_via_ssrf(ssrf_url)
)

# Recon finds subdomains → immediately probed by web agent
findings_bus.subscribe("recon.subdomain.found", lambda sub:
    web_agent.run_nuclei(sub)
)
```

---

## Usage from Red Team Agent

```
Run a full distributed red team assessment against target.com — all phases in parallel
Run only web and cloud agents in parallel, skip AD and network
Coordinate recon and web agents so that each discovered subdomain is immediately tested
Run auto-install to ensure all tools are ready before the engagement starts
Show me the current status of all running agent tasks
```
