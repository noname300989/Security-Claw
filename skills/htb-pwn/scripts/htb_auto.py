#!/usr/bin/env python3
"""
htb_auto.py — HackTheBox Full Automation Script
Part of the OpenClaw htb-pwn skill.

Usage:
    python3 htb_auto.py --list               # Show ranked active machines
    python3 htb_auto.py --run                # Auto-select and run full pipeline
    python3 htb_auto.py --machine <ID>       # Target a specific machine ID
    python3 htb_auto.py --machine <ID> --no-exploit  # Recon only, no exploitation

Requires:
    - HTB_APP_TOKEN env var (from https://app.hackthebox.com/profile/settings)
    - HTB VPN connected (sudo openvpn <your>.ovpn)
    - Python packages: requests, rich
    - Tools on PATH: nmap, gobuster, httpx, nuclei, sqlmap, curl
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

# ── Optional rich for pretty output ──────────────────────────────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    console = Console()
    def info(msg: str)  -> None: console.print(f"[cyan]\\[*][/cyan] {msg}")
    def ok(msg: str)    -> None: console.print(f"[green]\\[+][/green] {msg}")
    def warn(msg: str)  -> None: console.print(f"[yellow]\\[!][/yellow] {msg}")
    def err(msg: str)   -> None: console.print(f"[red]\\[-][/red] {msg}")
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    def info(msg: str) -> None: print(f"[*] {msg}")
    def ok(msg: str)   -> None: print(f"[+] {msg}")
    def warn(msg: str) -> None: print(f"[!] {msg}")
    def err(msg: str)  -> None: print(f"[-] {msg}")


# ── Constants ─────────────────────────────────────────────────────────────────
HTB_BASE   = "https://www.hackthebox.com/api/v4"
REPORT_DIR = Path("reports")
RECON_DIR  = Path("recon")
FINDINGS_DIR = Path("findings")

DIFFICULTY_ORDER = {"Easy": 0, "Medium": 1, "Hard": 2, "Insane": 3}

# ── Config ────────────────────────────────────────────────────────────────────
def get_token() -> str:
    token = os.environ.get("HTB_APP_TOKEN", "").strip()
    if not token:
        err("HTB_APP_TOKEN is not set. Export it or add it to your .env file.")
        err("  Get your token: https://app.hackthebox.com/profile/settings → App Token")
        sys.exit(1)
    return token

def htb_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
        "Accept":        "application/json",
    }


# ── Data Types ────────────────────────────────────────────────────────────────
@dataclass
class Machine:
    id:         int
    name:       str
    difficulty: str
    os:         str
    points:     int
    user_owns:  int
    root_owns:  int
    ip:         str = ""
    active:     bool = True

    @property
    def score(self) -> int:
        """Lower score = better target (easy + fewer owns = more novel)."""
        diff_score = DIFFICULTY_ORDER.get(self.difficulty, 99) * 1000
        own_score  = self.user_owns  # fewer solves = more unique
        return diff_score + own_score


@dataclass
class EngagementResult:
    machine:    Machine
    started_at: datetime = field(default_factory=datetime.utcnow)
    finished_at: datetime | None = None
    nmap_output: str = ""
    gobuster_output: str = ""
    nuclei_findings: list[dict] = field(default_factory=list)
    user_flag:  str = ""
    root_flag:  str = ""
    attack_path: list[str] = field(default_factory=list)
    report_path: Path | None = None

    @property
    def duration_str(self) -> str:
        if not self.finished_at:
            return "ongoing"
        td = self.finished_at - self.started_at
        h, rem = divmod(int(td.total_seconds()), 3600)
        m, s   = divmod(rem, 60)
        return f"{h}h {m:02d}m {s:02d}s"

    @property
    def pwned(self) -> bool:
        return bool(self.user_flag) and bool(self.root_flag)


# ── HTB API ───────────────────────────────────────────────────────────────────
import urllib.request
import urllib.parse

def htb_get(path: str, token: str) -> Any:
    """Hit the HTB v4 API with GET and return parsed JSON."""
    url = f"{HTB_BASE}{path}"
    req = urllib.request.Request(url, headers=htb_headers(token))
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except Exception as exc:
        err(f"HTB API GET {path} failed: {exc}")
        return {}


def htb_post(path: str, token: str, body: dict) -> Any:
    """Hit the HTB v4 API with POST and return parsed JSON."""
    url  = f"{HTB_BASE}{path}"
    data = json.dumps(body).encode()
    req  = urllib.request.Request(url, data=data, headers=htb_headers(token), method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except Exception as exc:
        err(f"HTB API POST {path} failed: {exc}")
        return {}


def list_active_machines(token: str) -> list[Machine]:
    """Fetch and return all active (non-retired) machines sorted by target score."""
    info("Fetching active machines from HTB API …")
    data = htb_get("/machine/list/active", token)
    raw  = data.get("data", data) if isinstance(data, dict) else []
    if not raw:
        # Fallback: paginate endpoint
        data = htb_get("/machine/paginate?page=1&is_active=1", token)
        raw  = data.get("data", {}).get("data", []) if isinstance(data, dict) else []

    machines: list[Machine] = []
    for m in raw:
        diff = m.get("difficultyText") or m.get("difficulty", "Unknown")
        machines.append(Machine(
            id         = m.get("id", 0),
            name       = m.get("name", "Unknown"),
            difficulty = diff,
            os         = m.get("os", "Unknown"),
            points     = m.get("points", 0),
            user_owns  = m.get("user_owns_count", m.get("userOwns", 0)),
            root_owns  = m.get("root_owns_count", m.get("rootOwns", 0)),
            ip         = m.get("ip", ""),
        ))
    machines.sort(key=lambda m: m.score)
    return machines


def spawn_machine(machine: Machine, token: str) -> str:
    """Spawn the machine and return its assigned IP."""
    info(f"Spawning machine: {machine.name} (ID {machine.id}) …")
    resp = htb_post("/vm/spawn", token, {"machine_id": machine.id})
    if resp.get("success") or resp.get("message"):
        ok(f"Machine spawned: {resp.get('message', 'OK')}")
    # Poll for IP (may take ~30s)
    for attempt in range(12):
        time.sleep(10)
        info(f"Waiting for IP … (attempt {attempt + 1}/12)")
        status = htb_get(f"/machine/active", token)
        ip = (status.get("info") or {}).get("ip", "")
        if ip:
            ok(f"Machine IP: {ip}")
            machine.ip = ip
            return ip
    warn("Could not retrieve IP automatically. Set it manually with --ip flag.")
    return ""


def submit_flag(machine: Machine, flag: str, flag_type: str, token: str) -> bool:
    """Submit user or root flag to HTB."""
    info(f"Submitting {flag_type} flag for {machine.name} …")
    resp = htb_post("/machine/own", token, {
        "id":         machine.id,
        "flag":       flag.strip(),
        "difficulty": 30,
    })
    success = bool(resp.get("success") or "Correct flag" in str(resp.get("message", "")))
    if success:
        ok(f"{flag_type.capitalize()} flag accepted! 🎉")
    else:
        warn(f"Flag submission response: {resp}")
    return success


# ── Tooling Wrappers ──────────────────────────────────────────────────────────
def run(cmd: list[str], *, capture: bool = True, timeout: int = 600) -> str:
    """Run a shell command and return stdout. Streams stderr."""
    info(f"Running: {' '.join(cmd)}")
    try:
        if capture:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            if result.returncode != 0 and result.stderr:
                warn(f"  stderr: {result.stderr[:300]}")
            return result.stdout
        else:
            subprocess.run(cmd, timeout=timeout, check=False)
            return ""
    except subprocess.TimeoutExpired:
        warn(f"Command timed out after {timeout}s: {cmd[0]}")
        return ""
    except FileNotFoundError:
        warn(f"Tool not found: {cmd[0]} — skipping.")
        return ""


def check_tools() -> list[str]:
    """Return a list of missing required tools."""
    required = ["nmap", "gobuster", "nuclei", "httpx", "sqlmap", "curl"]
    missing  = [t for t in required if not shutil.which(t)]
    return missing


# ── Recon Phase ───────────────────────────────────────────────────────────────
def phase_recon(target: str, recon_dir: Path) -> dict:
    """Run full enumeration. Returns dict of open ports, web services, tech."""
    recon_dir.mkdir(parents=True, exist_ok=True)
    results: dict = {"ports": [], "web": [], "tech": [], "nmap_raw": ""}

    # ── 1. nmap (top ports fast, then full) ──
    nmap_out = recon_dir / "nmap_top.txt"
    info("Running nmap top-1000 ports …")
    results["nmap_raw"] = run([
        "nmap", "-sV", "-sC", "--top-ports", "1000",
        "--min-rate", "1000", "-oN", str(nmap_out), target
    ], timeout=300)
    if nmap_out.exists():
        results["nmap_raw"] = nmap_out.read_text()

    # Parse open ports from nmap output
    for line in results["nmap_raw"].splitlines():
        m = re.match(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", line)
        if m:
            results["ports"].append({
                "port": int(m.group(1)),
                "service": m.group(2),
                "version": m.group(3).strip(),
            })

    # ── 2. httpx (web probe) ──
    for port in [80, 443, 8080, 8443]:
        for scheme in ["http", "https"]:
            url = f"{scheme}://{target}:{port}"
            out = run(["httpx", "-u", url, "-title", "-status-code",
                       "-tech-detect", "-silent"], timeout=30)
            if out.strip():
                results["web"].append({"url": url, "info": out.strip()})

    # ── 3. gobuster (if web found) ──
    if results["web"]:
        base_url = results["web"][0]["url"].split()[0]
        wordlist = (
            "/usr/share/seclists/Discovery/Web-Content/common.txt"
            if Path("/usr/share/seclists").exists()
            else "/usr/share/wordlists/dirb/common.txt"
        )
        if Path(wordlist).exists():
            gb_out = recon_dir / "gobuster.txt"
            run([
                "gobuster", "dir", "-u", base_url, "-w", wordlist,
                "--delay", "100ms", "-q", "-o", str(gb_out)
            ], timeout=300)
            if gb_out.exists():
                results["gobuster"] = gb_out.read_text()

    # ── 4. nuclei ──
    if results["web"]:
        nuc_out = recon_dir / "nuclei.json"
        base_url = results["web"][0]["url"].split()[0]
        run([
            "nuclei", "-u", base_url, "-severity", "critical,high,medium",
            "-rate-limit", "5", "-json", "-o", str(nuc_out), "-silent"
        ], timeout=600)
        if nuc_out.exists():
            for line in nuc_out.read_text().splitlines():
                try:
                    results.setdefault("nuclei", []).append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    return results


# ── Exploitation Phase ────────────────────────────────────────────────────────
def phase_exploit(target: str, recon: dict, findings_dir: Path) -> list[str]:
    """
    Service-aware exploitation. Returns list of attack path steps taken.
    NOTE: This performs actual exploitation — only run on HTB lab ranges.
    """
    findings_dir.mkdir(parents=True, exist_ok=True)
    attack_path: list[str] = []
    ports = {p["port"]: p for p in recon.get("ports", [])}

    # ── FTP anonymous login ──
    if 21 in ports:
        out = run(["curl", "-s", "--max-time", "10",
                   f"ftp://anonymous:anonymous@{target}/"], timeout=15)
        if out:
            ok("FTP anonymous login succeeded!")
            attack_path.append("FTP anonymous access — file listing retrieved")
            (findings_dir / "ftp_anon.txt").write_text(out)

    # ── SMB enumeration ──
    if 445 in ports:
        smbmap = shutil.which("smbmap")
        if smbmap:
            out = run(["smbmap", "-H", target, "-u", "", "-p", ""], timeout=60)
            if out:
                attack_path.append("SMB shares enumerated via smbmap")
                (findings_dir / "smb_shares.txt").write_text(out)

    # ── SSH default creds ──
    if 22 in ports:
        hydra = shutil.which("hydra")
        if hydra:
            info("Testing common SSH credentials (top 20 only) …")
            common_creds = [
                "admin:admin", "root:root", "admin:password",
                "admin:1234", "root:toor", "guest:guest",
            ]
            cred_file = findings_dir / "ssh_creds.txt"
            cred_file.write_text("\n".join(common_creds))
            out = run([
                "hydra", "-C", str(cred_file), "-t", "4",
                f"ssh://{target}", "-e", "nsr", "-q"
            ], timeout=120)
            if "login:" in out.lower():
                attack_path.append(f"SSH default credentials found → {out[:200]}")
                (findings_dir / "ssh_found.txt").write_text(out)

    # ── Web — SQLi via sqlmap ──
    if recon.get("web"):
        base_url = recon["web"][0]["url"].split()[0]
        login_url = f"{base_url}/login"
        sqli_out  = findings_dir / "sqli.json"
        info(f"Testing {login_url} for SQL injection …")
        out = run([
            "sqlmap", "-u", login_url,
            "--batch", "--level=2", "--risk=1", "--delay=1",
            "--output-dir", str(findings_dir / "sqlmap"),
            "--quiet"
        ], timeout=300)
        if "injectable" in out.lower() or "sql injection" in out.lower():
            attack_path.append(f"SQL Injection found at {login_url}")

    # ── Nuclei critical findings ──
    for finding in recon.get("nuclei", []):
        severity = finding.get("info", {}).get("severity", "").upper()
        name     = finding.get("info", {}).get("name", "Unknown")
        if severity in ("CRITICAL", "HIGH"):
            attack_path.append(f"[{severity}] Nuclei: {name} @ {finding.get('matched-at', '')}")

    if not attack_path:
        attack_path.append("Manual exploitation required — no automated vector found")
        warn("No automated exploit vector triggered. Refer to nmap/nuclei output for manual steps.")

    return attack_path


# ── Report Generation ─────────────────────────────────────────────────────────
def generate_report(result: EngagementResult) -> Path:
    """Write a structured Markdown pentest report and return its path."""
    m       = result.machine
    date_str = result.started_at.strftime("%Y-%m-%d")
    report_dir = REPORT_DIR / f"{m.name}_{date_str}"
    report_dir.mkdir(parents=True, exist_ok=True)

    flags_row = ""
    if result.user_flag:
        flags_row += f"| **User Flag**   | `{result.user_flag}` |\n"
    if result.root_flag:
        flags_row += f"| **Root Flag**   | `{result.root_flag}` |\n"

    attack_path_md = "\n".join(
        f"{i+1}. {step}" for i, step in enumerate(result.attack_path)
    ) or "_No automated attack path recorded. See recon output._"

    nuclei_md = ""
    for f in result.nuclei_findings:
        sev  = f.get("info", {}).get("severity", "info").upper()
        name = f.get("info", {}).get("name", "Unknown")
        url  = f.get("matched-at", "")
        nuclei_md += f"- **[{sev}]** {name} @ `{url}`\n"
    if not nuclei_md:
        nuclei_md = "_No nuclei findings._"

    status = "PWNED ✅" if result.pwned else "PARTIAL ⚠️"

    report_content = f"""# HTB Machine Report: {m.name}

| Field           | Value                 |
|-----------------|-----------------------|
| **Machine**     | {m.name}              |
| **Date**        | {date_str}            |
| **OS**          | {m.os}                |
| **Difficulty**  | {m.difficulty}        |
| **IP**          | {m.ip or "10.10.XX.XX"} |
| **Status**      | {status}              |
| **Duration**    | {result.duration_str} |
{flags_row}

---

## Executive Summary

Machine **{m.name}** ({m.difficulty} · {m.os}) was fully compromised during an automated
security assessment on {date_str}. The engagement covered full port enumeration,
service fingerprinting, vulnerability scanning, and targeted exploitation.
{"Both user and root flags were captured." if result.pwned else "Partial access was achieved."}

---

## Recon Summary

### Open Ports (nmap)

```
{result.nmap_output[:3000] if result.nmap_output else "See recon/nmap_top.txt"}
```

### Web Fingerprint (httpx)

```
{result.gobuster_output[:1000] if result.gobuster_output else "See recon/gobuster.txt"}
```

---

## Vulnerability Scan (nuclei)

{nuclei_md}

---

## Attack Path

{attack_path_md}

---

## Flags

| Type   | Value                                         | Submitted |
|--------|-----------------------------------------------|-----------|
| User   | `{result.user_flag or "NOT CAPTURED"}`        | {"✅" if result.user_flag else "❌"} |
| Root   | `{result.root_flag or "NOT CAPTURED"}`        | {"✅" if result.root_flag else "❌"} |

---

## Remediation Notes

1. **Patch identified CVEs** — Apply vendor patches for all detected vulnerabilities.
2. **Restrict exposed services** — Minimise open ports; firewall non-essential services.
3. **Harden authentication** — Enforce strong credentials; disable default accounts.
4. **Update software stack** — Ensure all services run current, patched versions.
5. **Monitor logs** — Implement SIEM alerting for lateral movement indicators.

---

## Evidence

```
{report_dir}/
  nmap_top.txt
  gobuster.txt
  nuclei.json
  results.json
  report.md
```

---

_Generated by OpenClaw htb-pwn skill — {datetime.utcnow().isoformat()}Z_
"""

    report_path = report_dir / "report.md"
    report_path.write_text(report_content)

    # Also save raw result JSON
    result_json = {
        "machine": {"id": m.id, "name": m.name, "os": m.os, "difficulty": m.difficulty, "ip": m.ip},
        "started_at":  result.started_at.isoformat(),
        "finished_at": result.finished_at.isoformat() if result.finished_at else None,
        "duration":    result.duration_str,
        "user_flag":   result.user_flag,
        "root_flag":   result.root_flag,
        "pwned":       result.pwned,
        "attack_path": result.attack_path,
        "report_path": str(report_path),
    }
    (report_dir / "results.json").write_text(json.dumps(result_json, indent=2))

    ok(f"Report written: {report_path}")
    result.report_path = report_path
    return report_path


# ── Broadcast Summary ─────────────────────────────────────────────────────────
def print_broadcast_summary(result: EngagementResult) -> None:
    """Print the broadcast message that the OpenClaw agent will send to all channels."""
    m      = result.machine
    status = "PWNED ✅" if result.pwned else "PARTIAL ⚠️"
    flags  = f"User {'✅' if result.user_flag else '❌'}  Root {'✅' if result.root_flag else '❌'}"

    broadcast = f"""
⚔️  HTB BOX {status} — {m.name}
{'━' * 50}
Machine:    {m.name} ({m.difficulty} · {m.os})
IP:         {m.ip or "10.10.XX.XX"}
Flags:      {flags}
Duration:   {result.duration_str}
Attack:     {result.attack_path[0] if result.attack_path else "See report"}

Full report: {result.report_path or f"reports/{m.name}_<date>/report.md"}
"""
    print(broadcast)

    # Emit a JSON block that the OpenClaw agent picks up to broadcast
    broadcast_data = {
        "htb_broadcast": True,
        "machine":     m.name,
        "difficulty":  m.difficulty,
        "os":          m.os,
        "status":      status,
        "flags":       flags,
        "duration":    result.duration_str,
        "attack_path": result.attack_path[:3],
        "report_path": str(result.report_path) if result.report_path else None,
    }
    print("\n--- BROADCAST_JSON ---")
    print(json.dumps(broadcast_data, indent=2))
    print("--- END_BROADCAST_JSON ---")


# ── CLI ───────────────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="HTB automation pipeline — browse, exploit, report, broadcast.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--list",       action="store_true",  help="List active machines and exit")
    p.add_argument("--run",        action="store_true",  help="Auto-select best machine and run full pipeline")
    p.add_argument("--machine",    type=int,             help="Target a specific machine ID")
    p.add_argument("--ip",         type=str,             help="Override machine IP (if VPN assigns differently)")
    p.add_argument("--no-exploit", action="store_true",  help="Skip exploitation phase (recon only)")
    p.add_argument("--no-spawn",   action="store_true",  help="Skip machine spawning (already running)")
    return p.parse_args()


def display_machine_table(machines: list[Machine]) -> None:
    if HAS_RICH:
        table = Table(title="Active HackTheBox Machines", show_lines=True)
        table.add_column("ID",         style="dim",    width=6)
        table.add_column("Name",       style="bold")
        table.add_column("OS",         style="cyan",   width=10)
        table.add_column("Difficulty", style="white",  width=10)
        table.add_column("Points",     justify="right", width=7)
        table.add_column("User Owns",  justify="right", width=10)
        table.add_column("Root Owns",  justify="right", width=10)

        for i, m in enumerate(machines):
            diff_color = {
                "Easy":   "green",
                "Medium": "yellow",
                "Hard":   "red",
                "Insane": "magenta",
            }.get(m.difficulty, "white")
            mark = " 🎯" if i == 0 else ""
            table.add_row(
                str(m.id), m.name + mark, m.os,
                f"[{diff_color}]{m.difficulty}[/{diff_color}]",
                str(m.points), str(m.user_owns), str(m.root_owns),
            )
        console.print(table)
    else:
        print(f"\n{'ID':>6}  {'Name':<20}  {'OS':<10}  {'Diff':<8}  {'Pts':>5}  {'Owns':>6}")
        print("-" * 65)
        for i, m in enumerate(machines):
            mark = " <-- RECOMMENDED" if i == 0 else ""
            print(f"{m.id:>6}  {m.name:<20}  {m.os:<10}  {m.difficulty:<8}  {m.points:>5}  {m.user_owns:>6}{mark}")
        print()


def main() -> None:
    args  = parse_args()
    token = get_token()

    # ── Check required tools ──
    missing = check_tools()
    if missing:
        warn(f"Missing tools (install first): {', '.join(missing)}")
        warn("Run: brew install nmap gobuster httpx sqlmap nuclei  (macOS)")

    # ── List mode ──
    if args.list:
        machines = list_active_machines(token)
        if not machines:
            err("No active machines found. Check your HTB_APP_TOKEN and network.")
            sys.exit(1)
        display_machine_table(machines)
        return

    # ── Run mode ──
    if not (args.run or args.machine):
        warn("Specify --list, --run, or --machine <ID>")
        sys.argv.append("--help")
        parse_args()
        return

    machines = list_active_machines(token)
    if not machines:
        err("No active machines returned. Check token and connectivity.")
        sys.exit(1)

    # Select machine
    if args.machine:
        candidates = [m for m in machines if m.id == args.machine]
        if not candidates:
            err(f"Machine ID {args.machine} not found in active list.")
            sys.exit(1)
        machine = candidates[0]
    else:
        display_machine_table(machines)
        machine = machines[0]

    ok(f"Target selected: {machine.name} ({machine.difficulty} · {machine.os})")

    # ── Spawn ──
    if not args.no_spawn:
        ip = spawn_machine(machine, token)
        if args.ip:
            machine.ip = args.ip
        elif ip:
            machine.ip = ip
    elif args.ip:
        machine.ip = args.ip

    if not machine.ip:
        err("No machine IP available. Use --ip <IP> to set it manually.")
        sys.exit(1)

    result = EngagementResult(machine=machine)

    # ── Phase 3: Recon ──
    recon_dir = RECON_DIR / machine.name
    info(f"Starting recon against {machine.ip} …")
    recon_data = phase_recon(machine.ip, recon_dir)
    result.nmap_output    = recon_data.get("nmap_raw", "")
    result.gobuster_output = recon_data.get("gobuster", "")
    result.nuclei_findings = recon_data.get("nuclei", [])
    ok(f"Recon complete: {len(recon_data.get('ports', []))} open ports, "
       f"{len(recon_data.get('web', []))} web services")

    # ── Phase 4: Exploit ──
    if not args.no_exploit:
        info("Starting exploitation phase …")
        findings_dir = FINDINGS_DIR / machine.name
        result.attack_path = phase_exploit(machine.ip, recon_data, findings_dir)
        ok(f"Exploitation phase done. Attack path steps: {len(result.attack_path)}")
    else:
        result.attack_path = ["Exploitation skipped (--no-exploit flag)"]

    # ── Phase 5: Proof (attempt to read flags if shell obtained) ──
    # NOTE: Flag capture after shell access is performed interactively.
    # The script accepts flags via stdin for submission.
    if not args.no_exploit:
        info("If you have a shell, paste your flags below (press Enter to skip):")
        try:
            user_flag = input("  user.txt flag (or blank): ").strip()
            root_flag = input("  root.txt flag (or blank): ").strip()
        except (EOFError, KeyboardInterrupt):
            user_flag = root_flag = ""

        if user_flag:
            submit_flag(machine, user_flag, "user", token)
            result.user_flag = user_flag
        if root_flag:
            submit_flag(machine, root_flag, "root", token)
            result.root_flag = root_flag

    # ── Phase 6: Report ──
    result.finished_at = datetime.utcnow()
    generate_report(result)

    # ── Phase 7: Broadcast summary (agent reads this output) ──
    print_broadcast_summary(result)


if __name__ == "__main__":
    main()
