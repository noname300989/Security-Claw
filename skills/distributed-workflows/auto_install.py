#!/usr/bin/env python3
"""
OpenClaw Auto-Install — Prerequisite Manager
Automatically installs all tools required for the Offensive OS platform.
Called by the Red Team Agent before any engagement phase starts.

Usage (by agent or manually):
    python3 skills/distributed-workflows/auto_install.py
    python3 skills/distributed-workflows/auto_install.py --check-only
    python3 skills/distributed-workflows/auto_install.py --phase web
"""

import argparse
import shutil
import subprocess
import sys
from dataclasses import dataclass

try:
    from rich.console import Console
    from rich.table import Table
    RICH = True
    console = Console()
except ImportError:
    RICH = False
    class _C:
        def print(self, *a, **kw): print(*a)
    console = _C()

# ─────────────────────────────────────────────────────────────────────────────
# Tool Registry
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Tool:
    name: str
    binary: str
    install_via: str        # "brew" | "pip3" | "shell"
    install_cmd: list[str]  # arguments to brew/pip3, or full shell command
    phase: str              # "all" | "web" | "cloud" | "ad" | "network" | "recon" | "code"
    check_module: str = ""  # Python module name for pip-installed tools

TOOLS: list[Tool] = [
    # ── Recon ──────────────────────────────────────────────────────────────
    Tool("subfinder",     "subfinder",   "brew",  ["subfinder"],                          "recon"),
    Tool("httpx",         "httpx",       "brew",  ["httpx"],                              "recon"),
    Tool("amass",         "amass",       "brew",  ["amass"],                              "recon"),
    Tool("nmap",          "nmap",        "brew",  ["nmap"],                               "recon"),
    Tool("masscan",       "masscan",     "brew",  ["masscan"],                            "network"),
    Tool("trufflehog",    "trufflehog",  "brew",  ["trufflehog"],                         "recon"),
    Tool("gitleaks",      "gitleaks",    "brew",  ["gitleaks"],                           "recon"),

    # ── Web / API ──────────────────────────────────────────────────────────
    Tool("nuclei",        "nuclei",      "brew",  ["nuclei"],                             "web"),
    Tool("sqlmap",        "sqlmap",      "brew",  ["sqlmap"],                             "web"),
    Tool("ffuf",          "ffuf",        "brew",  ["ffuf"],                               "web"),
    Tool("semgrep",       "semgrep",     "brew",  ["semgrep"],                            "code"),
    Tool("feroxbuster",   "feroxbuster", "brew",  ["feroxbuster"],                        "web"),

    # ── Proxy & Browser ─────────────────────────────────────────────────────
    Tool("mitmproxy",     "mitmproxy",   "pip3",  ["mitmproxy"],                          "web",    "mitmproxy"),
    Tool("playwright",    "",            "pip3",  ["playwright"],                         "web",    "playwright"),

    # ── Cloud ───────────────────────────────────────────────────────────────
    Tool("aws-cli",       "aws",         "brew",  ["awscli"],                             "cloud"),
    Tool("scoutsuite",    "scout",       "pip3",  ["scoutsuite"],                         "cloud",  "ScoutSuite"),
    Tool("pacu",          "pacu",        "pip3",  ["pacu"],                               "cloud",  "pacu"),

    # ── Active Directory ────────────────────────────────────────────────────
    Tool("impacket",      "",            "pip3",  ["impacket"],                           "ad",     "impacket"),
    Tool("crackmapexec",  "crackmapexec","pip3",  ["crackmapexec"],                       "ad",     ""),
    Tool("bloodhound-py", "",            "pip3",  ["bloodhound"],                         "ad",     "bloodhound"),

    # ── Network ─────────────────────────────────────────────────────────────
    Tool("bettercap",     "bettercap",   "brew",  ["bettercap"],                          "network"),
    Tool("hydra",         "hydra",       "brew",  ["hydra"],                              "network"),

    # ── SAST / SCA ──────────────────────────────────────────────────────────
    Tool("bandit",        "bandit",      "pip3",  ["bandit"],                             "code",   "bandit"),
    Tool("safety",        "safety",      "pip3",  ["safety"],                             "code",   "safety"),

    # ── Python Security Libs ────────────────────────────────────────────────
    Tool("requests",      "",            "pip3",  ["requests"],                           "all",    "requests"),
    Tool("httpx-py",      "",            "pip3",  ["httpx"],                              "all",    "httpx"),
    Tool("rich",          "",            "pip3",  ["rich"],                               "all",    "rich"),
    Tool("pyyaml",        "",            "pip3",  ["pyyaml"],                             "all",    "yaml"),
    Tool("beautifulsoup4","",            "pip3",  ["beautifulsoup4"],                     "all",    "bs4"),
    Tool("feedparser",    "",            "pip3",  ["feedparser"],                         "all",    "feedparser"),
    Tool("jinja2",        "",            "pip3",  ["jinja2"],                             "all",    "jinja2"),
    Tool("scapy",         "",            "pip3",  ["scapy"],                              "network","scapy"),
    Tool("cryptography",  "",            "pip3",  ["cryptography"],                       "all",    "cryptography"),
    Tool("paramiko",      "",            "pip3",  ["paramiko"],                           "ad",     "paramiko"),

    # ── tmux ────────────────────────────────────────────────────────────────
    Tool("tmux",          "tmux",        "brew",  ["tmux"],                               "all"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Checker
# ─────────────────────────────────────────────────────────────────────────────

def is_installed(tool: Tool) -> bool:
    if tool.binary and shutil.which(tool.binary):
        return True
    if tool.check_module:
        try:
            __import__(tool.check_module)
            return True
        except ImportError:
            return False
    return not tool.binary and not tool.check_module  # unknown, assume ok

def check_all(phase: str = "all") -> tuple[list[Tool], list[Tool]]:
    installed, missing = [], []
    for t in TOOLS:
        if phase != "all" and t.phase not in ("all", phase):
            continue
        (installed if is_installed(t) else missing).append(t)
    return installed, missing


# ─────────────────────────────────────────────────────────────────────────────
# Installer
# ─────────────────────────────────────────────────────────────────────────────

def install_tool(tool: Tool) -> bool:
    try:
        if tool.install_via == "brew":
            result = subprocess.run(
                ["brew", "install"] + tool.install_cmd,
                capture_output=True, text=True, timeout=120, check=False,
            )
        elif tool.install_via == "pip3":
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "--break-system-packages", "-q"]
                + tool.install_cmd,
                capture_output=True, text=True, timeout=120, check=False,
            )
        else:
            return False

        success = result.returncode == 0
        if not success and result.stderr:
            console.print(f"    [dim red]{result.stderr[:100]}[/dim red]")
        return success
    except Exception as e:
        console.print(f"    [red]Error: {e}[/red]")
        return False


def auto_install(phase: str = "all", dry_run: bool = False) -> dict:
    installed, missing = check_all(phase)
    phase_label = f" ({phase})" if phase != "all" else ""

    console.print(f"\n[bold]🔧 OpenClaw Auto-Install{phase_label}[/bold]")
    console.print(f"   Already installed: [green]{len(installed)}[/green]  "
                  f"Missing: [yellow]{len(missing)}[/yellow]\n")

    if not missing:
        console.print("[green]✓ All prerequisites are already installed![/green]")
        return {"installed": len(installed), "newly_installed": 0, "failed": []}

    newly_installed, failed = [], []
    brew_batch = [t for t in missing if t.install_via == "brew"]
    pip_batch  = [t for t in missing if t.install_via == "pip3"]

    # Batch brew installs
    if brew_batch and not dry_run:
        pkgs = [p for t in brew_batch for p in t.install_cmd]
        console.print(f"[*] brew install {' '.join(pkgs)}")
        result = subprocess.run(
            ["brew", "install"] + pkgs,
            capture_output=True, text=True, timeout=300, check=False,
        )
        for t in brew_batch:
            (newly_installed if is_installed(t) else failed).append(t.name)

    # Batch pip installs
    if pip_batch and not dry_run:
        pkgs = [p for t in pip_batch for p in t.install_cmd]
        console.print(f"[*] pip install {' '.join(pkgs)}")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--break-system-packages", "-q"] + pkgs,
            capture_output=True, text=True, timeout=300, check=False,
        )
        for t in pip_batch:
            (newly_installed if is_installed(t) else failed).append(t.name)

    # Playwright browsers (special case)
    if any(t.name == "playwright" for t in pip_batch) and not dry_run:
        console.print("[*] Installing Playwright Chromium browser...")
        subprocess.run(
            [sys.executable, "-m", "playwright", "install", "chromium"],
            capture_output=True, timeout=120, check=False,
        )

    # Nuclei template update
    if shutil.which("nuclei") and not dry_run:
        console.print("[*] Updating Nuclei templates...")
        subprocess.run(["nuclei", "-update-templates", "-silent"],
                       capture_output=True, timeout=60, check=False)

    console.print(f"\n[green]✓ Newly installed: {len(newly_installed)}[/green]")
    if failed:
        console.print(f"[yellow]⚠ Failed (install manually): {', '.join(failed)}[/yellow]")

    return {
        "already_installed": len(installed),
        "newly_installed": len(newly_installed),
        "failed": failed,
    }


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def print_status_table(phase: str = "all") -> None:
    installed, missing = check_all(phase)
    table = Table(title=f"Tool Status ({phase})", border_style="dim", show_lines=False)
    table.add_column("Tool", width=20)
    table.add_column("Phase", width=10)
    table.add_column("Status", width=10)
    for t in sorted(TOOLS, key=lambda x: (x.phase, x.name)):
        if phase != "all" and t.phase not in ("all", phase):
            continue
        status = "[green]✓ Ready[/green]" if is_installed(t) else "[red]✗ Missing[/red]"
        table.add_row(t.name, t.phase, status)
    console.print(table)


def main():
    parser = argparse.ArgumentParser(description="OpenClaw Auto-Install — Prerequisite Manager")
    parser.add_argument("--phase",      default="all",
                        choices=["all","web","cloud","ad","network","recon","code"],
                        help="Install tools for a specific phase only")
    parser.add_argument("--check-only", action="store_true", help="Show status without installing")
    parser.add_argument("--dry-run",    action="store_true", help="Show what would be installed")
    args = parser.parse_args()

    if args.check_only:
        print_status_table(args.phase)
    else:
        result = auto_install(phase=args.phase, dry_run=args.dry_run)
        if not args.dry_run:
            print_status_table(args.phase)


if __name__ == "__main__":
    main()
