<#
.SYNOPSIS
OpenClaw Offensive OS — Windows Security-First Setup Script
Automates the installation of Node.js, Python, pnpm, and various offensive security/pentesting tools on Windows natively using Winget & pip.

.DESCRIPTION
This script must be run as Administrator. It will attempt to install Node, Python, and the required tooling for all 5 offensive phases. Note that some Linux-native tools are omitted on Windows by default and run via OpenClaw containerized skills.
#>

if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Please run this script as an Administrator."
    Exit
}

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "   OPENCLAW OFFENSIVE OS — SETUP (WINDOWS)" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host ""
Write-Warning "This script installs offensive security tools."
Write-Warning "Only use on systems you are authorized to test."
Write-Host ""

# Ensure Winget is available
if (-Not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Error "Winget is not installed. Please install App Installer from the Microsoft Store."
    Exit
}

function Install-WingetPackage {
    param ($PackageId)
    Write-Host "Installing $PackageId..." -ForegroundColor Yellow
    winget install --id "$PackageId" --accept-package-agreements --accept-source-agreements --silent
}

function Install-PipPackage {
    param ($Package)
    Write-Host "Installing $Package via pip..." -ForegroundColor Yellow
    pip install "$Package" --quiet
}

# 1. Base Framework
Write-Host "[1/5] Installing Base Framework (Node.js & Python)..." -ForegroundColor Cyan
Install-WingetPackage "OpenJS.NodeJS"
Install-WingetPackage "Python.Python.3.11"

# Refresh environment variables
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

# 2. Phase 1 & 2 Tools (Web, API, Cloud)
Write-Host "[2/5] Installing Phase 1 & 2 Tools..." -ForegroundColor Cyan
Install-WingetPackage "ProjectDiscovery.Nuclei"
Install-WingetPackage "Amazon.AWSCLI"
Install-WingetPackage "Nmap.Nmap"

# 3. Python offensive packages
Write-Host "[3/5] Installing Python Offensive Tooling..." -ForegroundColor Cyan
python -m pip install --upgrade pip
Install-PipPackage "jwt_tool"
Install-PipPackage "trufflehog"
Install-PipPackage "scoutsuite"
Install-PipPackage "pacu"
Install-PipPackage "impacket"
Install-PipPackage "bloodhound"
Install-PipPackage "crackmapexec"

# 4. Global Dependencies
Write-Host "[4/5] Installing pnpm & global deps..." -ForegroundColor Cyan
npm install -g pnpm

# 5. Project Build
Write-Host "[5/5] Building OpenClaw Project..." -ForegroundColor Cyan
pnpm install
pnpm build

if (-Not (Test-Path "openclaw.json.template")) {
    $TemplateJson = @"
{
  "agents": {
    "list": [
      {
        "id": "red-team",
        "name": "Red Team Agent",
        "emoji": "😈",
        "skills": ["red-team-orchestration", "web-api-offensive", "ai-offensive", "cloud-offensive", "ad-offensive", "network-offensive", "attack-graph"],
        "identity": {
          "name": "Red Team",
          "emoji": "😈"
        }
      }
    ]
  }
}
"@
    Set-Content -Path "openclaw.json.template" -Value $TemplateJson
}

Write-Host "──────────────────────────────────────────────────────"
Write-Host "[✓] OpenClaw Offensive OS Windows setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "  Next steps:"
Write-Host "  1. Copy openclaw.json.template to ~/.openclaw/openclaw.json"
Write-Host "  2. Add your LLM API key to .env (see .env.example)"
Write-Host "  3. Activate the Red Team Agent:"
Write-Host "     pnpm openclaw agent --activation red-team"
Write-Host "──────────────────────────────────────────────────────"
