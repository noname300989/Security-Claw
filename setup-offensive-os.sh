#!/usr/bin/env bash
# OpenClaw Offensive OS — Security-First Setup Script
# Automates installation of all tools and configuration for all 5 offensive phases.
# Supports macOS (Brew) and Linux (APT).
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

header() { echo -e "${BLUE}$1${NC}"; }
ok()     { echo -e "${GREEN}[✓]${NC} $1"; }
warn()   { echo -e "${YELLOW}[!]${NC} $1"; }
err()    { echo -e "${RED}[✗]${NC} $1"; }

header "===================================================="
header "   OPENCLAW OFFENSIVE OS — SETUP (SECURITY-FIRST)"
header "===================================================="
echo ""
warn "This script installs offensive security tools."
warn "Only use on systems you are authorized to test."
echo ""

# ─────────────────────────────────────────────────────────────
# OS Detection
# ─────────────────────────────────────────────────────────────
OS="$(uname -s)"
PKG_MGR=""
INSTALL_CMD=""

if [[ "$OS" == "Darwin" ]]; then
  PKG_MGR="brew"
  if ! command -v brew >/dev/null 2>&1; then
    err "Homebrew not found. Install it from https://brew.sh first."
    exit 1
  fi
  INSTALL_CMD="brew install"
  ok "macOS detected. Using Homebrew."
elif [[ "$OS" == "Linux" ]]; then
  if command -v apt-get >/dev/null 2>&1; then
    PKG_MGR="apt"
    INSTALL_CMD="sudo apt-get install -y"
    ok "Linux detected. Using APT."
    warn "Running apt-get update..."
    sudo apt-get update -qq
  else
    err "Unsupported Linux distribution. APT package manager required."
    exit 1
  fi
else
  err "Unsupported operating system: $OS. Use the Windows .ps1 script instead."
  exit 1
fi

install_pkg() {
  local pkg=$1
  if command -v "$pkg" >/dev/null 2>&1; then
    ok "$pkg already installed"
  else
    warn "Installing $pkg..."
    $INSTALL_CMD "$pkg" 2>/dev/null || warn "Could not install $pkg via $PKG_MGR — install manually"
  fi
}

install_pip() {
  local pkg=$1
  if ! python3 -c "import $pkg" 2>/dev/null && ! command -v "$pkg" >/dev/null 2>&1; then
    warn "Installing $pkg (pip)..."
    pip3 install "$pkg" --break-system-packages 2>/dev/null || pip3 install "$pkg" 2>/dev/null || warn "$pkg install failed — install manually"
  else
    ok "$pkg already installed"
  fi
}

# ─────────────────────────────────────────────────────────────
# 1. Node.js Version Check
# ─────────────────────────────────────────────────────────────
header "[1/7] Checking Node.js version..."
if ! command -v node >/dev/null 2>&1; then
  warn "Node.js not found. Installing..."
  if [[ "$PKG_MGR" == "brew" ]]; then
    brew install node
  elif [[ "$PKG_MGR" == "apt" ]]; then
    curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
    sudo apt-get install -y nodejs
  fi
fi

REQUIRED_NODE="22.12.0"
CURRENT_NODE=$(node -v 2>/dev/null | cut -d'v' -f2 || echo "0.0.0")

if [[ "$(printf '%s\n' "$REQUIRED_NODE" "$CURRENT_NODE" | sort -V | head -n1)" != "$REQUIRED_NODE" ]]; then
  err "Node $CURRENT_NODE is too old. OpenClaw requires Node >= $REQUIRED_NODE."
  exit 1
fi
ok "Node.js $CURRENT_NODE meets requirement (>= $REQUIRED_NODE)"

# ─────────────────────────────────────────────────────────────
# 2. Phase 1 Tools — Web/API Offensive
# ─────────────────────────────────────────────────────────────
header "[2/7] Installing Phase 1 tools (Web/API Offensive)..."
if [[ "$PKG_MGR" == "brew" ]]; then
  PHASE1_TOOLS=("nuclei" "sqlmap" "ffuf" "semgrep" "amass" "subfinder" "httpx" "feroxbuster")
  for tool in "${PHASE1_TOOLS[@]}"; do install_pkg "$tool"; done
elif [[ "$PKG_MGR" == "apt" ]]; then
  # On Linux, these tools are often best installed via Go or direct binary downloads.
  # Installing the ones available in APT, or warning to use Go for specialized tools.
  warn "On Linux, tools like nuclei/subfinder are best installed via 'go install'. Attempting APT fallbacks."
  sudo apt-get install -y sqlmap ffuf
  install_pkg "golang"
fi

install_pip "jwt_tool"

# ─────────────────────────────────────────────────────────────
# 3. Phase 2 Tools — Cloud Offensive
# ─────────────────────────────────────────────────────────────
header "[3/7] Installing Phase 2 tools (Cloud Offensive)..."
install_pkg "awscli"
install_pip "trufflehog"
install_pip "scoutsuite"
install_pip "pacu"

# ─────────────────────────────────────────────────────────────
# 4. Phase 3 Tools — Active Directory Offensive
# ─────────────────────────────────────────────────────────────
header "[4/7] Installing Phase 3 tools (Active Directory Offensive)..."
install_pip "impacket"
install_pip "bloodhound"

if ! command -v crackmapexec >/dev/null 2>&1 && ! command -v cme >/dev/null 2>&1; then
  install_pip "crackmapexec"
fi

if ! command -v kerbrute >/dev/null 2>&1; then
  warn "Kerbrute not found — download manually from GitHub releases"
fi

# ─────────────────────────────────────────────────────────────
# 5. Phase 4 Tools — Network Offensive
# ─────────────────────────────────────────────────────────────
header "[5/7] Installing Phase 4 tools (Network Offensive)..."
NETWORK_TOOLS=("nmap" "masscan" "bettercap" "hydra")
for tool in "${NETWORK_TOOLS[@]}"; do install_pkg "$tool"; done

# ─────────────────────────────────────────────────────────────
# 6. Global Dependences
# ─────────────────────────────────────────────────────────────
header "[6/7] Installing Global Dependencies..."
if ! command -v pnpm >/dev/null 2>&1; then
  warn "pnpm not found. Installing..."
  npm install -g pnpm || { err "pnpm installation failed."; exit 1; }
fi

# ─────────────────────────────────────────────────────────────
# 7. Project Build & Config
# ─────────────────────────────────────────────────────────────
header "[7/7] Initializing OpenClaw project..."

ok "Running pnpm install..."
pnpm install

ok "Building project..."
pnpm build || {
  err "Build failed. Check Node.js version and dependencies."
  exit 1
}

# Generate openclaw.json config template
ok "Generating openclaw.json configuration template..."
TEMPLATE_FILE="openclaw.json.template"
if [[ ! -f "$TEMPLATE_FILE" ]]; then
  cat > "$TEMPLATE_FILE" << 'JSONEOF'
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
JSONEOF
fi

echo ""
echo "──────────────────────────────────────────────────────"
ok "OpenClaw Offensive OS setup complete!"
echo ""
echo "  Next steps:"
echo "  1. Copy openclaw.json.template to ~/.openclaw/openclaw.json"
echo "  2. Add your LLM API key to .env (see .env.example)"
echo "  3. Activate the Red Team Agent:"
echo "     pnpm openclaw agent --activation red-team"
echo ""
warn "Security reminder: Only test systems you are authorized to test."
echo "──────────────────────────────────────────────────────"
