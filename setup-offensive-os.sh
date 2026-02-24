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
# 1. Go Installation (required for many security tools)
# ─────────────────────────────────────────────────────────────
header "[1/8] Checking / Installing Go (required for nuclei, ffuf, amass, subfinder, httpx, kerbrute)..."

install_go() {
  local GO_VERSION="1.22.3"
  local OS_LOWER
  local ARCH
  OS_LOWER="$(uname -s | tr '[:upper:]' '[:lower:]')"
  ARCH="$(uname -m)"
  if [[ "$ARCH" == "arm64" || "$ARCH" == "aarch64" ]]; then
    ARCH="arm64"
  else
    ARCH="amd64"
  fi
  local TARBALL="go${GO_VERSION}.${OS_LOWER}-${ARCH}.tar.gz"
  local URL="https://go.dev/dl/${TARBALL}"
  warn "Downloading Go ${GO_VERSION} from ${URL}..."
  curl -fsSL "$URL" -o "/tmp/${TARBALL}" && \
    sudo rm -rf /usr/local/go && \
    sudo tar -C /usr/local -xzf "/tmp/${TARBALL}" && \
    rm -f "/tmp/${TARBALL}"
  export PATH="$PATH:/usr/local/go/bin"
  ok "Go ${GO_VERSION} installed at /usr/local/go"
}

if ! command -v go >/dev/null 2>&1; then
  if [[ "$PKG_MGR" == "brew" ]]; then
    warn "Go not found — installing via Homebrew..."
    brew install go
  else
    install_go
  fi
else
  ok "Go $(go version | awk '{print $3}') already installed"
fi

# Ensure GOPATH/bin is in PATH for this session and future shells
export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin"

# Persist GOPATH/bin to shell profile if not already present
SHELL_PROFILE="$HOME/.zshrc"
[[ -f "$HOME/.bash_profile" ]] && SHELL_PROFILE="$HOME/.bash_profile"
if ! grep -q 'GOPATH/bin' "$SHELL_PROFILE" 2>/dev/null; then
  echo '' >> "$SHELL_PROFILE"
  echo '# Go binaries' >> "$SHELL_PROFILE"
  echo 'export GOPATH="$HOME/go"' >> "$SHELL_PROFILE"
  echo 'export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin"' >> "$SHELL_PROFILE"
  ok "Added GOPATH/bin to $SHELL_PROFILE"
fi

# Helper: install a Go binary tool via go install
install_go_binary() {
  local name=$1
  local pkg=$2
  if command -v "$name" >/dev/null 2>&1; then
    ok "$name already installed"
  else
    warn "Installing $name via go install..."
    go install "$pkg" 2>/dev/null && ok "$name installed" || warn "Failed to install $name — install manually: go install $pkg"
  fi
}

header "[2/8] Checking Node.js version..."
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
# 3. Phase 1 Tools — Web/API Offensive
# ─────────────────────────────────────────────────────────────
header "[3/8] Installing Phase 1 tools (Web/API Offensive)..."

# Go-based tools — install via go install on ALL platforms
install_go_binary "nuclei"      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
install_go_binary "ffuf"        "github.com/ffuf/ffuf/v2@latest"
install_go_binary "amass"       "github.com/owasp-amass/amass/v4/...@master"
install_go_binary "subfinder"   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_binary "httpx"       "github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_go_binary "feroxbuster" "github.com/epi052/feroxbuster@latest" 2>/dev/null || \
  install_pkg "feroxbuster"  # feroxbuster is Rust-based — brew fallback

# Non-Go tools via package manager
install_pkg "sqlmap"
install_pkg "semgrep"
install_pkg "whatweb"  # Web fingerprinting (Ruby-based, available in brew/apt)

# jwt_tool — JWT security testing CLI
if ! command -v jwt_tool >/dev/null 2>&1; then
  warn "Installing jwt_tool (pip)..."
  pip3 install jwt-tool --break-system-packages 2>/dev/null || pip3 install jwt-tool 2>/dev/null && ok "jwt_tool installed" || warn "jwt_tool install failed — run: pip3 install jwt-tool"
else
  ok "jwt_tool already installed"
fi

# ─────────────────────────────────────────────────────────────
# 4. Phase 2 Tools — Cloud Offensive
# ─────────────────────────────────────────────────────────────
header "[4/8] Installing Phase 2 tools (Cloud Offensive)..."
install_pkg "awscli"
install_pip "trufflehog"
install_pip "scoutsuite"
install_pip "pacu"

# ─────────────────────────────────────────────────────────────
# 5. Phase 3 Tools — Active Directory Offensive
# ─────────────────────────────────────────────────────────────
header "[5/8] Installing Phase 3 tools (Active Directory Offensive)..."
install_pip "impacket"
install_pip "bloodhound"

if ! command -v crackmapexec >/dev/null 2>&1 && ! command -v cme >/dev/null 2>&1; then
  install_pip "crackmapexec"
fi

# Kerbrute — Go binary, auto-installed
install_go_binary "kerbrute" "github.com/ropnop/kerbrute@latest"

# ─────────────────────────────────────────────────────────────
# 6. Phase 4 Tools — Network Offensive
# ─────────────────────────────────────────────────────────────
header "[6/8] Installing Phase 4 tools (Network Offensive)..."
NETWORK_TOOLS=("nmap" "masscan" "bettercap" "hydra" "dnsx")
for tool in "${NETWORK_TOOLS[@]}"; do install_pkg "$tool"; done
# dnsx is also available as a Go binary fallback
command -v dnsx >/dev/null 2>&1 || install_go_binary "dnsx" "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"

# ─────────────────────────────────────────────────────────────
# 7. Global / Utility Dependencies
# ─────────────────────────────────────────────────────────────
header "[7/8] Installing Global / Utility Dependencies..."

# ripgrep (rg) — fast text search used by OpenClaw code tools
if ! command -v rg >/dev/null 2>&1; then
  if [[ "$PKG_MGR" == "brew" ]]; then
    brew install ripgrep
  else
    $INSTALL_CMD ripgrep 2>/dev/null || warn "ripgrep install failed — install manually: apt install ripgrep"
  fi
else
  ok "rg (ripgrep) already installed"
fi

# signal-cli — Signal messaging channel for OpenClaw
if ! command -v signal-cli >/dev/null 2>&1; then
  if [[ "$PKG_MGR" == "brew" ]]; then
    brew install signal-cli
  else
    warn "signal-cli: on Linux install via: https://github.com/AsamK/signal-cli/releases"
  fi
else
  ok "signal-cli already installed"
fi

# xurl — X/Twitter URL resolver CLI
if ! command -v xurl >/dev/null 2>&1; then
  if [[ "$PKG_MGR" == "brew" ]]; then
    brew install --cask xurl 2>/dev/null || brew install xurl 2>/dev/null || warn "xurl install failed — install manually from https://github.com/xdevplatform/xurl"
  else
    warn "xurl: download from https://github.com/xdevplatform/xurl/releases"
  fi
else
  ok "xurl already installed"
fi

# pnpm
if ! command -v pnpm >/dev/null 2>&1; then
  warn "pnpm not found. Installing..."
  npm install -g pnpm || { err "pnpm installation failed."; exit 1; }
fi

# ─────────────────────────────────────────────────────────────
# 8. Project Build & Config
# ─────────────────────────────────────────────────────────────
header "[8/8] Initializing OpenClaw project..."

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
echo "  3. (Signal channel) Register signal-cli with your phone number:"
echo "     signal-cli -a +<YOUR_PHONE_NUMBER> register"
echo "     signal-cli -a +<YOUR_PHONE_NUMBER> verify <CODE>"
echo "     Then set channels.signal.phoneNumber in openclaw.json"
echo "  4. (Slack channel) Add your Slack Bot + App token in openclaw.json:"
echo "     channels.slack.botToken and channels.slack.appToken"
echo "  5. Activate the Red Team Agent:"
echo "     pnpm openclaw agent --activation red-team"
echo ""
warn "Security reminder: Only test systems you are authorized to test."
echo "──────────────────────────────────────────────────────"
