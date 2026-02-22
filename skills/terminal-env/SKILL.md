---
name: terminal-env
description: |
  Interactive terminal environment management for red team operations. Provides sandboxed shell
  execution, persistent session management, command history tracking, multi-session parallel
  execution, and output capture for evidence collection. Supports bash, zsh, Python REPL, and
  tmux-based session persistence across engagement phases. Ensures all commands are logged with
  timestamps for the engagement audit trail.
metadata:
  {
    "openclaw":
      {
        "emoji": "💻",
        "requires": { "bins": ["bash", "python3"] },
        "install":
          [
            {
              "id": "brew-tmux",
              "kind": "brew",
              "formula": "tmux",
              "bins": ["tmux"],
              "label": "Install tmux for session persistence (brew)"
            }
          ],
      },
  }
---

# Terminal Environments — Interactive Shell Management

Managed, logged shell sessions for command execution, tool interaction, and audit trails.

## Usage

### 1. Persistent Engagement Session (tmux)

```bash
# Start a named engagement session
tmux new-session -d -s engagement -x 220 -y 50

# Create windows for each domain
tmux new-window -t engagement -n recon
tmux new-window -t engagement -n web
tmux new-window -t engagement -n ad
tmux new-window -t engagement -n cloud

# Attach
tmux attach-session -t engagement

# Send command to a specific window
tmux send-keys -t engagement:recon "subfinder -d target.com" Enter

# List all sessions
tmux ls
```

---

### 2. Command Execution with Audit Logging

```bash
# Log all commands with timestamps
exec > >(tee -a "logs/engagement_$(date +%Y%m%d_%H%M%S).log") 2>&1
set -x  # trace all commands

# Or use the OpenClaw logger wrapper
function claw() {
    local cmd="$*"
    local ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "[CMD $ts] $cmd" >> logs/command_history.log
    eval "$cmd" 2>&1 | tee -a "logs/output_$(date +%Y%m%d).log"
}
claw nmap -sV 192.168.1.10
```

---

### 3. Parallel Tool Execution

```bash
# Run multiple tools simultaneously
(nuclei -u https://target.com -severity critical -o nuclei.txt &)
(subfinder -d target.com -o subs.txt &)
(nmap -sV 192.168.1.0/24 -oA network_scan &)
wait
echo "[*] All scans complete"
```

---

### 4. Interactive Shell for Specific Tools

```bash
# Python REPL with security libraries pre-loaded
python3 -c "
import requests, json
s = requests.Session()
s.headers['Authorization'] = 'Bearer YOUR_TOKEN'
# Now interactive REST testing
"

# SQLmap interactive
sqlmap -u "https://target.com?id=1" --level=3 --risk=2 --dbs --batch

# Metasploit console
msfconsole -q -x "use exploit/multi/handler; set LHOST 0.0.0.0; set LPORT 4444; run"
```

---

### 5. Evidence Collection Shell

```bash
#!/usr/bin/env bash
# Capture command + output as evidence
EVIDENCE_DIR="evidence/$(date +%Y%m%d)"
mkdir -p "$EVIDENCE_DIR"

capture() {
    local label="$1"; shift
    local outfile="$EVIDENCE_DIR/${label}_$(date +%H%M%S).txt"
    echo "=== Command: $* ===" > "$outfile"
    echo "=== Timestamp: $(date -u) ===" >> "$outfile"
    echo "=== Output ===" >> "$outfile"
    "$@" 2>&1 | tee -a "$outfile"
    echo "[*] Evidence saved: $outfile"
}

capture "nmap_scan"    nmap -sV 192.168.1.10
capture "nuclei_scan"  nuclei -u https://target.com -severity critical
capture "sqlmap"       sqlmap -u "https://target.com?id=1" --dbs --batch
```

---

### 6. Reverse Shell / Listener Management

```bash
# Start listener (authorized testing only)
nc -lvnp 4444

# Verify connectivity before exploitation
nc -zv TARGET_IP PORT

# Netcat listener with output capture
nc -lvnp 4444 | tee shells/session_$(date +%H%M%S).log
```

---

## Usage from Red Team Agent

```
Open a new terminal session for the engagement and set up audit logging
Run nmap, nuclei, and subfinder in parallel against 192.168.1.0/24
Start a tmux session with separate windows for recon, web, AD, and cloud testing
Capture all command output as evidence for the report
Set up a netcat listener on port 4444 for the lab environment
```
