---
name: recon-auto-feed
description: |
  Recon automation pipeline that feeds structured output directly into your manual testing
  workflow. Runs subdomain enumeration, live host probing, technology fingerprinting, and
  endpoint discovery — then surfaces the most interesting targets for you to test manually.
  Designed as a pre-work companion: you come back to a prioritized hit-list, not raw data.
metadata:
  {
    "openclaw":
      {
        "emoji": "📡",
        "requires": { "bins": ["subfinder", "httpx", "nmap", "nuclei", "ffuf", "whatweb"] },
        "install":
          [
            {
              "id": "recon-feed-macos",
              "kind": "shell",
              "cmd": "brew install subfinder httpx nmap nuclei ffuf whatweb",
              "bins": ["subfinder", "httpx", "nmap", "nuclei", "ffuf"],
              "label": "Install recon tools (macOS via brew)",
              "when": "platform == 'darwin'",
            },
            {
              "id": "recon-feed-linux",
              "kind": "shell",
              "cmd": "sudo apt-get install -y nmap ffuf whatweb 2>/dev/null || true && go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
              "bins": ["subfinder", "httpx", "nmap", "nuclei", "ffuf"],
              "label": "Install recon tools (Linux via apt + Go)",
              "when": "platform == 'linux'",
            },
            {
              "id": "recon-feed-windows",
              "kind": "shell",
              "cmd": "choco install nmap ffuf -y && go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
              "bins": ["subfinder", "httpx", "nmap", "nuclei", "ffuf"],
              "label": "Install recon tools (Windows via choco + Go)",
              "when": "platform == 'win32'",
            },
          ],
      },
  }
---

# Recon Auto-Feed — Pre-Work Companion for Manual Testing

Runs all recon automation while you sleep. Comes back with a prioritized hit-list of the
most interesting targets, endpoints, and technology findings ready for your manual testing.

## When to Use

✅ **USE this skill when:**

- Starting a new engagement or picking a new program target
- You want recon done before you start manual testing
- You need a prioritized list of interesting endpoints and tech stacks
- You want to refresh recon for a program you've tested before

---

## Quick Start

```
Run full recon on example.com and give me a prioritized testing list
Do recon on *.shopify.com — highlight anything interesting for manual testing
Refresh the recon data for my Bugcrowd program target.com
```

---

## Pipeline

```
Target Domain
    ↓
[1] Subdomain Enum     → subs.txt
    ↓
[2] Live Probe         → live.txt + tech.json
    ↓
[3] Endpoint Discovery → endpoints.txt
    ↓
[4] JS Secrets Scan    → secrets.txt
    ↓
[5] Quick Nuclei Pass  → interesting.txt
    ↓
[6] Prioritized Output → RECON_BRIEF.md  ← you start here
```

---

## Step 1 — Subdomain Enumeration

```bash
# Passive sources (no target contact)
subfinder -d TARGET -o recon/subs_passive.txt -silent -all

# Certificate transparency
curl -s "https://crt.sh/?q=%.TARGET&output=json" \
  | python3 -c "import json,sys;[print(r['name_value']) for r in json.load(sys.stdin)]" \
  | sort -u >> recon/subs_ct.txt

# Deduplicate all sources
cat recon/subs_passive.txt recon/subs_ct.txt \
  | sort -u | grep -v "^\*" > recon/subs_all.txt

echo "[*] Total subdomains: $(wc -l < recon/subs_all.txt)"
```

---

## Step 2 — Live Host Probing

```bash
# Fast live probe with tech fingerprinting
httpx -l recon/subs_all.txt \
  -rate-limit 5 \
  -tech-detect -title -status-code -content-length -ip -cdn \
  -json -o recon/live.json \
  -o recon/live.txt

# Extract interesting status codes
cat recon/live.json \
  | python3 -c "
import json, sys
for line in sys.stdin:
    h = json.loads(line)
    sc = h.get('status_code', 0)
    if sc in [200, 401, 403, 302]:
        print(f\"{sc} | {h.get('url','')} | {', '.join(h.get('tech',[])[:3])} | {h.get('title','')}\")
" | sort > recon/live_summary.txt
```

---

## Step 3 — Endpoint Discovery

```bash
# Parameter fuzzing on all live hosts
while read host; do
  ffuf -u "$host/FUZZ" \
    -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
    -rate 10 -mc 200,201,301,302,401,403 \
    -o "recon/dirs_$(echo $host | sed 's/[^a-z0-9]/_/g').json" \
    -of json -t 1 2>/dev/null
done < recon/live.txt

# JS file discovery
cat recon/live.json | python3 -c "
import json, sys
for line in sys.stdin:
    print(json.loads(line).get('url',''))
" | while read url; do
  curl -s "$url" | grep -oE 'src=\"[^\"]+\.js\"' | grep -oE '\"[^\"]+\"' \
    | tr -d '"' >> recon/js_files.txt
done
```

---

## Step 4 — JS Secrets Scanning

```bash
# Download and scan JS files for secrets
cat recon/js_files.txt | while read jsfile; do
  curl -s "$jsfile" -o "/tmp/jsfile.js"
  # Look for API keys, tokens, endpoints
  grep -oE "(api_key|apikey|api-key|token|secret|password|key)\s*[=:]\s*['\"][^'\"]{8,}['\"]" \
    /tmp/jsfile.js >> recon/js_secrets.txt
  # Internal endpoints
  grep -oE '(https?://[a-z0-9.-]+\.[a-z]{2,}/[/a-z0-9_-]*)' \
    /tmp/jsfile.js >> recon/internal_endpoints.txt
done

cat recon/js_secrets.txt | sort -u > recon/secrets_unique.txt
echo "[*] Potential secrets: $(wc -l < recon/secrets_unique.txt)"
```

---

## Step 5 — Quick Nuclei Pass (Non-Intrusive)

```bash
# Passive + exposure templates only (no active attack)
nuclei -l recon/live.txt \
  -tags exposure,misconfiguration,takeover,info \
  -severity medium,high,critical \
  -rate-limit 3 \
  -json -o recon/nuclei_quick.json

# Count by severity
cat recon/nuclei_quick.json \
  | python3 -c "
import json, sys
from collections import Counter
sev = Counter(json.loads(l)['info']['severity'] for l in sys.stdin if l.strip())
for s, n in sev.most_common():
    print(f'  {s.upper():10} {n}')
"
```

---

## Step 6 — Prioritized Recon Brief

The agent generates `RECON_BRIEF.md` — your starting point for manual testing:

```markdown
# Recon Brief — example.com

Generated: 2026-02-23 13:05 IST

## Attack Surface Summary

- Total subdomains: 234
- Live hosts: 47
- Interesting (4xx/30x): 23
- JS secrets found: 3
- Nuclei findings: 5 (2 high, 3 medium)

## 🎯 Top Targets for Manual Testing

### Priority 1 — Most Interesting

| Host                | Why Interesting                            |
| ------------------- | ------------------------------------------ |
| api.example.com     | REST API, no CDN, jQuery 1.x (known vulns) |
| admin.example.com   | 403 (access control!), WordPress admin     |
| staging.example.com | 200, staging env, likely dev creds         |
| legacy.example.com  | PHP 5.6, Apache 2.2 — very old stack       |

### Priority 2 — Test These Next

| Host                 | Why Interesting           |
| -------------------- | ------------------------- |
| auth.example.com     | SSO endpoint, OAuth flows |
| payments.example.com | PCI scope, high value     |

## 🔑 Potential Secrets Found (Verify Manually)

- Line 47 in /static/app.js: `api_key = "AIzaSy..."`
- Line 122 in /bundle.js: `secret: "sk_live_..."`

## ⚠️ Quick Wins (Nuclei Flagged)

- [HIGH] admin.example.com — Exposed admin panel (/.git/)
- [MEDIUM] legacy.example.com — PHP info disclosure (/phpinfo.php)

## 📝 Technology Map

| Stack           | Hosts         |
| --------------- | ------------- |
| React + Node.js | api, app, www |
| WordPress       | blog, news    |
| PHP 5.x         | legacy        |
| Java Spring     | payments      |
```

---

## Re-Running Recon

```
Refresh recon for example.com — what's changed since last week?
Compare today's recon with last session — any new subdomains?
Run a quick recon refresh on the top 10 targets from the brief
```

---

## Usage from Agent

```
Run full recon on example.com and generate a testing brief for me
Do subdomain enum on *.target.com and show me which ones are most interesting
Scan the live hosts for secrets in JS files
Run the quick Nuclei pass on recon/live.txt and show me any easy wins
Generate a prioritized recon brief from the data in recon/
```
