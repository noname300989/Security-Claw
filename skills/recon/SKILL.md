---
name: recon
description: |
  Automated OSINT and attack surface mapping engine. Performs passive and active reconnaissance
  to enumerate the full attack surface of a target: subdomain discovery, DNS enumeration, port 
  scanning, technology fingerprinting, email harvesting, GitHub/GitLab secrets, cloud asset 
  discovery, Shodan/Censys intelligence, WHOIS analysis, certificate transparency logs, and
  Google dorking. Results are normalized and fed into subsequent attack phases. Maps to
  MITRE ATT&CK Reconnaissance (TA0043) tactics.
metadata:
  {
    "openclaw":
      {
        "emoji": "🔭",
        "requires": { "bins": ["python3"] },
        "install":
          [
            {
              "id": "brew-recon-tools",
              "kind": "shell",
              "cmd": "brew install subfinder httpx amass nmap && pip3 install theHarvester shodan",
              "bins": ["subfinder", "httpx", "amass", "nmap"],
              "label": "Install OSINT and recon tools (brew + pip)",
            },
          ],
      },
  }
---

# Reconnaissance — Automated OSINT & Attack Surface Mapping

Full-scope passive and active reconnaissance pipeline from target to attack surface inventory.

## Reconnaissance Pipeline

```
Target Domain / IP
       ↓
[1] Passive Recon (OSINT, no direct target contact)
       ↓
[2] Subdomain Enumeration (DNS, CT logs, brute-force)
       ↓
[3] HTTP Probing (live host detection, tech fingerprint)
       ↓
[4] Port & Service Discovery (active scanning)
       ↓
[5] Cloud Asset Discovery (S3, Azure, GCP)
       ↓
[6] Secret & Credential Leakage (GitHub, Pastebin)
       ↓
[7] Attack Surface Report
```

## Capabilities

### 1. Passive OSINT (No direct contact)

Gather intelligence without touching the target.

**Usage:**

> Perform passive OSINT on target.com — no direct contact with target systems

```bash
# WHOIS
whois target.com

# Certificate Transparency Logs (crt.sh)
curl -s "https://crt.sh/?q=%.target.com&output=json" \
  | python3 -c "import json,sys; [print(r['name_value']) for r in json.load(sys.stdin)]" \
  | sort -u > ct_subs.txt

# DNS history / passive DNS
curl -s "https://api.securitytrails.com/v1/history/target.com/dns/a" \
  -H "APIKEY: $SECURITYTRAILS_KEY" | python3 -m json.tool

# Google dorking
site:target.com ext:env OR ext:sql OR ext:log OR ext:bak
site:target.com intext:"api_key" OR intext:"secret" OR intext:"password"
```

**MITRE ATT&CK:** T1596 — Search Open Technical Databases

---

### 2. Subdomain Enumeration

Discover all subdomains of the target.

**Usage:**

> Enumerate all subdomains of target.com and identify which are live

```bash
# Method 1: subfinder (passive DNS intelligence)
subfinder -d target.com -o subs_passive.txt -v

# Method 2: amass (comprehensive, active + passive)
amass enum -d target.com -o subs_amass.txt

# Method 3: Certificate transparency
curl -s https://crt.sh/?q=%.target.com&output=json \
  | python3 -c "import json,sys;[print(e['name_value']) for e in json.load(sys.stdin)]" \
  | sort -u >> subs_all.txt

# Combine and deduplicate
cat subs_passive.txt subs_amass.txt subs_all.txt | sort -u > all_subs.txt
echo "[*] Total unique subdomains: $(wc -l < all_subs.txt)"
```

**MITRE ATT&CK:** T1590.001 — IP Addresses, T1590.005 — IP Addresses/DNS

---

### 3. HTTP Probing & Technology Fingerprinting

Identify which subdomains are live and what technologies they run.

**Usage:**

> Probe all discovered subdomains and fingerprint their technology stack

```bash
# httpx — fast probe with tech detection
httpx -l all_subs.txt -o live_hosts.txt \
  -tech-detect -title -status-code -content-length -ip \
  -json -o live_hosts.json

# Check for interesting status codes
httpx -l all_subs.txt -mc 200,201,301,302,401,403 -o interesting.txt

# Technology summary
cat live_hosts.json | python3 -c "
import json, sys
from collections import Counter
techs = Counter()
for line in sys.stdin:
    for t in json.loads(line).get('tech', []):
        techs[t] += 1
for t, n in techs.most_common(20):
    print(f'  {n:4d}x {t}')
"
```

**MITRE ATT&CK:** T1592 — Gather Victim Host Information

---

### 4. Port & Service Discovery

Scan live hosts for open ports and identify services.

**Usage:**

> Scan the discovered live hosts for open ports and vulnerable services

```bash
# Fast port scan (masscan)
masscan -iL live_hosts.txt -p0-65535 --rate 10000 -oG masscan.out

# Detailed service detection on discovered ports (nmap)
nmap -iL live_hosts.txt -sV -sC -O \
  -p 21,22,25,53,80,110,143,389,443,445,3306,3389,5432,6379,8080,8443,27017 \
  -oA nmap_services --open

# NSE vulnerability scripts
nmap -iL live_hosts.txt --script=vuln -p 80,443,8080 -oA nmap_vulns
```

**MITRE ATT&CK:** T1595.001 — Active Scanning: Scanning IP Blocks

---

### 5. Cloud Asset Discovery

Find S3 buckets, Azure blobs, GCP storage linked to the target.

**Usage:**

> Discover and test for misconfigured cloud storage assets for target.com

```bash
# S3 bucket enumeration (common naming patterns)
python3 - <<'EOF'
import requests
company = "target"
patterns = [
    f"{company}", f"{company}-dev", f"{company}-prod", f"{company}-backup",
    f"{company}-assets", f"{company}-uploads", f"{company}-data",
    f"dev-{company}", f"prod-{company}", f"api-{company}",
]
for bucket in patterns:
    url = f"https://{bucket}.s3.amazonaws.com"
    r = requests.head(url, timeout=5)
    status = r.status_code
    if status == 200:
        print(f"[PUBLIC] {url}")
    elif status == 403:
        print(f"[EXISTS-PRIVATE] {url}")
    elif status == 301:
        print(f"[REDIRECT] {url} → {r.headers.get('Location','?')}")
EOF

# TruffleHog for cloud secrets
trufflehog github --org=target-org --only-verified
trufflehog s3 --bucket=target-bucket
```

**MITRE ATT&CK:** T1530 — Data from Cloud Storage Object

---

### 6. GitHub / GitLab Secret Scanning

**Usage:**

> Search target's GitHub repositories for leaked API keys, credentials, and secrets

```bash
# TruffleHog GitHub scan
trufflehog github --org=target-org --only-verified --json > github_secrets.json

# GitLeaks on cloned repo
git clone https://github.com/target-org/target-repo
gitleaks detect --source ./target-repo --report-format json --report-path leaks.json

# Manual GitHub search (API)
curl -H "Authorization: token $GITHUB_TOKEN" \
  "https://api.github.com/search/code?q=target.com+password+in:file" \
  | python3 -m json.tool
```

**MITRE ATT&CK:** T1552.001 — Credentials in Files

---

### 7. Email Harvesting

```bash
# theHarvester
theHarvester -d target.com -l 500 -b google,bing,shodan,linkedin -f harvest.html

# Hunter.io API
curl "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=$HUNTER_KEY" \
  | python3 -m json.tool
```

**MITRE ATT&CK:** T1589.002 — Email Addresses

---

### 8. Shodan Intelligence

```bash
# Shodan CLI
shodan search "hostname:target.com" --fields ip_str,port,org,product

# Find target infrastructure
shodan search "org:'Target Corporation'" --fields ip_str,port,hostnames

# Shodan Python
python3 - <<'EOF'
import shodan
api = shodan.Shodan("$SHODAN_KEY")
results = api.search("hostname:target.com")
for r in results["matches"]:
    print(f"{r['ip_str']}:{r['port']} — {r.get('product','?')} ({r.get('data','')[:60]})")
EOF
```

**MITRE ATT&CK:** T1596.005 — Scan Databases

---

### 9. Full Automated Recon Pipeline

```bash
#!/usr/bin/env bash
TARGET="$1"
echo "[*] Starting full recon for: $TARGET"
mkdir -p "recon/$TARGET"

# Subdomains
subfinder -d "$TARGET" -o "recon/$TARGET/subs.txt" -silent
amass enum -passive -d "$TARGET" >> "recon/$TARGET/subs.txt"

# CT logs
curl -s "https://crt.sh/?q=%.$TARGET&output=json" \
  | python3 -c "import json,sys;[print(r['name_value']) for r in json.load(sys.stdin)]" \
  >> "recon/$TARGET/subs.txt"

sort -u "recon/$TARGET/subs.txt" -o "recon/$TARGET/subs_all.txt"
echo "[*] Subdomains: $(wc -l < recon/$TARGET/subs_all.txt)"

# HTTP probe
httpx -l "recon/$TARGET/subs_all.txt" -o "recon/$TARGET/live.txt" \
  -tech-detect -silent -status-code -title

# Port scan
nmap -iL "recon/$TARGET/live.txt" \
  -p 22,80,443,8080,8443,3306,5432,6379,27017 \
  -sV --open -oA "recon/$TARGET/nmap" -T4

echo "[*] Recon complete. Results in: recon/$TARGET/"
```

## Usage from Red Team Agent

```
Run full passive OSINT on target.com — no direct contact
Enumerate all subdomains for target.com and probe which are live
Scan live hosts for open ports and identify vulnerable services
Search GitHub for leaked credentials related to target.com
Check for misconfigured S3 buckets for target-company
Generate a complete attack surface report for target.com
```
