---
name: threat-intel
description: |
  Live threat intelligence scraper that gathers the latest security information from authoritative
  web sources. Pulls real-time CVEs from NVD/CISA, public exploits from Exploit-DB and Packet Storm,
  security advisories from vendor feeds, OWASP project updates, nuclei template releases, and
  threat actor TTPs from open-source intelligence sources. Feeds fresh intelligence directly into
  active assessments so findings are always backed by current data.
metadata:
  {
    "openclaw":
      {
        "emoji": "📡",
        "requires": { "bins": ["python3", "curl"] },
        "install":
          [
            {
              "id": "pip-scraper-deps",
              "kind": "shell",
              "cmd": "pip3 install requests beautifulsoup4 feedparser lxml httpx rich",
              "bins": [],
              "label": "Install scraper dependencies (pip)"
            }
          ],
      },
  }
---

# Threat Intelligence Scraper Skill

Real-time web scraping of authoritative security sources to keep every assessment backed
by the latest vulnerability data, exploit code, and threat actor intelligence.

## Sources Scraped

| Source | Data | URL |
|---|---|---|
| **NVD API v2** | Latest CVEs + CVSS scores | nvd.nist.gov/developers |
| **CISA KEV** | Known Exploited Vulnerabilities catalog | cisa.gov/known-exploited-vulnerabilities-catalog |
| **Exploit-DB** | Public exploit code (searchsploit) | exploit-db.com |
| **Packet Storm** | CVE-linked exploit releases | packetstormsecurity.com |
| **OWASP** | Top 10 updates, new projects | owasp.org |
| **Nuclei Templates** | Latest community templates | github.com/projectdiscovery/nuclei-templates |
| **GitHub Security Advisories** | OSS dependency vulns | github.com/advisories |
| **Shodan Trends** | Internet exposure statistics | trends.shodan.io (via API) |
| **GreyNoise** | Mass-scanning IPs & campaign activity | api.greynoise.io |
| **AlienVault OTX** | Threat indicators (IPs, domains, hashes) | otx.alienvault.com |
| **AttackerKB** | Exploitability assessments | attackerkb.com |
| **HackerNews / RSS** | Security community discussions | hn.algolia.com |

---

## Capabilities

### 1. Latest CVE Feed (NVD + CISA KEV)
Fetch the most recently published and modified CVEs, prioritized by CISA "Known Exploited" status.

**Usage:**
> Get the latest critical CVEs published in the last 7 days

**Usage:**
> Check if CVE-2024-XXXXX is in the CISA Known Exploited Vulnerabilities catalog

**Python snippet:**
```python
import requests, json

# NVD API v2 — latest critical CVEs (last 7 days)
def get_latest_cves(days=7, severity="CRITICAL"):
    from datetime import datetime, timedelta, timezone
    start = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000")
    end   = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
    url = (
        f"https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?pubStartDate={start}&pubEndDate={end}"
        f"&cvssV3Severity={severity}"
    )
    resp = requests.get(url, timeout=30, headers={"User-Agent": "SecurityResearch/1.0"})
    resp.raise_for_status()
    data = resp.json()
    return data.get("vulnerabilities", [])

# CISA KEV catalog
def get_cisa_kev():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    return resp.json().get("vulnerabilities", [])

cves = get_latest_cves(days=7)
kev  = get_cisa_kev()
kev_ids = {v["cveID"] for v in kev}

for item in cves[:10]:
    cve_id = item["cve"]["id"]
    desc   = item["cve"]["descriptions"][0]["value"][:120]
    in_kev = "⚠️ ACTIVELY EXPLOITED (CISA KEV)" if cve_id in kev_ids else ""
    print(f"{cve_id} {in_kev}\n  {desc}\n")
```

---

### 2. Exploit-DB Search (searchsploit)
Search for public exploit code matching a product, CVE, or technology.

**Usage:**
> Find public exploits for Apache 2.4.49

**Usage:**
> Search for exploits matching CVE-2024-XXXXX on Exploit-DB

**Commands:**
```bash
# CLI via searchsploit (requires exploitdb package)
searchsploit apache 2.4.49
searchsploit --cve CVE-2024-12345

# Install searchsploit
brew install exploitdb   # macOS
# or: apt install exploitdb  (Kali/Debian)
```

**Python snippet (Exploit-DB JSON API):**
```python
import requests

def search_exploitdb(query):
    url = f"https://www.exploit-db.com/search?q={query}&type=exploits"
    headers = {
        "Accept": "application/json",
        "User-Agent": "SecurityResearch/1.0",
        "X-Requested-With": "XMLHttpRequest"
    }
    resp = requests.get(url, headers=headers, timeout=20)
    return resp.json().get("data", [])

results = search_exploitdb("log4j")
for r in results[:5]:
    print(f"[{r['id']}] {r['description']} — {r['platform']} — {r['date_published']}")
```

---

### 3. Nuclei Template Updates
Fetch the latest released Nuclei templates from the official community repository.

**Usage:**
> Update Nuclei templates and show what's new this week

**Commands:**
```bash
# Update templates (if nuclei installed)
nuclei -update-templates

# List recently added templates
nuclei -list -stats

# Show templates added in last 7 days via GitHub API
curl -s "https://api.github.com/repos/projectdiscovery/nuclei-templates/commits?since=$(date -u -v-7d +%Y-%m-%dT%H:%M:%SZ)&per_page=50" \
  | python3 -c "import json,sys; [print(c['commit']['message'][:100]) for c in json.load(sys.stdin)]"
```

---

### 4. OWASP Project Feed
Scrape OWASP's website and GitHub for updated Top 10 lists, new projects, and blog posts.

**Usage:**
> Check if there are any OWASP Top 10 updates published this month

**Python snippet:**
```python
import feedparser

# OWASP blog RSS
feed = feedparser.parse("https://owasp.org/feed.xml")
for entry in feed.entries[:5]:
    print(f"{entry.published[:10]} — {entry.title}")
    print(f"  {entry.link}\n")

# OWASP GitHub releases (e.g. new Top 10 documents)
import requests
for repo in ["www-project-top-ten", "www-project-api-security", "www-project-llm-top-10"]:
    url = f"https://api.github.com/repos/OWASP/{repo}/releases/latest"
    r = requests.get(url, timeout=15, headers={"User-Agent": "SecurityResearch/1.0"})
    if r.status_code == 200:
        rel = r.json()
        print(f"OWASP/{repo}: {rel.get('tag_name','?')} — {rel.get('published_at','?')[:10]}")
```

---

### 5. GitHub Security Advisories (GHSA)
Fetch GitHub Security Advisories for open-source packages and ecosystems.

**Usage:**
> Get the latest critical GitHub Security Advisories for npm packages

**Commands:**
```bash
# GraphQL query via curl (requires GITHUB_TOKEN)
curl -H "Authorization: bearer $GITHUB_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"query":"{ securityAdvisories(first:10, orderBy:{field:PUBLISHED_AT,direction:DESC}) { nodes { ghsaId summary severity publishedAt } } }"}' \
     https://api.github.com/graphql
```

---

### 6. AlienVault OTX Threat Indicators
Pull indicators of compromise (IPs, domains, file hashes) from AlienVault Open Threat Exchange.

**Usage:**
> Get the latest threat indicators for ransomware campaigns from AlienVault OTX

**Python snippet:**
```python
import requests

OTX_API_KEY = "YOUR_OTX_API_KEY"  # Free at otx.alienvault.com

def get_otx_pulses(limit=10):
    url = f"https://otx.alienvault.com/api/v1/pulses/subscribed?limit={limit}"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    resp = requests.get(url, headers=headers, timeout=20)
    resp.raise_for_status()
    return resp.json().get("results", [])

pulses = get_otx_pulses()
for p in pulses:
    print(f"[{p['created'][:10]}] {p['name']}")
    print(f"  Tags: {', '.join(p.get('tags', [])[:5])}")
    ioc_count = sum(len(i.get('indicators', [])) for i in [p])
    print(f"  Indicators: {ioc_count}\n")
```

---

### 7. GreyNoise Mass-Scanning Intelligence
Identify IPs actively scanning the internet for specific vulnerabilities or services.

**Usage:**
> Check which IPs are actively scanning for Log4j vulnerabilities right now

**Commands:**
```bash
# GreyNoise Community API (free tier)
curl -H "key: $GREYNOISE_API_KEY" \
  "https://api.greynoise.io/v3/community/1.2.3.4"

# GNQL query for active scanners (paid)
curl -H "key: $GREYNOISE_API_KEY" \
  "https://api.greynoise.io/v2/experimental/gnql?query=tags:log4j-attempt+last_seen:1d"
```

---

### 8. Packet Storm Security Feed
Scrape Packet Storm for the latest exploits, advisories, and security papers.

**Usage:**
> Get today's latest exploit releases from Packet Storm Security

**Python snippet:**
```python
import feedparser

feed = feedparser.parse("https://rss.packetstormsecurity.com/files/")
for entry in feed.entries[:10]:
    print(f"{entry.published[:10]} — {entry.title}")
    print(f"  {entry.link}\n")
```

---

### 9. Full Intelligence Refresh
Run a comprehensive scrape of all sources and return a unified threat briefing.

**Usage:**
> Run a full threat intelligence refresh and give me today's security briefing

**Output includes:**
- 🔴 Critical CVEs (CVSS ≥ 9.0) from last 48h
- ⚠️ CISA KEV additions from last 7 days
- 🎯 New public exploits on Exploit-DB / Packet Storm
- 📋 Updated Nuclei templates
- 🌐 Active scanning campaigns (GreyNoise)
- 🚨 Latest threat actor pulse (AlienVault OTX)

---

## Quick Reference

```bash
# Run full intel refresh (Python)
python3 - <<'EOF'
import requests, feedparser
from datetime import datetime, timedelta, timezone

# CISA KEV
kev = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json").json()
recent_kev = [v for v in kev["vulnerabilities"] if v.get("dateAdded","") >= (datetime.now()-timedelta(days=7)).strftime("%Y-%m-%d")]
print(f"\n🚨 CISA KEV additions (last 7 days): {len(recent_kev)}")
for v in recent_kev[:5]:
    print(f"  {v['cveID']}: {v['vulnerabilityName']}")

# NVD critical CVEs
now = datetime.now(timezone.utc)
start = (now - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%S.000")
end = now.strftime("%Y-%m-%dT%H:%M:%S.000")
nvd = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={start}&pubEndDate={end}&cvssV3Severity=CRITICAL", timeout=30).json()
print(f"\n🔴 Critical CVEs (last 48h): {nvd.get('totalResults', 0)}")
for v in nvd.get("vulnerabilities", [])[:5]:
    print(f"  {v['cve']['id']}: {v['cve']['descriptions'][0]['value'][:100]}")

# Packet Storm RSS
ps = feedparser.parse("https://rss.packetstormsecurity.com/files/")
print(f"\n💥 Latest Packet Storm releases:")
for e in ps.entries[:5]:
    print(f"  {e.title}")
EOF
```
