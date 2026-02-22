#!/usr/bin/env python3
"""
OpenClaw Offensive OS — Threat Intelligence Scraper
Gathers latest CVEs, exploits, OWASP updates, and threat indicators from live web sources.

Usage:
    python3 skills/threat-intel/scraper.py [--days 7] [--severity CRITICAL] [--output json|text]

Requirements:
    pip3 install requests beautifulsoup4 feedparser lxml rich
"""

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone

try:
    import requests
    import feedparser
    from bs4 import BeautifulSoup
    try:
        from rich.console import Console
        from rich.table import Table
        from rich import print as rprint
        RICH = True
    except ImportError:
        RICH = False
except ImportError:
    print("[!] Missing dependencies. Run: pip3 install requests beautifulsoup4 feedparser lxml rich")
    sys.exit(1)

console = Console() if RICH else None
SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (SecurityResearch/OpenClawOS) AppleWebKit/537.36"
})


# ─────────────────────────────────────────────────────────────────────────────
# Source 1 — NVD CVE API v2
# ─────────────────────────────────────────────────────────────────────────────

def fetch_nvd_cves(days: int = 7, severity: str = "CRITICAL") -> list[dict]:
    """Fetch latest CVEs from NVD API v2."""
    now   = datetime.now(timezone.utc)
    start = (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000")
    end   = now.strftime("%Y-%m-%dT%H:%M:%S.000")
    url = (
        f"https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?pubStartDate={start}&pubEndDate={end}&cvssV3Severity={severity}"
    )
    try:
        resp = SESSION.get(url, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        results = []
        for v in data.get("vulnerabilities", []):
            cve = v["cve"]
            metrics = cve.get("metrics", {})
            cvss_data = (
                metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                if metrics.get("cvssMetricV31") else {}
            )
            results.append({
                "id": cve["id"],
                "description": cve["descriptions"][0]["value"][:200] if cve.get("descriptions") else "",
                "cvss_score": cvss_data.get("baseScore", "N/A"),
                "published": cve.get("published", "")[:10],
            })
        return results
    except Exception as e:
        return [{"error": f"NVD fetch failed: {e}"}]


# ─────────────────────────────────────────────────────────────────────────────
# Source 2 — CISA Known Exploited Vulnerabilities
# ─────────────────────────────────────────────────────────────────────────────

def fetch_cisa_kev(days: int = 14) -> list[dict]:
    """Fetch recently added entries in the CISA KEV catalog."""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        resp = SESSION.get(url, timeout=30)
        resp.raise_for_status()
        since = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
        return [
            {
                "id": v["cveID"],
                "name": v["vulnerabilityName"],
                "vendor": v.get("vendorProject", ""),
                "product": v.get("product", ""),
                "added": v.get("dateAdded", ""),
                "due": v.get("dueDate", ""),
            }
            for v in resp.json().get("vulnerabilities", [])
            if v.get("dateAdded", "") >= since
        ]
    except Exception as e:
        return [{"error": f"CISA KEV fetch failed: {e}"}]


# ─────────────────────────────────────────────────────────────────────────────
# Source 3 — Packet Storm Security RSS
# ─────────────────────────────────────────────────────────────────────────────

def fetch_packetstorm(limit: int = 10) -> list[dict]:
    """Fetch latest items from Packet Storm Security RSS feed."""
    try:
        feed = feedparser.parse("https://rss.packetstormsecurity.com/files/")
        return [
            {
                "title": e.get("title", ""),
                "link": e.get("link", ""),
                "published": e.get("published", "")[:16],
                "summary": e.get("summary", "")[:150],
            }
            for e in feed.entries[:limit]
        ]
    except Exception as e:
        return [{"error": f"Packet Storm fetch failed: {e}"}]


# ─────────────────────────────────────────────────────────────────────────────
# Source 4 — OWASP Blog / RSS
# ─────────────────────────────────────────────────────────────────────────────

def fetch_owasp_updates(limit: int = 5) -> list[dict]:
    """Fetch latest OWASP blog / news items."""
    feeds = [
        ("OWASP Blog", "https://owasp.org/feed.xml"),
    ]
    results = []
    for source, url in feeds:
        try:
            feed = feedparser.parse(url)
            for e in feed.entries[:limit]:
                results.append({
                    "source": source,
                    "title": e.get("title", ""),
                    "link": e.get("link", ""),
                    "published": e.get("published", "")[:10],
                })
        except Exception as exc:
            results.append({"source": source, "error": str(exc)})
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Source 5 — Nuclei Templates GitHub Releases
# ─────────────────────────────────────────────────────────────────────────────

def fetch_nuclei_template_updates(days: int = 7) -> list[dict]:
    """Fetch recent nuclei-templates commits from GitHub API."""
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    url = (
        f"https://api.github.com/repos/projectdiscovery/nuclei-templates/commits"
        f"?since={since}&per_page=20"
    )
    try:
        resp = SESSION.get(url, timeout=20)
        resp.raise_for_status()
        return [
            {
                "message": c["commit"]["message"].split("\n")[0][:120],
                "author": c["commit"]["author"]["name"],
                "date": c["commit"]["author"]["date"][:10],
                "url": c["html_url"],
            }
            for c in resp.json()
        ]
    except Exception as e:
        return [{"error": f"Nuclei templates fetch failed: {e}"}]


# ─────────────────────────────────────────────────────────────────────────────
# Source 6 — GitHub Security Advisories (public, no auth needed)
# ─────────────────────────────────────────────────────────────────────────────

def fetch_github_advisories(ecosystem: str = "npm", limit: int = 10) -> list[dict]:
    """Fetch latest GitHub Security Advisories for a given ecosystem."""
    url = f"https://api.github.com/advisories?ecosystem={ecosystem}&per_page={limit}&type=reviewed"
    try:
        resp = SESSION.get(url, timeout=20)
        resp.raise_for_status()
        return [
            {
                "ghsa_id": a.get("ghsa_id", ""),
                "cve_id": a.get("cve_id", "N/A"),
                "summary": a.get("summary", "")[:150],
                "severity": a.get("severity", ""),
                "published": a.get("published_at", "")[:10],
            }
            for a in resp.json()
        ]
    except Exception as e:
        return [{"error": f"GitHub advisories fetch failed: {e}"}]


# ─────────────────────────────────────────────────────────────────────────────
# Source 7 — Exploit-DB via searchsploit (local) or web search
# ─────────────────────────────────────────────────────────────────────────────

def search_exploitdb_web(query: str, limit: int = 5) -> list[dict]:
    """Search Exploit-DB for exploits matching a query term."""
    url = f"https://www.exploit-db.com/search?q={requests.utils.quote(query)}&type=exploits"
    try:
        resp = SESSION.get(
            url,
            timeout=15,
            headers={**SESSION.headers, "Accept": "application/json", "X-Requested-With": "XMLHttpRequest"},
        )
        resp.raise_for_status()
        data = resp.json().get("data", [])
        return [
            {
                "id": r.get("id", ""),
                "title": r.get("description", "")[:120],
                "platform": r.get("platform", {}).get("name", "") if isinstance(r.get("platform"), dict) else "",
                "date": r.get("date_published", "")[:10],
                "url": f"https://www.exploit-db.com/exploits/{r.get('id','')}",
            }
            for r in data[:limit]
        ]
    except Exception as e:
        return [{"error": f"Exploit-DB search failed: {e}"}]


# ─────────────────────────────────────────────────────────────────────────────
# Full Intelligence Refresh
# ─────────────────────────────────────────────────────────────────────────────

def full_intel_refresh(days: int = 7, severity: str = "CRITICAL") -> dict:
    """Run a comprehensive scrape of all sources and return a unified briefing."""
    print(f"[*] Starting threat intelligence refresh (last {days} days)...\n")

    briefing = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "nvd_critical_cves": fetch_nvd_cves(days=days, severity=severity),
        "cisa_kev_additions": fetch_cisa_kev(days=days),
        "packet_storm_releases": fetch_packetstorm(limit=10),
        "owasp_updates": fetch_owasp_updates(),
        "nuclei_template_commits": fetch_nuclei_template_updates(days=days),
        "github_advisories_npm": fetch_github_advisories(ecosystem="npm"),
    }
    return briefing


# ─────────────────────────────────────────────────────────────────────────────
# Pretty Print
# ─────────────────────────────────────────────────────────────────────────────

def print_briefing(data: dict, fmt: str = "text") -> None:
    if fmt == "json":
        print(json.dumps(data, indent=2))
        return

    ts = data.get("generated_at", "")[:19].replace("T", " ")
    print(f"\n{'='*70}")
    print(f"  🎯 OpenClaw Offensive OS — Threat Intelligence Briefing")
    print(f"  Generated: {ts} UTC")
    print(f"{'='*70}\n")

    # Critical CVEs
    cves = data.get("nvd_critical_cves", [])
    print(f"🔴 CRITICAL CVEs (NVD): {len(cves)} found")
    for c in cves[:8]:
        if "error" in c:
            print(f"   [!] {c['error']}")
        else:
            print(f"   [{c['published']}] {c['id']} (CVSS {c['cvss_score']})")
            print(f"       {c['description'][:100]}...")

    # CISA KEV
    kev = data.get("cisa_kev_additions", [])
    print(f"\n⚠️  CISA KEV Additions: {len(kev)} this period")
    for k in kev[:5]:
        if "error" not in k:
            print(f"   [{k['added']}] {k['id']} — {k['name']} ({k['product']})")

    # Packet Storm
    ps = data.get("packet_storm_releases", [])
    print(f"\n💥 Packet Storm Latest Releases: {len(ps)}")
    for p in ps[:5]:
        if "error" not in p:
            print(f"   [{p['published']}] {p['title']}")

    # OWASP
    ow = data.get("owasp_updates", [])
    print(f"\n📋 OWASP Updates: {len(ow)}")
    for o in ow[:3]:
        if "error" not in o:
            print(f"   [{o.get('published','')}] {o['title']}")

    # Nuclei
    nt = data.get("nuclei_template_commits", [])
    print(f"\n🧬 Nuclei Template Commits (last {len(nt)}): ")
    for n in nt[:5]:
        if "error" not in n:
            print(f"   [{n['date']}] {n['message'][:80]}")

    # GitHub Advisories
    ga = data.get("github_advisories_npm", [])
    print(f"\n🔒 GitHub Security Advisories (npm — latest {len(ga)}): ")
    for g in ga[:5]:
        if "error" not in g:
            print(f"   [{g['published']}] {g['severity'].upper()} — {g.get('cve_id','GHSA')} {g['summary'][:80]}")

    print(f"\n{'='*70}\n")


# ─────────────────────────────────────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="OpenClaw Threat Intelligence Scraper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scraper.py                          # Full refresh, text output
  python3 scraper.py --days 3 --output json   # Last 3 days, JSON output
  python3 scraper.py --severity HIGH          # Include HIGH severity CVEs
  python3 scraper.py --search "log4j"         # Search Exploit-DB for log4j
  python3 scraper.py --cve CVE-2024-1234      # Look up specific CVE
        """,
    )
    parser.add_argument("--days",     type=int, default=7,        help="Look-back window in days (default: 7)")
    parser.add_argument("--severity", default="CRITICAL",         help="NVD severity filter (default: CRITICAL)")
    parser.add_argument("--output",   choices=["text", "json"], default="text", help="Output format")
    parser.add_argument("--search",   help="Search Exploit-DB for a term (e.g. 'apache 2.4')")
    parser.add_argument("--cve",      help="Look up a single CVE in NVD (e.g. CVE-2024-1234)")
    args = parser.parse_args()

    if args.search:
        print(f"[*] Searching Exploit-DB for: {args.search}\n")
        results = search_exploitdb_web(args.search)
        if args.output == "json":
            print(json.dumps(results, indent=2))
        else:
            for r in results:
                if "error" in r:
                    print(f"[!] {r['error']}")
                else:
                    print(f"[{r['date']}] #{r['id']} {r['title']} ({r['platform']})")
                    print(f"    {r['url']}")
        return

    if args.cve:
        print(f"[*] Looking up {args.cve} in NVD...\n")
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={args.cve}"
        try:
            resp = SESSION.get(url, timeout=20)
            data = resp.json()
            if args.output == "json":
                print(json.dumps(data, indent=2))
            else:
                for v in data.get("vulnerabilities", []):
                    cve = v["cve"]
                    print(f"ID:          {cve['id']}")
                    print(f"Published:   {cve.get('published','')[:10]}")
                    print(f"Description: {cve['descriptions'][0]['value'][:300]}")
        except Exception as e:
            print(f"[!] Failed: {e}")
        return

    briefing = full_intel_refresh(days=args.days, severity=args.severity)
    print_briefing(briefing, fmt=args.output)


if __name__ == "__main__":
    main()
