#!/usr/bin/env python3
"""
XBOW Autonomous Pentesting API Client
Usage:
  python3 xbow_client.py launch <url> [--headers '{"Auth":"Bearer token"}']
  python3 xbow_client.py status <scan_id>
  python3 xbow_client.py findings <scan_id>
  python3 xbow_client.py report <scan_id> --output report.md
"""

import os
import sys
import json
import time
import argparse
import urllib.request
import urllib.error

# Configured via .env usually, but also accept explicit env injection
API_KEY = os.environ.get("XBOW_API_KEY")
BASE_URL = "https://api.xbow.com/v1" # Standardized assumed v1 API endpoint

def api_request(method, endpoint, payload=None):
    if not API_KEY:
        print(json.dumps({
            "error": "XBOW_API_KEY environment variable is not set.",
            "remediation": "Configure this key in your .env file."
        }))
        sys.exit(1)

    url = f"{BASE_URL}{endpoint}"
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    data = None
    if payload:
        data = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8")
        try:
            err_json = json.loads(err_body)
        except:
            err_json = {"raw": err_body}
        return {"error": f"HTTP {e.code}", "details": err_json}
    except Exception as e:
        return {"error": str(e)}

def do_launch(url, headers_json):
    # Prepare optional headers
    custom_headers = {}
    if headers_json:
        try:
            custom_headers = json.loads(headers_json)
        except json.JSONDecodeError:
            print(json.dumps({"error": "Invalid JSON format for --headers"}))
            sys.exit(1)

    payload = {
        "target": {
            "url": url,
            "headers": custom_headers
        },
        # Assuming typical payload flags for depth/aggressiveness
        "settings": {
            "mode": "autonomous",
            "confirm_exploits": True
        }
    }
    
    res = api_request("POST", "/scans", payload)
    print(json.dumps(res, indent=2))

def do_status(scan_id):
    res = api_request("GET", f"/scans/{scan_id}")
    print(json.dumps(res, indent=2))

def do_findings(scan_id):
    res = api_request("GET", f"/scans/{scan_id}/findings")
    print(json.dumps(res, indent=2))

def do_report(scan_id, output_file):
    scan_info = api_request("GET", f"/scans/{scan_id}")
    findings = api_request("GET", f"/scans/{scan_id}/findings")

    if "error" in findings:
        print(json.dumps(findings))
        sys.exit(1)

    report = f"# XBOW Autonomous Pentest Report\n\n"
    report += f"**Scan ID:** `{scan_id}`\n"
    target = scan_info.get("target", {}).get("url", "Unknown Target")
    report += f"**Target:** {target}\n"
    report += f"**Status:** {scan_info.get('status', 'Completed')}\n\n"
    report += "---\n\n## Verified Findings\n\n"

    items = findings.get("findings", [])
    if not items:
        report += "*No verified vulnerabilities discovered.*"
    else:
        for f in items:
            report += f"### {f.get('title', 'Unknown Finding')}\n"
            report += f"- **Severity:** {f.get('severity', 'UNKNOWN')}\n"
            report += f"- **CWE:** {f.get('cwe', 'N/A')} | **CVSS:** {f.get('cvss', 'N/A')}\n\n"
            report += f"**Description:**\n{f.get('description', '')}\n\n"
            report += f"**Exploit Proof (Confirmed):**\n```\n{f.get('evidence', '')}\n```\n\n"
            report += f"**Remediation:**\n{f.get('remediation', '')}\n\n---\n"

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(report)
    print(json.dumps({"report_saved": output_file}))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="XBOW API Client")
    subparsers = parser.add_subparsers(dest="action", required=True)

    # Launch args
    p_launch = subparsers.add_parser("launch")
    p_launch.add_argument("url", help="Target URL")
    p_launch.add_argument("--headers", default="{}", help="JSON string of HTTP headers (e.g., auth tokens)")

    # Status args
    p_status = subparsers.add_parser("status")
    p_status.add_argument("scan_id", help="XBOW Scan ID")

    # Findings args
    p_findings = subparsers.add_parser("findings")
    p_findings.add_argument("scan_id", help="XBOW Scan ID")

    # Report args
    p_report = subparsers.add_parser("report")
    p_report.add_argument("scan_id", help="XBOW Scan ID")
    p_report.add_argument("--output", default="xbow_report.md", help="Markdown report path")

    args = parser.parse_args()

    if args.action == "launch":
        do_launch(args.url, args.headers)
    elif args.action == "status":
        do_status(args.scan_id)
    elif args.action == "findings":
        do_findings(args.scan_id)
    elif args.action == "report":
        do_report(args.scan_id, args.output)
