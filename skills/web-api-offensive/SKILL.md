---
name: web-api-offensive
description: |
  Full-spectrum Web Application & API offensive testing engine. Automates subdomain/surface
  discovery, authentication bypass, IDOR detection, SSRF chaining, GraphQL abuse, rate-limit
  analysis, JWT manipulation testing, and business-logic flaw reasoning. Maps every finding to
  OWASP Web Top 10 (2021+2025 draft), OWASP API Security Top 10 (2023), and OWASP WSTG v4.2
  test-case references. Integrates Nuclei, SQLMap, ffuf, Semgrep, and jwt_tool.
metadata:
  {
    "openclaw":
      {
        "emoji": "🕷️",
        "requires":
          {
            "bins": ["nuclei", "sqlmap", "ffuf", "semgrep", "jwt_tool"],
            "optional": ["amass", "subfinder", "httpx"],
          },
        "install":
          [
            {
              "id": "brew-nuclei",
              "kind": "brew",
              "formula": "nuclei",
              "bins": ["nuclei"],
              "label": "Install Nuclei (brew)"
            },
            {
              "id": "brew-sqlmap",
              "kind": "brew",
              "formula": "sqlmap",
              "bins": ["sqlmap"],
              "label": "Install SQLMap (brew)"
            },
            {
              "id": "brew-ffuf",
              "kind": "brew",
              "formula": "ffuf",
              "bins": ["ffuf"],
              "label": "Install ffuf (brew)"
            },
            {
              "id": "brew-semgrep",
              "kind": "brew",
              "formula": "semgrep",
              "bins": ["semgrep"],
              "label": "Install Semgrep (brew)"
            },
            {
              "id": "pip-jwt-tool",
              "kind": "shell",
              "cmd": "pip3 install jwt_tool 2>/dev/null || pip install jwt_tool",
              "bins": ["jwt_tool"],
              "label": "Install jwt_tool (pip)"
            }
          ],
      },
  }
---

# Web App + API Offensive Skill

A comprehensive skill for attacking web applications and APIs, guided by OWASP standards.

## Capabilities

### 1. Subdomain & Surface Discovery (WSTG-INFO-*)
Enumerate subdomains and map the attack surface before exploitation.

**Usage:**
> Discover the attack surface for example.com

**Tools:** `subfinder`, `amass`, `httpx`, `nuclei`

**OWASP References:**
- WSTG-INFO-01: Search Engine Discovery
- WSTG-INFO-02: Fingerprint Web Server
- WSTG-INFO-08: Fingerprint Web Application Framework

---

### 2. Authentication Bypass (OWASP A07, API Security API2)
Test for broken authentication including default credentials, login brute-force, and session fixation.

**Usage:**
> Test the login at https://target.com/api/v1/login for authentication bypass

**Tools:** `ffuf` (credential fuzzing), `nuclei` (auth templates)

**OWASP References:**
- A07:2021 Identification and Authentication Failures
- API2:2023 Broken Authentication
- WSTG-ATHN-01 through WSTG-ATHN-10

---

### 3. IDOR Detection (OWASP A01, API Security API1)
Detect Insecure Direct Object References by fuzzing object/resource IDs across endpoints.

**Usage:**
> Check for IDOR vulnerabilities in the /api/v1/users/{id} endpoint

**Tools:** `ffuf` (ID fuzzing), `nuclei` (IDOR templates)

**OWASP References:**
- A01:2021 Broken Access Control
- API1:2023 Broken Object Level Authorization (BOLA)
- WSTG-ATHZ-01: Testing Directory Traversal / File Include

---

### 4. SSRF Chaining (OWASP A10, API Security API7)
Identify and exploit Server-Side Request Forgery for internal network pivoting.

**Usage:**
> Test /api/fetch?url= parameter for SSRF on https://target.com

**Tools:** `nuclei` (SSRF templates), custom `ffuf` payloads

**OWASP References:**
- A10:2021 Server-Side Request Forgery
- API7:2023 Server Side Request Forgery
- WSTG-INPV-19: Testing for Server-Side Request Forgery

---

### 5. GraphQL Abuse (OWASP A03, API Security API8)
Introspect and abuse GraphQL endpoints for information disclosure and injection.

**Usage:**
> Enumerate and attack the GraphQL endpoint at https://target.com/graphql

**Tools:** `nuclei` (GraphQL templates), manual introspection via curl

**OWASP References:**
- A03:2021 Injection
- API8:2023 Security Misconfiguration
- WSTG-INPV-12: Testing for Command Injection

---

### 6. Rate Limit Analysis (API Security API4)
Test for missing or bypassable rate limiting on sensitive endpoints.

**Usage:**
> Test rate limits on the /api/v1/login and /api/v1/password-reset endpoints

**Tools:** `ffuf` (multi-threaded fuzzing)

**OWASP References:**
- API4:2023 Unrestricted Resource Consumption
- WSTG-ATHN-03: Testing for Weak Lock Out Mechanism

---

### 7. JWT Manipulation Testing (OWASP A02, A07)
Test for weak JWT signing, algorithm confusion (HS256 → RS256), and token forgery.

**Usage:**
> Analyze and attack the JWT token: eyJhbGci...

**Tools:** `jwt_tool`

**OWASP References:**
- A02:2021 Cryptographic Failures
- A07:2021 Identification and Authentication Failures
- WSTG-SESS-10: Testing JSON Web Tokens

---

### 8. SQL Injection (OWASP A03)
Automated SQL injection detection and exploitation.

**Usage:**
> Test https://target.com/search?q= for SQL injection

**Tools:** `sqlmap`

**OWASP References:**
- A03:2021 Injection
- WSTG-INPV-05: Testing for SQL Injection

---

### 9. AI-Assisted Business Logic Flaw Reasoning
Analyze application workflows to identify logical flaws that automated scanners miss.

**Usage:**
> Analyze the checkout flow at https://shop.example.com for business logic flaws

**Tools:** LLM-based reasoning, `nuclei` (custom templates)

**OWASP References:**
- A04:2021 Insecure Design
- WSTG-BUSL-01 through WSTG-BUSL-09

---

## Quick Commands

| Goal | Command |
|---|---|
| Surface Discovery | `nuclei -u https://TARGET -t exposures/ -o findings.txt` |
| Subdomain Enum | `subfinder -d TARGET -o subs.txt && httpx -l subs.txt` |
| Directory Fuzzing | `ffuf -u https://TARGET/FUZZ -w wordlist.txt` |
| SQLi | `sqlmap -u "https://TARGET/page?id=1" --dbs` |
| JWT Attack | `jwt_tool TOKEN -M at` |
| Auth Fuzz | `ffuf -u https://TARGET/login -X POST -d 'user=FUZZ&pass=admin' -w users.txt` |
