---
name: report-generator
description: |
  Auto-generates professional security reports with CVSS v3.1 scoring, PoC structure,
  remediation steps, and business impact statements. Produces HackerOne/Bugcrowd submissions,
  pentest executive reports, and technical finding pages. Auto-populates from finding metadata —
  you just describe what you found.
metadata: { "openclaw": { "emoji": "📄" } }
---

# Report Generator — Auto-Populated Security Reports

Describe a finding, get a polished submission. Handles CVSS scoring, PoC formatting,
remediation, impact — everything a triage team needs to act immediately.

## When to Use

✅ **USE this skill when:**

- Writing a HackerOne or Bugcrowd submission
- Generating a pentest finding page
- Creating an executive or technical report
- Scoring CVSS for a new finding

---

## Generate a Finding Report

### Basic Usage

```
Generate a report for: SQL injection in /api/search?q= parameter — unauthenticated, returns database version
Write a HackerOne submission for: stored XSS in profile bio field, triggers on other users' profiles
Generate a finding report for IDOR at /api/orders/{id} — any authenticated user can access any order
```

### With Full Context

```
Write a report for this finding:
- Type: SSRF
- Host: api.example.com
- Endpoint: /fetch?url=
- Auth: Authenticated (any user)
- Evidence: AWS IMDS metadata retrieved - ami-id, instance-id
- WAF: Cloudflare, bypassed via 0x7f000001
- Screenshot: evidence/001/screenshot.png
```

---

## CVSS v3.1 Auto-Scoring

The agent calculates CVSS scores based on your description:

| Finding Type               | Typical Score | Vector                              |
| -------------------------- | ------------- | ----------------------------------- |
| RCE (no auth)              | 9.8 CRITICAL  | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| SQLi (no auth, data exfil) | 9.1 CRITICAL  | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L |
| Stored XSS                 | 8.0 HIGH      | AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N |
| SSRF (cloud metadata)      | 8.6 HIGH      | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N |
| IDOR (authenticated)       | 7.5 HIGH      | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| Open Redirect              | 6.1 MEDIUM    | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N |
| Reflected XSS              | 6.1 MEDIUM    | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N |
| Path Traversal             | 7.5 HIGH      | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N |
| Subdomain Takeover         | 8.1 HIGH      | AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N |

```
What's the CVSS score for an unauthenticated RCE via command injection?
Score this: authenticated IDOR that exposes other users' PII (no modification possible)
Calculate CVSS for: stored XSS in admin panel, triggered on every admin page load
```

---

## HackerOne / Bugcrowd Submission Template

Generated automatically:

```markdown
# [Vulnerability Type] in [Endpoint] — [Brief Impact]

## Summary

[2-3 sentence description. State: what it is, where it is, what impact it enables.]

**Vulnerability:** [Type] ([CWE-ID])
**OWASP:** [A0X:20XX — Name]
**CVSS 3.1:** [Score] ([Vector])
**Severity:** [CRITICAL / HIGH / MEDIUM / LOW]

## Steps to Reproduce

**Prerequisites:**

- [ ] Account required: [Yes (any) / Yes (admin only) / No]
- [ ] Tools: [curl / Burp Suite / Browser]

**Steps:**

1. Navigate to `https://target.com/vulnerable-endpoint`
2. Submit the following payload in the `[parameter]` field:
```

[PAYLOAD]

```
3. Observe: [what happens — error, data returned, redirect, etc.]
4. The server responds with:
```

[RESPONSE SNIPPET]

````

**PoC (curl):**
```bash
curl -s -X [METHOD] "https://target.com/endpoint?param=PAYLOAD" \
-H "Authorization: Bearer YOUR_TOKEN" \
-d "body=data"
````

## Evidence

[Embedded screenshots]

**Extracted data / proof of impact:**

```
[Output or evidence snippet]
```

## Impact

[Business impact in plain language — who is affected, what data/functionality is at risk,
what could an attacker do with this.]

**Attack scenarios:**

- An unauthenticated attacker can [X]
- This could lead to [Y]
- In a real attack, an adversary would [Z]

## CVSS Breakdown

| Metric              | Value     | Rationale                                |
| ------------------- | --------- | ---------------------------------------- |
| Attack Vector       | Network   | Exploitable remotely                     |
| Attack Complexity   | Low       | No special conditions                    |
| Privileges Required | None      | Unauthenticated                          |
| User Interaction    | None      | No victim action needed                  |
| Scope               | Unchanged | Impact contained to vulnerable component |
| Confidentiality     | High      | Full data exposure                       |
| Integrity           | High      | Data modification possible               |
| Availability        | Low       | Service not affected                     |

**Score: [X.X] [SEVERITY]**

## Remediation

**Immediate fix:**
[Specific code-level fix — parameterized queries, output encoding, SSRF block, etc.]

**Code example (secure):**

```[language]
[Secure code snippet]
```

**Additional hardening:**

- [Add WAF rule / rate limit / Content-Security-Policy / etc.]
- [Audit all similar endpoints for the same pattern]

## References

- [OWASP link]
- [CWE link]
- [CVE if applicable]

```

---

## Pentest Technical Finding Page

```

Generate a pentest finding page for: command injection in ping functionality
Format: technical pentest report (not bug bounty)

````

```markdown
## Finding #001 — OS Command Injection

| Field | Value |
|---|---|
| **ID** | CLAW-2026-001 |
| **Title** | OS Command Injection in Network Diagnostics |
| **Severity** | CRITICAL |
| **CVSS 3.1** | 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| **CWE** | CWE-78 |
| **OWASP** | A03:2021 — Injection |
| **ATT&CK** | T1059 — Command and Scripting Interpreter |
| **Host** | admin.example.com |
| **Endpoint** | POST /admin/network/ping |
| **Date Found** | 2026-02-23 |
| **Status** | Open |

### Description
...

### Evidence
![Screenshot](screenshots/001.png)

### Remediation
...
````

---

## Executive Summary Generator

```
Generate an executive summary for my shopify engagement
Write an exec summary: 1 critical, 3 high, 5 medium findings, 2-week engagement
```

```markdown
# Executive Summary

**Engagement:** Shopify Bug Bounty — February 2026
**Duration:** 14 days
**Tester:** [Your name]

## Key Findings

During the engagement, **9 security vulnerabilities** were identified:

| Severity    | Count | Highlight                            |
| ----------- | ----- | ------------------------------------ |
| 🔴 Critical | 1     | SQL Injection — full database access |
| 🟠 High     | 3     | IDOR, SSRF, Open Redirect            |
| 🟡 Medium   | 5     | XSS (3), Info Disclosure (2)         |

**Overall risk rating: HIGH**

## Critical Risk

The most severe finding — SQL Injection in the `/api/search` endpoint — allows an unauthenticated
attacker to retrieve the entire user database, including plaintext credentials and payment records.
Immediate remediation is strongly recommended.

## Recommendations

1. Implement parameterized queries across all database interaction points
2. Enable Content-Security-Policy headers to mitigate XSS
3. Enforce authorization checks on all resource ID lookups
```

---

## Usage from Agent

```
Generate a HackerOne submission for: reflected XSS in /search?q= on target.com
Write a bug bounty report for the SSRF I found via the url parameter
What's the CVSS score for my finding: RCE via deserialization, requires authentication?
Generate an executive summary for my engagement: 2 crits, 4 highs, 6 mediums
Auto-populate the OWASP, CWE, and remediation for a stored XSS finding
Write the PoC section for my IDOR finding at /api/users/{id}/profile
```
