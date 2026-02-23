---
name: researcher-assistant
description: |
  Human researcher companion for bug bounty and penetration testing. Organizes targets and
  scope, tracks findings across sessions, drafts writeups with embedded screenshots, manages
  the engagement lifecycle (in-progress, confirmed, reported, fixed). Use when: coordinating
  a manual testing engagement, organizing discovered findings, or drafting submission writeups.
metadata: { "openclaw": { "emoji": "🗂️" } }
---

# Researcher Assistant — Engagement Organizer & Writeup Drafter

Your AI pair-programmer for manual security research. Keeps you organized, tracks everything,
and drafts polished writeups so you can stay focused on finding bugs.

## When to Use

✅ **USE this skill when:**

- Starting a new engagement or bug bounty program
- Organizing targets, scope, and notes across sessions
- Logging a newly discovered finding mid-test
- Drafting a polished writeup / platform submission
- Reviewing all open findings at a glance

---

## Engagement Setup

### Start a New Engagement

```
Set up a new engagement for HackerOne program: shopify.com
Scope: *.shopify.com, *.myshopify.com
Out of scope: cdn.shopify.com, help.shopify.com
Reward range: $500–$50,000
```

The agent will create:

```
engagements/
  shopify_h1/
    scope.md          — in-scope targets, out-of-scope list
    targets.txt       — live hosts from recon
    findings/         — one folder per finding
    notes.md          — general testing notes
    timeline.md       — timestamped activity log
    README.md         — engagement overview
```

### Add a Target

```
Add api.shopify.com to the shopify engagement targets
Add all subdomains from recon/live.txt to the current engagement
Mark checkout.shopify.com as high-priority (handles payments)
```

---

## Finding Tracking

### Log a New Finding (mid-test)

```
Log a new finding: XSS in the search parameter on shop.example.com/search?q=
I found an IDOR at /api/v1/orders/{id} — any authenticated user can access any order
Add finding: Open redirect at /redirect?url= — confirmed via browser
```

The agent creates `findings/CLAW-2026-001/`:

```
findings/CLAW-2026-001/
  finding.md          — title, type, severity, status, description
  request.txt         — HTTP request
  response.txt        — HTTP response
  poc.md              — reproduction steps
  screenshots/        — evidence images
  status: OPEN
```

### Update Finding Status

```
Mark CLAW-2026-001 as confirmed
Update CLAW-2026-002 status to reported — submitted to HackerOne
Mark CLAW-2026-003 as fixed — vendor patched it
```

### Finding Status Lifecycle

| Status      | Meaning                       |
| ----------- | ----------------------------- |
| `OPEN`      | Discovered, not yet confirmed |
| `CONFIRMED` | PoC proven, ready to write up |
| `REPORTED`  | Submitted to platform         |
| `TRIAGED`   | Platform acknowledged         |
| `FIXED`     | Vendor patched                |
| `DUPLICATE` | Closed as dup                 |
| `N/A`       | Rejected / out of scope       |

### Dashboard — All Findings

```
Show me all open findings in the current engagement
List all confirmed findings ready to write up
What's the status of all my findings for shopify?
```

Output:

```
ENGAGEMENT: Shopify HackerOne
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CLAW-2026-001 | CRITICAL | CONFIRMED  | SQLi in /api/search
CLAW-2026-002 | HIGH     | REPORTED   | IDOR /api/orders/
CLAW-2026-003 | MEDIUM   | OPEN       | Open Redirect /redirect
CLAW-2026-004 | HIGH     | CONFIRMED  | XSS in search param
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total: 4  |  Confirmed: 2  |  Reported: 1  |  Bounty potential: ~$8,500
```

---

## Writeup Drafting

### Draft a Submission Writeup

```
Draft a HackerOne writeup for CLAW-2026-001
Write a Bugcrowd submission for the IDOR finding
Draft the XSS writeup with the screenshots I captured
```

The agent auto-populates:

- Title (clear, descriptive, impactful)
- Vulnerability type + OWASP reference
- CVSS score with justification
- Step-by-step reproduction
- Embedded screenshots (from `findings/FINDINGID/screenshots/`)
- Business impact statement
- Remediation recommendation

### Notes & Scratch Pad

```
Add a note to the shopify engagement: checkout flow uses GraphQL — test for IDOR there
Paste these HTTP request headers into the current finding notes
Add a timestamp note: 13:42 — found interesting admin panel at /admin-preview
```

---

## Session Continuity

```
Summarize what I was doing in the last shopify session
What finding was I working on before?
Pick up where I left off on the shopify engagement
```

The agent reads `timeline.md` and `findings/*/status` to reconstruct context.

---

## Usage from Agent

```
Set up a new engagement for hackerone program: example.com
I found a reflected XSS in the search bar — log it and create a finding
Show me all my confirmed findings ready to report
Draft the writeup for CLAW-2026-001 with screenshots
What's my current engagement status and bounty potential?
Pick up where I left off yesterday on the shopify engagement
```
