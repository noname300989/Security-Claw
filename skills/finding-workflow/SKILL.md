---
name: finding-workflow
description: |
  Real-time finding capture and report writing assistant. Alert the agent the moment you
  manually discover something and it will: log the finding instantly, guide you through
  capturing evidence (screenshots, requests, responses), calculate severity, draft the writeup,
  and notify all configured channels. The bridge between your manual testing and polished reports.
metadata: { "openclaw": { "emoji": "🚨" } }
---

# Finding Workflow — Real-Time Discovery Capture

Tell the agent what you found. It handles logging, evidence capture, severity scoring,
writeup drafting, and all-channel notification — so you stay in testing mode.

## When to Use

✅ **USE this skill when:**

- You've just manually found something and want to log it instantly
- You need to take screenshots and capture request/response evidence
- You want immediate notification to your team/channels
- You're ready to draft the writeup right after finding something

---

## Quick Log — Capture Instantly

Say any of these to log a finding immediately:

```
Found! SQL injection in /api/search?q= on example.com — unauthenticated, returns DB version
I found XSS — search param on shop.example.com/search reflects unescaped
Bug: IDOR at /api/orders/{id} — can access other users' orders while logged in
Found open redirect at /redirect?url=https://evil.com — triggers after login
I think I found SSRF in the URL param — retrieved 169.254.169.254 metadata
```

The agent immediately:

1. Creates `findings/CLAW-YYYY-NNN/` with a timestamped entry
2. Assigns severity (asks if unsure)
3. Prompts you for evidence: "Paste the request, or tell me where the screenshot is"
4. Notifies all connected channels: **"🚨 Finding captured — [TYPE] on [HOST]"**

---

## Evidence Capture Workflow

After logging, the agent walks you through capturing clean evidence:

### Step 1 — Paste Your HTTP Request

```
Paste the request:

POST /api/search HTTP/1.1
Host: api.example.com
Authorization: Bearer ...
Content-Type: application/json

{"q":"1' OR 1=1--"}
```

### Step 2 — Paste the Response

```
Paste the response (or just the key part):

{"error":"You have an error in your SQL syntax...","database":"mysql-prod"}
```

### Step 3 — Screenshot

```
Take a screenshot of the finding in the browser
I took a screenshot — it's at /tmp/screenshot.png
Save the current browser view as evidence for this finding
```

### Step 4 — PoC Confirmation

The agent generates the minimal PoC command:

```bash
# Auto-generated PoC
curl -s -X POST "https://api.example.com/api/search" \
  -H "Content-Type: application/json" \
  -d '{"q":"1'\''/**/OR/**/1=1--"}'
# Expected: SQL error message or different response comportament
```

---

## Severity Escalation Check

After logging, the agent asks the right questions to make sure severity is calibrated:

```
🔍 Severity Check for CLAW-2026-001 (SQL Injection)

→ Is auth required?          [Yes — any authenticated user / No — unauthenticated]
→ What data can be retrieved? [User table? Payment data? Credentials?]
→ Is write access possible?   [Can you INSERT/UPDATE/DELETE?]
→ Is it time-based blind or error-based?

Based on your answers: CVSS 9.1 CRITICAL (unauthenticated, full data access)
```

---

## Instant All-Channel Alert

When you log a finding, all configured channels receive:

```
🚨 NEW FINDING — CLAW-2026-001
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Type:      SQL Injection
Severity:  🔴 CRITICAL (CVSS 9.1)
Host:      api.example.com
Endpoint:  POST /api/search?q=
Auth:      Unauthenticated
Status:    Evidence capture in progress

→ Start writing the report? Reply YES to this message.
```

Channels: Discord, Telegram, WhatsApp, iMessage, Signal — all simultaneously.

---

## Team Collaboration Mode

If you're testing with a team, findings are broadcast to all members:

```
Announce finding to the team: SQL injection confirmed on api.example.com
Notify team that I'm working on the checkout flow — don't duplicate testing there
Update the team: CLAW-2026-001 is ready for writeup review
```

---

## Guided Writeup Mode

When you're ready to write up a finding:

```
Let's write up CLAW-2026-001
Help me write the submission for the XSS I found
Generate the HackerOne report for my SQL injection finding
```

The agent enters an interactive mode:

```
📝 Writing up CLAW-2026-001 — SQL Injection

I have:
  ✅ Request captured
  ✅ Response captured
  ✅ Screenshot at evidence/001/screenshot.png
  ✅ CVSS: 9.1 CRITICAL

Missing:
  ⚠️  Business impact statement — what data is exposed?
  ⚠️  Remediation specifics — what language/framework is the target?

→ What would you like to add to the impact statement?
  (e.g. "Users' passwords, emails, and payment tokens are in the database")
```

Then generates the full submission draft.

---

## Daily Finding Summary

```
What did I find today?
Summarize all new findings from this session
How many findings do I have ready to report?
```

```
📋 Today's Findings — 2026-02-23

CLAW-2026-001 | 🔴 CRITICAL | SQL Injection    | Evidence ✅ | Writeup ✅ | READY TO SUBMIT
CLAW-2026-002 | 🟠 HIGH     | IDOR             | Evidence ✅ | Writeup ⏳ | Needs writeup
CLAW-2026-003 | 🟡 MEDIUM   | Open Redirect    | Evidence ⚠️  | Writeup ❌ | Needs screenshot

2 ready to submit, 1 needs more evidence
Estimated bounty: ~$4,500–$9,000
```

---

## Quick Commands

| Command                  | What It Does                                  |
| ------------------------ | --------------------------------------------- |
| `Found! [description]`   | Instantly log and notify                      |
| `Take screenshot`        | Capture browser state as evidence             |
| `Paste request/response` | Add to current finding's evidence             |
| `Score this finding`     | Calculate CVSS interactively                  |
| `Write up [finding ID]`  | Enter guided writeup mode                     |
| `Notify team: [msg]`     | Broadcast to all channels                     |
| `What did I find today?` | Show today's finding summary                  |
| `Ready to report`        | List all confirmed, writeup-complete findings |

---

## Usage from Agent

```
Found! Reflected XSS in the search bar at shop.example.com/search?q=
I found an IDOR — any user can access /api/profile/{userId} without owning that account
Notify all channels: just confirmed RCE via command injection on the ping endpoint
Take a screenshot of the XSS proof in the browser and save it to the current finding
Let's write up CLAW-2026-001 — I'm ready
What findings do I have ready to submit today?
Update my team: I'm testing the payment flow, please don't duplicate this
```
