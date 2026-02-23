---
name: interview-prep
description: |
  Daily security interview preparation system. Generates 50 deep technical interview questions
  across 5 security domains (OWASP Agentic AI Top 10, Penetration Testing, LLM Security, Cloud
  Security, Active Directory). Writes questions to the local Interview Dashboard at
  apps/interview-dashboard/data.json, and broadcasts a notification across WhatsApp, Telegram,
  and Discord. Triggered daily via the cron:daily hook, or invoked on-demand.
metadata: { "openclaw": { "emoji": "🎯" } }
---

# Interview Prep — Daily Security Q&A Generator

Automated daily generation of 50 expert-level security interview questions with full answers, written to the local dashboard and broadcast to all channels.

## When to Use

✅ **USE this skill when:**

- Generating today's security interview question set on-demand
- Refreshing the Interview Dashboard (`apps/interview-dashboard/`) with new questions
- Customizing the domains or question count for a specific exam/role
- Broadcasting interview prep notifications to WhatsApp, Telegram, or Discord
- Reviewing questions for a specific category (OWASP, Cloud, AD, LLM)

## When NOT to Use

❌ **DON'T use this skill when:**

- Actually running an automated attack (use `red-team-orchestration`)
- Looking up a specific CVE (use `web-search`)
- Studying a non-security topic

## Architecture

```
cron:daily
    │
    ▼
interview-prep-daily hook  (src/hooks/bundled/interview-prep-daily/handler.ts)
    │
    ├── 1. Generate 50 questions (agent query)
    ├── 2. Write → apps/interview-dashboard/data.json
    └── 3. Broadcast → WhatsApp + Telegram + Discord
```

The dashboard (`apps/interview-dashboard/index.html`) loads `data.json` and renders an interactive accordion by category.

## Coverage Domains

| Domain                      | Examples                                                          |
| --------------------------- | ----------------------------------------------------------------- |
| **OWASP Agentic AI Top 10** | AI04 Data Poisoning, Indirect Prompt Injection, Insecure Tool Use |
| **Penetration Testing**     | Bind vs Reverse Shell, Active Directory attacks, lateral movement |
| **LLM Security**            | LLM02 Insecure Output Handling, prompt injection, jailbreaks      |
| **Cloud Security**          | AWS IMDS SSRF, IAM privilege escalation, S3 misconfig             |
| **Active Directory**        | Kerberoasting, Pass-the-Hash, BloodHound enumeration              |

## data.json Format

```json
{
  "generatedAt": "2026-02-23T07:00:00.000Z",
  "description": "Daily Elite Security Interview Batch",
  "questions": [
    {
      "category": "OWASP Agentic AI Top 10",
      "question": "What is AI04:2025 Data Poisoning and how can it compromise an autonomous agent?",
      "answer": "..."
    },
    {
      "category": "Cloud Security",
      "question": "Explain SSRF against AWS IMDSv1. How does IMDSv2 mitigate this?",
      "answer": "..."
    }
  ]
}
```

## On-Demand Generation

Ask the agent to generate a fresh batch immediately:

```
Generate today's 50 security interview questions and write them to the dashboard
```

Generate for a specific domain only:

```
Generate 20 Active Directory interview questions and update data.json
```

Generate for a specific role/exam:

```
Generate 30 AWS Security Specialty exam-style questions and save to the dashboard
```

## Manual Dashboard Update

If you want to write custom questions directly:

```bash
# Update the dashboard data
cat > apps/interview-dashboard/data.json << 'EOF'
{
  "generatedAt": "2026-02-23T12:00:00.000Z",
  "description": "Custom Security Interview Batch",
  "questions": [
    {
      "category": "Penetration Testing",
      "question": "...",
      "answer": "..."
    }
  ]
}
EOF
```

Then open the dashboard:

```bash
open apps/interview-dashboard/index.html
```

## Broadcast Notification Format

The hook sends this message to all channels after generation:

```
🚨 New Interview Prep Available
The interview-prep agent has generated 50 new questions covering
OWASP Agentic AI, Penetration Testing, Cloud Security, and LLM Security.

Visit your Local Dashboard at apps/interview-dashboard/index.html to study!
```

## Scheduling (Automatic Daily Trigger)

The hook fires on `cron:daily`. To verify it's scheduled:

```json
{ "tool": "cron", "action": "list" }
```

To trigger immediately without waiting for the daily cron:

```json
{ "tool": "cron", "action": "run", "jobId": "interview-prep-daily" }
```

## Dashboard Features

The local web dashboard at `apps/interview-dashboard/index.html` provides:

- **Category filter tabs** — filter by domain (OWASP, Cloud, AD, LLM, Pentest)
- **Accordion answers** — click a question to reveal the full answer
- **Total question count** display
- **Auto-refresh** from `data.json` on page load

## Usage from Agent

```
Generate today's 50 security interview questions across all 5 domains and update the dashboard
Run the interview-prep-daily hook now and broadcast to all channels
Generate 15 questions specifically about Kerberoasting and Active Directory pivoting
Show me the current questions in the dashboard categorized by Cloud Security
Update data.json with 10 new LLM Security questions about prompt injection
```
