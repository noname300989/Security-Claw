---
name: daily-summary
description: "Trigger and review the daily agent activity summary via the daily-summary hook. Use when: (1) requesting a summary of today's agent actions, tool calls, and session outputs, (2) triggering the daily briefing manually before the scheduled cron:daily run. Triggered automatically at end of each day via the cron:daily hook."
metadata: { "openclaw": { "emoji": "📋" } }
---

# Daily Summary Hook

Automatically generates and distributes a daily summary of all agent activity.

## When to Use

✅ **USE this skill when:**

- Requesting a summary of today's agent sessions, findings, and tool calls
- Triggering the daily briefing on-demand before the scheduled run
- Reviewing what the agent accomplished across all engagements today

## How It Works

The `daily-summary` hook fires on `cron:daily` and:

1. Collects session logs from the day's agent runs
2. Summarizes key actions, findings, and outputs across all sessions
3. Sends the summary to all configured messaging channels (WhatsApp, Telegram, Discord)

## Trigger On-Demand

### Via cron tool

```json
{ "tool": "cron", "action": "run", "jobId": "daily-summary" }
```

### By asking the agent

```
Generate and send today's daily activity summary to all channels
Summarize everything that happened in today's agent sessions
```

## What Gets Included

- Sessions started and completed today
- Tool calls made per session (exec, browser, nuclei, etc.)
- Key findings or outputs surfaced during sessions
- Errors or failures that need attention
- Token usage summary

## Notification Format

The hook broadcasts to all configured channels:

```
📋 Daily Agent Summary — 2026-02-23
Sessions: 4 completed, 0 failed
Key actions:
  • Recon scan on example.com — 3 live subdomains found
  • Nuclei scan — 1 critical CVE confirmed
  • Report generated and saved to /reports/2026-02-23.md
Tokens used today: 45,230 in / 12,890 out
```

## Config

```json5
{
  cron: {
    jobs: [
      {
        id: "daily-summary",
        schedule: "0 22 * * *",
        task: "Generate and send daily agent activity summary",
      },
    ],
  },
}
```

## Usage from Agent

```
Trigger the daily summary now and send to all channels
What did the agent do today?
Summarize all sessions and tool calls from the past 24 hours
```
