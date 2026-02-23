---
name: cron
description: "Gateway cron job management via the `cron` tool. Use when: (1) scheduling recurring agent tasks, (2) setting up one-shot delayed jobs, (3) listing/managing existing cron jobs, (4) triggering immediate wakeups. NOT for: one-off background commands (use exec), or long-running persistent tasks (use background exec)."
metadata: { "openclaw": { "emoji": "🕐" } }
---

# Cron — Gateway Job Scheduling

Schedule recurring or one-shot tasks on the OpenClaw Gateway.

## When to Use

✅ **USE this skill when:**

- Scheduling recurring agent heartbeats or checks
- Setting up a delayed one-shot task
- Listing or managing existing scheduled jobs
- Triggering an immediate gateway wakeup with `wake`

## When NOT to Use

❌ **DON'T use this skill when:**

- Running a one-off background command now → use `exec` with `background: true`
- Persisting long-running monitoring → combine `exec` + `process` polling

## Actions

| Action   | Description                               |
| -------- | ----------------------------------------- |
| `status` | Current cron state                        |
| `list`   | List all scheduled jobs                   |
| `add`    | Add a new cron job                        |
| `update` | Patch an existing job                     |
| `remove` | Delete a job by id                        |
| `run`    | Immediately trigger a job                 |
| `runs`   | Job run history                           |
| `wake`   | Enqueue system event + optional heartbeat |

## Common Patterns

### List All Jobs

```json
{ "tool": "cron", "action": "list" }
```

### Add a Recurring Job

```json
{
  "tool": "cron",
  "action": "add",
  "job": {
    "id": "daily-recon",
    "schedule": "0 6 * * *",
    "task": "Run daily recon scan against scope targets",
    "agentId": "red-team"
  }
}
```

### Add a One-Shot Job

```json
{
  "tool": "cron",
  "action": "add",
  "job": {
    "id": "one-shot-report",
    "schedule": "2026-03-01T08:00:00Z",
    "task": "Generate and send weekly pentest summary report",
    "agentId": "main",
    "once": true
  }
}
```

### Update a Job

```json
{
  "tool": "cron",
  "action": "update",
  "jobId": "daily-recon",
  "patch": { "schedule": "0 7 * * 1-5" }
}
```

### Remove a Job

```json
{ "tool": "cron", "action": "remove", "jobId": "daily-recon" }
```

### Trigger a Job Immediately

```json
{ "tool": "cron", "action": "run", "jobId": "daily-recon" }
```

### Wake the Gateway

Enqueue a system event and optionally trigger an immediate heartbeat:

```json
{ "tool": "cron", "action": "wake" }
```

## Cron Schedule Format

Standard 5-field cron:

```
┌─── minute (0–59)
│ ┌─── hour (0–23)
│ │ ┌─── day of month (1–31)
│ │ │ ┌─── month (1–12)
│ │ │ │ ┌─── day of week (0–7, 0/7=Sun)
* * * * *
```

| Schedule      | Meaning               |
| ------------- | --------------------- |
| `* * * * *`   | Every minute          |
| `0 * * * *`   | Every hour            |
| `0 6 * * *`   | Daily at 06:00        |
| `0 9 * * 1`   | Every Monday at 09:00 |
| `0 6 * * 1-5` | Weekdays at 06:00     |
| `0 0 1 * *`   | Monthly on the 1st    |

## Usage from Agent

```
Schedule a daily recon scan at 06:00 UTC against the target scope
List all currently active cron jobs
Remove the daily-recon cron job
Trigger the weekly-report job immediately
Wake the gateway to process pending events
```
