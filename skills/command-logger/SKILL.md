---
name: command-logger
description: "Centralized audit logging for all agent commands via the command-logger hook. Fires on every command event and writes timestamped entries to a local log file. Use when: (1) auditing all commands run during an engagement, (2) building compliance logs for authorized penetration tests, (3) reviewing what commands the agent executed."
metadata: { "openclaw": { "emoji": "📝" } }
---

# Command Logger Hook

Centralized, timestamped audit log for every agent command — compliance-ready engagement logging.

## When to Use

✅ **USE this skill when:**

- Maintaining an audit trail during an authorized penetration test
- Building compliance logs for engagements requiring evidence of agent actions
- Reviewing what commands were executed across sessions
- Forensic review of agent activity after an engagement

## How It Works

The `command-logger` hook fires on every command event and writes:

```json
{
  "timestamp": "2026-02-23T07:12:34Z",
  "sessionId": "agent:red-team:main",
  "command": "exec",
  "args": { "command": "nmap -sV 192.168.1.10", "host": "gateway" },
  "result": "success"
}
```

Entries are appended to a daily log file:

```
logs/commands/2026-02-23.jsonl
```

## Enable

```json5
{
  hooks: {
    entries: {
      "command-logger": {
        enabled: true,
        config: {
          logDir: "logs/commands",
          includeToolResults: false,
          includeSessionId: true,
        },
      },
    },
  },
}
```

## Log Format

Each line is a JSON object (JSONL format):

| Field        | Description             |
| ------------ | ----------------------- |
| `timestamp`  | ISO 8601 UTC            |
| `sessionId`  | Agent session key       |
| `command`    | Tool name               |
| `args`       | Tool arguments          |
| `result`     | `success` or `error`    |
| `error`      | Error message if failed |
| `durationMs` | Execution time          |

## Query the Logs

```bash
# All exec tool calls today
grep '"command":"exec"' logs/commands/2026-02-23.jsonl | jq .

# Failed commands
grep '"result":"error"' logs/commands/2026-02-23.jsonl | jq .

# Commands by host=gateway
grep 'host.*gateway' logs/commands/2026-02-23.jsonl | jq .
```

Or ask the agent:

```
Show me all exec commands run today from the audit log
What tool calls failed in today's engagement session?
Extract all nmap commands from the command log
```

## Retention

By default, logs are kept locally and never auto-deleted. Set up rotation:

```bash
# Keep 30 days of logs
find logs/commands/ -name "*.jsonl" -mtime +30 -delete
```

## Usage from Agent

```
Show me the command log for today's engagement session
List all failed tool calls from the logs/commands directory
Extract all exec commands from the command audit log for the report
How many total commands were run in the last engagement?
```
