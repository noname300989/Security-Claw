---
name: subagent-spawner
description: "Spawn and manage sub-agent runs via `sessions_spawn` and `/subagents`. Use when: (1) parallelizing slow/long tasks without blocking the main agent, (2) running isolated research or scans as background workers, (3) orchestrating multi-agent pipelines, (4) creating thread-bound Discord sub-agent sessions. NOT for: simple background shell commands (use exec), or scheduled recurring tasks (use cron)."
metadata: { "openclaw": { "emoji": "🤖" } }
---

# Sub-Agent Spawner

Spawn isolated background agent runs and orchestrate multi-agent pipelines.

## When to Use

✅ **USE this skill when:**

- Parallelizing long research, recon, or analysis tasks
- Running isolated agent work without blocking the main conversation
- Orchestrating worker agents from an orchestrator (depth-2 pattern)
- Binding a sub-agent session to a Discord thread for persistent follow-up

## When NOT to Use

❌ **DON'T use this skill when:**

- Running a background shell command → use `exec` with `background: true`
- Scheduling a future task → use `cron` tool
- Sending a message to an existing session → use `sessions_send`

## Spawn a Sub-Agent

```json
{
  "tool": "sessions_spawn",
  "task": "Enumerate subdomains for example.com and return a list of live hosts",
  "label": "subdomain-enum",
  "agentId": "red-team"
}
```

### With Model Override

```json
{
  "tool": "sessions_spawn",
  "task": "Summarize the CVE findings in evidence/scan.json",
  "label": "cve-summary",
  "model": "claude-haiku-3"
}
```

### With Timeout

```json
{
  "tool": "sessions_spawn",
  "task": "Run a full nuclei scan against 192.168.1.0/24",
  "label": "nuclei-scan",
  "runTimeoutSeconds": 600
}
```

### Thread-Bound (Discord)

Bind the sub-agent to a Discord thread for persistent follow-up:

```json
{
  "tool": "sessions_spawn",
  "task": "Assist with post-exploitation enumeration",
  "label": "post-ex-helper",
  "thread": true,
  "mode": "session"
}
```

## Slash Commands

Manage sub-agents from the chat:

```
/subagents list                         ← list all active sub-agents
/subagents info <id|#>                  ← details about a specific run
/subagents log <id|#> 50                ← last 50 lines of output
/subagents kill <id|#|all>              ← stop a sub-agent
/subagents send <id|#> <message>        ← send a message to the sub-agent
/subagents steer <id|#> <message>       ← inject steering guidance
/subagents spawn <agentId> <task>       ← manually spawn from chat
```

## Discover Available Agents

```json
{ "tool": "agents_list" }
```

## List Sessions

```json
{ "tool": "sessions_list", "kinds": ["subagent"], "limit": 10 }
```

## Read Sub-Agent History

```json
{ "tool": "sessions_history", "sessionKey": "agent:red-team:subagent:<uuid>", "limit": 20 }
```

## Orchestrator Pattern (depth-2)

Enable nested spawning in config:

```json5
{
  agents: {
    defaults: {
      subagents: {
        maxSpawnDepth: 2,
        maxChildrenPerAgent: 5,
        maxConcurrent: 8,
      },
    },
  },
}
```

Flow:

```
Main agent
  └── Orchestrator sub-agent (depth 1) — spawns workers
        ├── Worker A (depth 2) — recon scan
        ├── Worker B (depth 2) — vuln scan
        └── Worker C (depth 2) — report generation
```

Each worker announces results back to the orchestrator, which synthesizes and announces to main.

## Announce Behavior

When a sub-agent finishes, it posts an announce message back to the requester chat:

```
Status: completed successfully
Result: Found 3 live subdomains: api.example.com, dev.example.com, staging.example.com
runtime 2m14s | 1,200 in / 340 out tokens
```

Reply `ANNOUNCE_SKIP` from sub-agent to suppress the announcement.

## Cleanup Options

| `cleanup`        | Behavior                                  |
| ---------------- | ----------------------------------------- |
| `keep` (default) | Session stays until auto-archive (60 min) |
| `delete`         | Archive immediately after announce        |

## Usage from Agent

```
Spawn a sub-agent to run a full recon scan against example.com in parallel
List all currently running sub-agents and their status
Kill the subdomain-enum sub-agent
Spawn three parallel workers: one for recon, one for vuln scanning, one for reporting
Create a thread-bound Discord sub-agent for interactive post-exploitation assistance
```
