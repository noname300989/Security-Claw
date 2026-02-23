---
name: lobster
description: "Run deterministic multi-step workflows with approval gates via the `lobster` tool. Use when: (1) running a multi-step pipeline where side-effects need explicit approval, (2) automating complex workflows that need to pause and resume, (3) chaining CLI tools in a typed pipeline with JSON piping. Requires lobster CLI installed and plugin enabled."
metadata:
  {
    "openclaw":
      {
        "emoji": "🦞",
        "requires": { "bins": ["lobster"] },
        "install":
          [
            {
              "id": "lobster-install",
              "kind": "shell",
              "cmd": "brew install openclaw/tap/lobster || cargo install lobster-cli",
              "bins": ["lobster"],
              "label": "Install Lobster CLI",
            },
          ],
      },
  }
---

# Lobster — Deterministic Workflow Runtime

Run typed, resumable pipelines with built-in approval gates. One tool call executes the whole pipeline.

## When to Use

✅ **USE this skill when:**

- Running multi-step pipelines where each step feeds the next (JSON piping)
- Any step has a side effect (send email, post message, exec on host) needing explicit approval
- You need to resume a halted workflow without re-running completed steps
- Replacing many back-and-forth agent tool calls with a single deterministic run

## When NOT to Use

❌ **DON'T use this skill when:**

- Simple one-off commands → use `exec`
- Interactive tool sessions → use `exec` with PTY
- Scheduling recurring tasks → use `cron` + `exec`

## Enable the Plugin

```json5
{
  tools: { alsoAllow: ["lobster"] },
}
```

## Run a Pipeline

```json
{
  "tool": "lobster",
  "action": "run",
  "pipeline": "inbox list --json | inbox categorize --json | inbox apply --json",
  "timeoutMs": 30000
}
```

## Run a Workflow File

```json
{
  "tool": "lobster",
  "action": "run",
  "pipeline": "/workflows/daily-report.lobster",
  "argsJson": "{\"target\": \"example.com\"}"
}
```

## Resume After Approval

When a pipeline pauses at an `approve` step, it returns a `resumeToken`:

```json
{
  "tool": "lobster",
  "action": "resume",
  "token": "<resumeToken>",
  "approve": true
}
```

Deny and cancel:

```json
{
  "tool": "lobster",
  "action": "resume",
  "token": "<resumeToken>",
  "approve": false
}
```

## Workflow File Format (.lobster)

```yaml
name: recon-pipeline
args:
  target:
    default: "example.com"
steps:
  - id: subdomain-enum
    command: subfinder -d ${target} --json
  - id: live-check
    command: httpx --json
    stdin: $subdomain-enum.stdout
  - id: approve-scan
    command: echo "Proceed with vuln scan?"
    approval: required
  - id: vuln-scan
    command: nuclei -u ${target} -severity critical,high -json
    condition: $approve-scan.approved
```

## JSON Piping Pattern

Build CLI commands that speak JSON, then chain them:

```bash
# Each tool outputs JSON, next tool reads it
gog.gmail.search --query 'newer_than:1d' \
  | openclaw.invoke --tool message --action send \
    --each --item-key message \
    --args-json '{"provider":"telegram","to":"chat_id"}'
```

## Output Envelope

| Status           | Meaning                                 |
| ---------------- | --------------------------------------- |
| `ok`             | Pipeline finished successfully          |
| `needs_approval` | Paused at `approve` step — use `resume` |
| `cancelled`      | Explicitly denied / cancelled           |

## Safety

> [!NOTE]
> Lobster runs as a local subprocess only — no network calls from the plugin. Sandbox-aware: disabled in sandboxed agent contexts.

## Usage from Agent

```
Run the daily email triage lobster pipeline
Execute the recon-pipeline.lobster against example.com
Resume the halted pipeline with approve=true
Run the report-generation workflow and pause before sending
```
