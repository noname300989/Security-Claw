---
name: exec-process
description: "Shell command execution via the `exec` tool and background process management via `process`. Use when: (1) running shell commands in the workspace, (2) backgrounding long-running tasks, (3) polling output from running processes, (4) sending stdin/keys to interactive processes, (5) targeting gateway or node hosts. NOT for: browser interaction (use browser tool), node notifications (use nodes tool), or cron scheduling (use cron tool)."
metadata: { "openclaw": { "emoji": "⚙️" } }
---

# Exec + Process — Shell Execution & Background Management

Run commands in the workspace, gateway, or paired node hosts. Use `process` to manage long-running background tasks.

## When to Use

✅ **USE this skill when:**

- Running build, test, or install commands in the workspace
- Executing long-running tools (scans, builds) in the background
- Sending stdin / key sequences to interactive processes (e.g. tmux, REPLs)
- Targeting the gateway host with `host=gateway` (elevated access)
- Running commands on a paired macOS node with `host=node`

## When NOT to Use

❌ **DON'T use this skill when:**

- Interacting with web pages → use `browser` tool
- Sending push notifications to devices → use `nodes` tool
- Scheduling recurring tasks → use `cron` tool
- Running structured LLM steps in workflows → use `llm-task` plugin

## Exec Parameters

| Parameter    | Default   | Notes                               |
| ------------ | --------- | ----------------------------------- |
| `command`    | required  | Shell command string                |
| `workdir`    | cwd       | Working directory override          |
| `env`        | —         | Key/value env overrides             |
| `yieldMs`    | 10000     | Auto-background after delay (ms)    |
| `background` | false     | Immediately background              |
| `timeout`    | 1800      | Kill process after N seconds        |
| `pty`        | false     | Pseudo-terminal (for TTY-only CLIs) |
| `host`       | auto      | `sandbox` \| `gateway` \| `node`    |
| `security`   | auto      | `deny` \| `allowlist` \| `full`     |
| `ask`        | `on-miss` | Approval mode for gateway/node      |
| `node`       | —         | Node id/name for `host=node`        |
| `elevated`   | false     | Request elevated gateway mode       |

> [!NOTE]
> `host` defaults to `sandbox` when sandbox runtime is active, `gateway` otherwise.

## Common Patterns

### 1. Foreground Command

```json
{ "tool": "exec", "command": "ls -la" }
```

```bash
# Run a build
npm run build

# Run tests
pytest tests/ -v

# Install dependencies
pip install -r requirements.txt
```

### 2. Background + Poll

Background a long-running command, then poll for completion:

```json
{ "tool": "exec", "command": "npm run build", "yieldMs": 1000 }
```

Once backgrounded, use `process` to poll:

```json
{ "tool": "process", "action": "poll", "sessionId": "<id>" }
```

### 3. List / Tail Background Sessions

```json
{ "tool": "process", "action": "list" }
{ "tool": "process", "action": "log", "sessionId": "<id>", "limit": 50 }
```

### 4. Send Keys to Interactive Process

For REPLs, `msfconsole`, `python3`, etc.:

```json
{ "tool": "process", "action": "send-keys", "sessionId": "<id>", "keys": ["Enter"] }
{ "tool": "process", "action": "send-keys", "sessionId": "<id>", "keys": ["C-c"] }
{ "tool": "process", "action": "submit", "sessionId": "<id>" }
```

Paste multi-line content:

```json
{ "tool": "process", "action": "paste", "sessionId": "<id>", "text": "line1\nline2\n" }
```

### 5. Kill / Clear Sessions

```json
{ "tool": "process", "action": "kill", "sessionId": "<id>" }
{ "tool": "process", "action": "clear" }
```

### 6. Gateway / Elevated Execution

Run on the gateway host with full access:

```json
{
  "tool": "exec",
  "command": "systemctl status openclaw",
  "host": "gateway",
  "security": "full",
  "elevated": true
}
```

### 7. Node Execution

Run on a paired macOS companion:

```json
{ "tool": "exec", "command": "say 'Task complete'", "host": "node", "node": "mac-1" }
```

### 8. PTY Mode (TTY-only CLIs)

For tools that require a real terminal:

```json
{ "tool": "exec", "command": "htop", "pty": true }
```

## Per-Session Override

Use `/exec` in chat to set session defaults:

```
/exec host=gateway security=allowlist ask=on-miss node=mac-1
/exec            ← show current values
```

## Config

```json5
{
  tools: {
    exec: {
      pathPrepend: ["~/bin", "/opt/tools/bin"],
      notifyOnExit: true,
      host: "gateway",
      security: "allowlist",
      ask: "on-miss",
    },
  },
}
```

## Usage from Agent

```
Run the test suite in the background and poll until complete
Execute nmap -sV 192.168.1.0/24 on the gateway host with elevated access
Start a python3 REPL and send commands to it interactively
Kill all backgrounded exec sessions
```
