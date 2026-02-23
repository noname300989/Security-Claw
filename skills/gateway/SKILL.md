---
name: gateway
description: "Gateway process management via the `gateway` tool. Use when: (1) restarting the gateway after config changes, (2) reading or patching openclaw.json config, (3) applying gateway updates in-place, (4) inspecting the config schema. NOT for: scheduling tasks (use cron), running shell commands (use exec), or managing nodes (use nodes)."
metadata: { "openclaw": { "emoji": "🔧" } }
---

# Gateway — Process Control & Config Management

Restart, reconfigure, and update the running OpenClaw Gateway process.

## When to Use

✅ **USE this skill when:**

- Applying config changes that require a restart
- Reading or patching `openclaw.json` programmatically
- Rolling out a gateway update in-place
- Inspecting the full config schema for a setting

## When NOT to Use

❌ **DON'T use this skill when:**

- Scheduling recurring jobs → use `cron` tool
- Running shell commands on the host → use `exec` with `host=gateway`
- Managing paired nodes → use `nodes` tool
- Enabling/disabling channels or agents → edit config then use `gateway config.patch`

## Actions

| Action          | Description                             |
| --------------- | --------------------------------------- |
| `restart`       | In-place restart (sends `SIGUSR1`)      |
| `config.get`    | Read current config (or a specific key) |
| `config.schema` | Get the JSON schema for config keys     |
| `config.apply`  | Validate + write full config + restart  |
| `config.patch`  | Merge a partial update + restart        |
| `update.run`    | Run gateway update + restart            |

## Common Patterns

### Restart the Gateway

```json
{ "tool": "gateway", "action": "restart" }
```

Add a delay to avoid interrupting in-flight replies:

```json
{ "tool": "gateway", "action": "restart", "delayMs": 3000 }
```

### Read Current Config

```json
{ "tool": "gateway", "action": "config.get" }
```

Read a specific key:

```json
{ "tool": "gateway", "action": "config.get", "key": "tools.web.search" }
```

### Inspect Schema for a Setting

```json
{ "tool": "gateway", "action": "config.schema", "key": "agents.defaults" }
```

### Patch Config (partial update)

Most common way to change settings without replacing the full config:

```json
{
  "tool": "gateway",
  "action": "config.patch",
  "patch": {
    "tools": {
      "web": { "search": { "enabled": true } }
    }
  }
}
```

Enables web search, restarts, and wakes the gateway automatically.

### Apply Full Config

Write and validate a complete config, then restart:

```json
{
  "tool": "gateway",
  "action": "config.apply",
  "config": { "...": "full openclaw.json contents here" }
}
```

### Run Gateway Update

In-place update to the latest release:

```json
{ "tool": "gateway", "action": "update.run" }
```

## Safety Notes

> [!CAUTION]
> `config.apply` replaces the entire config. Prefer `config.patch` for targeted changes to avoid accidentally removing existing settings.

> [!NOTE]
> `restart` defaults to `delayMs: 2000`. Increase this if a long reply is in-flight.

## Config

Disable restart command (if you want to block agents from restarting):

```json5
{ commands: { restart: false } }
```

## Usage from Agent

```
Enable web search in the config and restart the gateway
Read the current tools.exec config
Patch the gateway config to set agents.defaults.model to claude-opus-4-7
Run the gateway update to upgrade to the latest version
Show the JSON schema for the cron config section
```
