---
name: session-memory
description: "Save and restore session context to long-term memory via the session-memory hook. Fires on /new or /reset commands to persist key context before clearing the session. Works with the memory-core plugin to maintain continuity across sessions. Use when: needing to preserve findings, targets, or context before starting a new session."
metadata: { "openclaw": { "emoji": "💾" } }
---

# Session Memory Hook

Automatically saves key session context to long-term memory before a session is cleared.

## When to Use

✅ **USE this skill when:**

- You're about to use `/new` or `/reset` and want to preserve current context
- You want the agent to automatically persist findings before starting a fresh session
- You need continuity between engagement sessions (target scope, findings, credentials)

## How It Works

The `session-memory` hook fires on `/new` or `/reset` commands and:

1. Scans the current session for key facts (targets, findings, credentials, scope)
2. Extracts and saves them to the `memory-core` long-term memory store
3. Clears the session as requested
4. In the new session, the agent can recall saved context via `memory_search`

## Requires

- `memory-core` plugin enabled
- `session-memory` hook enabled

```json5
{
  plugins: {
    entries: {
      "memory-core": { enabled: true },
      "session-memory": { enabled: true },
    },
  },
}
```

## What Gets Saved

The hook extracts and saves:

- Active engagement targets and scope
- Key findings and vulnerabilities discovered
- Credentials or API tokens found (securely tagged)
- Tool configurations or custom settings applied
- Outstanding tasks or next steps

## Recall in Future Sessions

After saving, use `memory_search` to recall:

```json
{ "tool": "memory_search", "query": "target scope from last engagement" }
```

Or just ask:

```
What do you remember from the previous engagement sessions?
Recall the findings from the Acme Corp pentest session
What targets and scope were saved last time?
```

## Manual Save

You can ask to save context at any time without resetting:

```
Save the current engagement findings to long-term memory before we clear the session
Remember the target scope: 192.168.10.0/24 and web app at https://target.example.com
```

## Usage from Agent

```
Save all current session context to memory then start a new session
What was saved from the previous engagement session?
Recall any findings about SQL injection from earlier sessions
Persist the current target scope and critical findings before we move on
```
