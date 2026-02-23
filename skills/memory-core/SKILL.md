---
name: memory-core
description: "Search and retrieve agent memory via `memory_search` and `memory_get` tools. Use when: (1) recalling facts, notes, or context saved in a previous session, (2) persisting important information for future sessions, (3) building agents with long-term memory across conversations. Requires memory-core plugin enabled in openclaw.json."
metadata: { "openclaw": { "emoji": "🧠" } }
---

# Memory Core — Long-Term Agent Memory

Search and retrieve facts stored across sessions using the memory plugin.

## When to Use

✅ **USE this skill when:**

- Recalling information stored in a previous session (user prefs, targets, findings)
- Persisting important information so it's available in future sessions
- Building agents that remember context across conversations
- Looking up past engagement notes, credentials, or scope definitions

## When NOT to Use

❌ **DON'T use this skill when:**

- Reading current session context (just reference earlier messages)
- File storage → use `write`/`read` tools
- Structured DB queries → use the relevant DB skill

## Enable Memory

```json5
{
  plugins: {
    entries: {
      "memory-core": { enabled: true },
    },
  },
}
```

## Tools

| Tool            | Description                          |
| --------------- | ------------------------------------ |
| `memory_search` | Semantic search over stored memories |
| `memory_get`    | Retrieve a specific memory by ID     |

## Common Patterns

### Search Memory

```json
{
  "tool": "memory_search",
  "query": "target scope for Acme engagement"
}
```

```json
{
  "tool": "memory_search",
  "query": "credentials or API keys found during pentest",
  "limit": 5
}
```

### Get a Specific Memory

```json
{
  "tool": "memory_get",
  "id": "memory_id"
}
```

### What Gets Stored

Memory is typically written by the agent during `/new` or `/reset` (via the `session-memory` hook), or explicitly when you ask:

```
Remember that the target scope for Project Alpha is 192.168.10.0/24
Save the finding: SQL injection on /api/v1/search?q= parameter
```

## Config

```json5
{
  plugins: {
    entries: {
      "memory-core": {
        enabled: true,
        config: {
          maxMemories: 1000,
          embeddingModel: "text-embedding-3-small",
        },
      },
    },
  },
}
```

## Usage from Agent

```
Search memory for the target scope defined last week
Recall any credentials or API tokens discovered in previous sessions
What did I save about the Acme Corp engagement findings?
Search memory for anything related to the cloud infrastructure enumeration
```
