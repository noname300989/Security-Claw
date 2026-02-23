---
name: googlechat
description: "Send and receive messages on Google Chat via the OpenClaw `message` tool. Use when: (1) sending alerts or reports to a Google Chat space or DM, (2) posting card messages with structured content, (3) managing threads in Google Chat spaces. Requires Google Chat Webhook or bot configuration."
metadata: { "openclaw": { "emoji": "💬", "requires": { "config": ["channels.googlechat"] } } }
---

# Google Chat Channel

Send messages, cards, and manage threads in Google Chat spaces.

## Setup

```json5
{
  channels: {
    googlechat: {
      serviceAccountKey: "/path/to/service-account.json",
      enabled: true,
    },
  },
}
```

Or using a webhook URL for simple posting:

```json5
{
  channels: {
    googlechat: {
      webhookUrl: "https://chat.googleapis.com/v1/spaces/.../messages?key=...&token=...",
      enabled: true,
    },
  },
}
```

## Common Operations

### Send a Plain Message

```json
{
  "tool": "message",
  "action": "send",
  "provider": "googlechat",
  "to": "space_id or webhook",
  "text": "🔴 Security Alert: 3 critical CVEs detected in production"
}
```

### Send a Card

```json
{
  "tool": "message",
  "action": "send",
  "provider": "googlechat",
  "to": "space_id",
  "card": {
    "header": { "title": "Security Report", "subtitle": "Daily Summary" },
    "sections": [
      {
        "widgets": [{ "textParagraph": { "text": "Critical: 3 | High: 8 | Medium: 14" } }]
      }
    ]
  }
}
```

### Reply to a Thread

```json
{
  "tool": "message",
  "action": "thread-reply",
  "provider": "googlechat",
  "to": "space_id",
  "threadId": "thread_key",
  "text": "Patch confirmed. All clear."
}
```

### List Spaces

```json
{
  "tool": "message",
  "action": "channel-list",
  "provider": "googlechat"
}
```

## Usage from Agent

```
Send a Google Chat message to the security space: "Daily scan complete"
Post a card to Google Chat with today's vulnerability summary
Reply to the existing thread in the security space with patch status
```
