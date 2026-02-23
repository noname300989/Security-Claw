---
name: msteams
description: "Send and receive messages on Microsoft Teams via the OpenClaw `message` tool. Use when: (1) sending alerts, reports, or Adaptive Cards to a Teams channel or user, (2) creating polls in Teams, (3) managing threads, reactions, and pins in Teams channels. Requires Teams app configuration in openclaw.json."
metadata: { "openclaw": { "emoji": "🟣", "requires": { "config": ["channels.msteams"] } } }
---

# Microsoft Teams Channel

Send messages, Adaptive Cards, and manage interactions in Microsoft Teams.

## Setup

Configure via the Teams extension in `openclaw.json`. Requires an Azure bot registration:

```json5
{
  channels: {
    msteams: {
      appId: "YOUR_AZURE_APP_ID",
      appPassword: "YOUR_AZURE_APP_PASSWORD",
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
  "provider": "msteams",
  "to": "channel_id or user_id",
  "text": "🔴 Critical finding detected — see report"
}
```

### Send an Adaptive Card

```json
{
  "tool": "message",
  "action": "send",
  "provider": "msteams",
  "to": "channel_id",
  "card": {
    "type": "AdaptiveCard",
    "version": "1.4",
    "body": [
      { "type": "TextBlock", "text": "Security Report", "weight": "Bolder", "size": "Large" },
      { "type": "TextBlock", "text": "3 critical, 5 high, 12 medium findings", "wrap": true }
    ],
    "actions": [
      {
        "type": "Action.OpenUrl",
        "title": "View Full Report",
        "url": "https://reports.example.com"
      }
    ]
  }
}
```

### Create a Poll

```json
{
  "tool": "message",
  "action": "poll",
  "provider": "msteams",
  "to": "channel_id",
  "question": "Should we escalate this finding?",
  "options": ["Yes — critical", "No — false positive", "Needs more review"]
}
```

### Reply to a Thread

```json
{
  "tool": "message",
  "action": "thread-reply",
  "provider": "msteams",
  "to": "channel_id",
  "threadId": "thread_id",
  "text": "Patch confirmed. Issue closed."
}
```

### React to a Message

```json
{
  "tool": "message",
  "action": "react",
  "provider": "msteams",
  "to": "channel_id",
  "messageId": "message_id",
  "emoji": "👍"
}
```

### List Channels

```json
{
  "tool": "message",
  "action": "channel-list",
  "provider": "msteams"
}
```

## Usage from Agent

```
Send an Adaptive Card to the Teams security channel with today's findings summary
Post a plain message to the Teams ops channel: "Engagement complete"
Create a Teams poll in the security channel asking whether to escalate
Reply to the existing vulnerability thread with the patch status update
```
