---
name: matrix
description: "Send and receive messages on Matrix (Element) via the OpenClaw `message` tool. Use when: (1) sending alerts or reports to a Matrix room, (2) handling federated or self-hosted Matrix deployments, (3) managing threads or reactions in Matrix rooms. Requires Matrix homeserver URL and credentials configured in openclaw.json."
metadata:
  {
    "openclaw":
      {
        "emoji": "🔷",
        "requires": { "config": ["channels.matrix.homeserverUrl", "channels.matrix.accessToken"] },
      },
  }
---

# Matrix Channel

Send and receive messages in Matrix rooms (self-hosted or hosted, e.g. Element).

## Setup

```json5
{
  channels: {
    matrix: {
      homeserverUrl: "https://matrix.example.com",
      accessToken: "YOUR_ACCESS_TOKEN",
      enabled: true,
    },
  },
}
```

To get an access token: log in to Element → Settings → Help & About → Access Token.

## Common Operations

### Send a Message

```json
{
  "tool": "message",
  "action": "send",
  "provider": "matrix",
  "to": "!roomId:matrix.org",
  "text": "🔴 Alert: Scan finished — 3 critical findings"
}
```

### Send with Formatting (HTML)

```json
{
  "tool": "message",
  "action": "send",
  "provider": "matrix",
  "to": "!roomId:matrix.org",
  "text": "<b>CVE-2024-1234</b> — CVSS 9.8<br>Exploitation confirmed in lab"
}
```

### Reply in a Thread

```json
{
  "tool": "message",
  "action": "thread-reply",
  "provider": "matrix",
  "to": "!roomId:matrix.org",
  "threadId": "$event_id",
  "text": "Patch deployed. Thread closed."
}
```

### React to a Message

```json
{
  "tool": "message",
  "action": "react",
  "provider": "matrix",
  "to": "!roomId:matrix.org",
  "messageId": "$event_id",
  "emoji": "✅"
}
```

### Read Room History

```json
{
  "tool": "message",
  "action": "read",
  "provider": "matrix",
  "to": "!roomId:matrix.org",
  "limit": 50
}
```

### List Channels / Rooms

```json
{
  "tool": "message",
  "action": "channel-list",
  "provider": "matrix"
}
```

## Notes

> [!NOTE]
> Room IDs look like `!abc123:matrix.org`. User IDs look like `@alice:matrix.org`.
> Matrix supports federation — your bot can join rooms on other homeservers.

## Usage from Agent

```
Send a Matrix message to !security:matrix.example.com: "Daily report ready"
Post the scan results to the security Matrix room
List all Matrix rooms the bot has joined
Reply to the existing thread in the ops room with the patch status
```
