---
name: nextcloud-talk
description: "Send and receive messages on Nextcloud Talk via the OpenClaw `message` tool. Use when: (1) sending alerts to a self-hosted Nextcloud Talk conversation, (2) managing messages in Nextcloud Talk rooms, (3) working with privacy-first self-hosted team comms. Requires Nextcloud server URL and credentials in openclaw.json."
metadata:
  {
    "openclaw":
      {
        "emoji": "☁️",
        "requires": { "config": ["channels.nextcloud.serverUrl", "channels.nextcloud.username"] },
      },
  }
---

# Nextcloud Talk Channel

Send and receive messages on self-hosted Nextcloud Talk.

## Setup

```json5
{
  channels: {
    nextcloud: {
      serverUrl: "https://nextcloud.example.com",
      username: "bot",
      password: "YOUR_APP_PASSWORD",
      enabled: true,
    },
  },
}
```

Create an app password: Nextcloud → Settings → Security → App Passwords.

## Common Operations

### Send to a Room

```json
{
  "tool": "message",
  "action": "send",
  "provider": "nextcloud",
  "to": "room_token",
  "text": "🔴 Daily security scan complete — 2 critical findings"
}
```

### Read Messages

```json
{
  "tool": "message",
  "action": "read",
  "provider": "nextcloud",
  "to": "room_token",
  "limit": 30
}
```

### List Rooms

```json
{
  "tool": "message",
  "action": "channel-list",
  "provider": "nextcloud"
}
```

### React to a Message

```json
{
  "tool": "message",
  "action": "react",
  "provider": "nextcloud",
  "to": "room_token",
  "messageId": "message_id",
  "emoji": "✅"
}
```

## Notes

> [!NOTE]
> Room tokens are short strings visible in the Nextcloud Talk URL (e.g., `abc1de2f`).
> Nextcloud Talk is self-hosted — ideal for organizations requiring data sovereignty.

## Usage from Agent

```
Send a Nextcloud Talk message to the security room: "Engagement briefing ready"
List all Nextcloud Talk rooms the bot is a member of
Read the latest messages from the ops room in Nextcloud Talk
```
