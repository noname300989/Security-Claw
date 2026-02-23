---
name: zalo
description: "Send and receive messages on Zalo (Vietnam's dominant messaging platform) via the OpenClaw `message` tool. Use when: (1) notifying a Zalo user or group about security events, (2) working with Vietnamese teams or partners. Requires Zalo OA (Official Account) credentials in openclaw.json."
metadata:
  {
    "openclaw":
      {
        "emoji": "🔵",
        "requires": { "config": ["channels.zalo.oaId", "channels.zalo.accessToken"] },
      },
  }
---

# Zalo Channel

Send messages and alerts via Zalo (the dominant messaging app in Vietnam).

## Setup

1. Create a Zalo Official Account at [oa.zalo.me](https://oa.zalo.me/)
2. Generate an access token from the OA dashboard
3. Configure in `openclaw.json`:

```json5
{
  channels: {
    zalo: {
      oaId: "YOUR_OA_ID",
      accessToken: "YOUR_ACCESS_TOKEN",
      enabled: true,
    },
  },
}
```

## Common Operations

### Send a Message

```json
{
  "tool": "message",
  "action": "send",
  "provider": "zalo",
  "to": "follower_id",
  "text": "🔴 Security Alert: Urgent vulnerability detected"
}
```

### Send Media

```json
{
  "tool": "message",
  "action": "send",
  "provider": "zalo",
  "to": "follower_id",
  "text": "Report attached",
  "media": ["/reports/daily_report.pdf"]
}
```

### Read Messages

```json
{
  "tool": "message",
  "action": "read",
  "provider": "zalo",
  "to": "follower_id"
}
```

## Notes

> [!NOTE]
> Zalo requires users to follow your Official Account before you can message them.
> Use primarily for Vietnam-based team notifications.

## Usage from Agent

```
Send a Zalo message to the Vietnam team follower: "Security scan complete"
Notify the Zalo user with the critical finding alert
```
