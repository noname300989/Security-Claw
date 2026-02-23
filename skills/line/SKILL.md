---
name: line
description: "Send messages on LINE via the OpenClaw `message` tool. Use when: (1) notifying a LINE user or group about security events, (2) sending alerts to a LINE channel in Asia-Pacific contexts (Japan, Thailand, Taiwan). Requires LINE channel access token configured in openclaw.json."
metadata:
  { "openclaw": { "emoji": "💚", "requires": { "config": ["channels.line.channelAccessToken"] } } }
---

# LINE Channel

Send messages and alerts to LINE users and groups.

## Setup

1. Create a LINE Messaging API channel at [LINE Developers](https://developers.line.biz/)
2. Get the Channel Access Token
3. Configure in `openclaw.json`:

```json5
{
  channels: {
    line: {
      channelAccessToken: "YOUR_CHANNEL_ACCESS_TOKEN",
      channelSecret: "YOUR_CHANNEL_SECRET",
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
  "provider": "line",
  "to": "user_id or group_id",
  "text": "🔴 Security Alert: Critical issue detected in production"
}
```

### Send Media

```json
{
  "tool": "message",
  "action": "send",
  "provider": "line",
  "to": "user_id",
  "text": "Vulnerability evidence",
  "media": ["/evidence/screenshot.png"]
}
```

### Reply to a Message

```json
{
  "tool": "message",
  "action": "send",
  "provider": "line",
  "to": "user_id",
  "text": "Patch applied and verified.",
  "replyTo": "reply_token"
}
```

## Notes

> [!NOTE]
> LINE is the dominant messaging app in Japan, Thailand, and Taiwan. Use for Asia-Pacific team notifications.

## Usage from Agent

```
Send a LINE message to the Japan security team group: "Daily report ready"
Notify the LINE user with the critical finding alert
Send the evidence screenshot via LINE
```
