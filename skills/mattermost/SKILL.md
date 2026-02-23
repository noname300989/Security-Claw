---
name: mattermost
description: "Send and receive messages on Mattermost via the OpenClaw `message` tool. Use when: (1) sending alerts or reports to a Mattermost channel or DM, (2) managing threads and reactions, (3) working with self-hosted Mattermost deployments. Requires Mattermost bot token and server URL in openclaw.json."
metadata:
  {
    "openclaw":
      {
        "emoji": "⚡",
        "requires": { "config": ["channels.mattermost.serverUrl", "channels.mattermost.token"] },
      },
  }
---

# Mattermost Channel

Send and receive messages on self-hosted or cloud Mattermost instances.

## Setup

```json5
{
  channels: {
    mattermost: {
      serverUrl: "https://mattermost.example.com",
      token: "YOUR_BOT_TOKEN",
      enabled: true,
    },
  },
}
```

Create a bot token: Mattermost → Integrations → Bot Accounts → Add Bot Account.

## Common Operations

### Send a Message

```json
{
  "tool": "message",
  "action": "send",
  "provider": "mattermost",
  "to": "channel_id or @username",
  "text": "🔴 Alert: Critical vulnerability confirmed on target host"
}
```

### Send with Attachment

```json
{
  "tool": "message",
  "action": "send",
  "provider": "mattermost",
  "to": "channel_id",
  "text": "Engagement report attached",
  "media": ["/reports/final_report.pdf"]
}
```

### Reply to a Thread

```json
{
  "tool": "message",
  "action": "thread-reply",
  "provider": "mattermost",
  "to": "channel_id",
  "threadId": "post_id",
  "text": "Remediation verified — closing this finding"
}
```

### React to a Post

```json
{
  "tool": "message",
  "action": "react",
  "provider": "mattermost",
  "to": "channel_id",
  "messageId": "post_id",
  "emoji": "white_check_mark"
}
```

### List Channels

```json
{
  "tool": "message",
  "action": "channel-list",
  "provider": "mattermost"
}
```

## Usage from Agent

```
Send a Mattermost message to the security channel: "Scan complete"
Post the daily vulnerability summary to Mattermost
Reply to the existing thread with remediation confirmation
React with ✅ to the patch deployment message in Mattermost
```
