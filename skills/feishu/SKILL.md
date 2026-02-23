---
name: feishu
description: "Send and receive messages on Feishu/Lark via the OpenClaw `message` tool. Use when: (1) sending alerts or reports to a Feishu user or group, (2) managing Feishu bot interactions, (3) working with the Feishu doc/drive/wiki via the feishu-doc, feishu-drive, or feishu-wiki skills. Requires Feishu app credentials configured in openclaw.json."
metadata:
  {
    "openclaw":
      {
        "emoji": "🪶",
        "requires": { "config": ["channels.feishu.appId", "channels.feishu.appSecret"] },
      },
  }
---

# Feishu / Lark Channel

Send and receive messages on Feishu (Lark) via the OpenClaw bot integration.

## Setup

1. Create a Feishu custom app at [open.feishu.cn](https://open.feishu.cn/)
2. Enable required scopes: `im:message`, `im:message:send_as_bot`
3. Configure in `openclaw.json`:

```json5
{
  channels: {
    feishu: {
      appId: "cli_xxx",
      appSecret: "YOUR_APP_SECRET",
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
  "provider": "feishu",
  "to": "user_id or chat_id",
  "text": "🚨 Security Alert: Critical issue found in production"
}
```

### Send Rich Card

```json
{
  "tool": "message",
  "action": "send",
  "provider": "feishu",
  "to": "chat_id",
  "card": {
    "config": { "wide_screen_mode": true },
    "elements": [
      {
        "tag": "div",
        "text": {
          "content": "**CVE-2024-1234** — CVSS 9.8\nRCE in login endpoint",
          "tag": "lark_md"
        }
      }
    ]
  }
}
```

### Send to a Thread

```json
{
  "tool": "message",
  "action": "thread-reply",
  "provider": "feishu",
  "to": "chat_id",
  "threadId": "thread_id",
  "text": "Follow-up: patch applied at 14:32 UTC"
}
```

### React to a Message

```json
{
  "tool": "message",
  "action": "react",
  "provider": "feishu",
  "to": "chat_id",
  "messageId": "msg_id",
  "emoji": "✅"
}
```

### Read Messages

```json
{
  "tool": "message",
  "action": "read",
  "provider": "feishu",
  "to": "chat_id",
  "limit": 20
}
```

## Related Skills

- **feishu-doc** — Create and edit Feishu documents
- **feishu-drive** — Manage files in Feishu Drive
- **feishu-wiki** — Read and write Feishu Wiki pages

## Usage from Agent

```
Send a Feishu message to the security team chat: "Engagement report ready"
Post the daily vulnerability digest to the Feishu security group
Reply to the existing thread with the patch confirmation
React with ✅ to the deployment confirmation message in Feishu
```
