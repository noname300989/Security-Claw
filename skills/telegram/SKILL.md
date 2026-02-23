---
name: telegram
description: "Send, receive, and manage messages on Telegram via the OpenClaw `message` tool. Use when: (1) sending alerts or reports to a Telegram user or group, (2) handling Telegram bot interactions, (3) creating polls, pinning messages, or managing threads. Requires Telegram bot token configured in openclaw.json."
metadata: { "openclaw": { "emoji": "✈️", "requires": { "config": ["channels.telegram.token"] } } }
---

# Telegram Channel

Send and receive Telegram messages via the OpenClaw bot integration.

## Setup

1. Create a bot via [@BotFather](https://t.me/BotFather) and get the token
2. Configure in `openclaw.json`:

```json5
{
  channels: {
    telegram: {
      token: "YOUR_BOT_TOKEN",
      enabled: true,
    },
  },
}
```

3. Start a chat with your bot and send `/start`

## Common Operations

### Send a Message

```json
{
  "tool": "message",
  "action": "send",
  "provider": "telegram",
  "to": "@username or chat_id",
  "text": "🔴 Alert: Scan complete — 3 critical findings detected"
}
```

### Send with Markdown

```json
{
  "tool": "message",
  "action": "send",
  "provider": "telegram",
  "to": "chat_id",
  "text": "*Critical Finding*\n`CVE-2024-1234` — RCE in login endpoint\nSeverity: CRITICAL"
}
```

### Send Media

```json
{
  "tool": "message",
  "action": "send",
  "provider": "telegram",
  "to": "chat_id",
  "text": "Evidence screenshot",
  "media": ["/evidence/xss_proof.png"]
}
```

### Create a Poll

```json
{
  "tool": "message",
  "action": "poll",
  "provider": "telegram",
  "to": "chat_id",
  "question": "Which vulnerability should we prioritize?",
  "options": ["SQL Injection", "XSS", "SSRF", "IDOR"]
}
```

### Reply to a Message

```json
{
  "tool": "message",
  "action": "send",
  "provider": "telegram",
  "to": "chat_id",
  "text": "Here is your report.",
  "replyTo": "message_id"
}
```

### Pin a Message

```json
{
  "tool": "message",
  "action": "pin",
  "provider": "telegram",
  "to": "chat_id",
  "messageId": "message_id"
}
```

### Search Messages

```json
{
  "tool": "message",
  "action": "search",
  "provider": "telegram",
  "to": "chat_id",
  "query": "CVE-2024"
}
```

## Topic Support

Telegram supports forum topics. Specify a `topic_id` to route messages:

```json
{
  "tool": "message",
  "action": "send",
  "provider": "telegram",
  "to": "group_chat_id",
  "text": "Daily recon complete",
  "topicId": "topic_id"
}
```

## Usage from Agent

```
Send a Telegram alert to @secteam: "Engagement complete — report ready"
Post the daily vulnerability summary to the security Telegram group
Create a Telegram poll asking which target to focus on next
Pin the engagement briefing message in the Telegram channel
```
