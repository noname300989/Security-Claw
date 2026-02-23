---
name: twitch
description: "Send messages and manage interactions on Twitch chat via the OpenClaw `message` tool. Use when: (1) sending alerts or bot messages to a Twitch channel chat, (2) monitoring Twitch chat for commands or keywords, (3) running a live security demo or stream bot. Requires Twitch OAuth token configured in openclaw.json."
metadata:
  {
    "openclaw":
      {
        "emoji": "🟣",
        "requires": { "config": ["channels.twitch.username", "channels.twitch.oauth"] },
      },
  }
---

# Twitch Channel

Connect to Twitch IRC and send/receive chat messages.

## Setup

1. Get an OAuth token at [twitchapps.com/tmi](https://twitchapps.com/tmi/)
2. Configure in `openclaw.json`:

```json5
{
  channels: {
    twitch: {
      username: "your_bot_name",
      oauth: "oauth:YOUR_TOKEN_HERE",
      channels: ["your_channel"],
      enabled: true,
    },
  },
}
```

## Common Operations

### Send a Chat Message

```json
{
  "tool": "message",
  "action": "send",
  "provider": "twitch",
  "to": "#your_channel",
  "text": "!alert Scan complete — follow along with the security demo!"
}
```

### Read Recent Chat

```json
{
  "tool": "message",
  "action": "read",
  "provider": "twitch",
  "to": "#your_channel",
  "limit": 50
}
```

### Send a Reply

```json
{
  "tool": "message",
  "action": "send",
  "provider": "twitch",
  "to": "#your_channel",
  "text": "@username Great question! The answer is CVE-2024-1234.",
  "replyTo": "message_id"
}
```

## Use Cases for Security Streams

- **Live pentest demos** — announce tool output in real time to chat
- **CTF live streams** — post hints or progress updates
- **Security education** — automate Q&A responses to common questions

## Notes

> [!NOTE]
> Twitch chat is public. Never post credentials, tokens, or sensitive target data in Twitch chat.
> Use stage/lab environments for live security demonstrations.

## Usage from Agent

```
Send a Twitch chat message to #mychannel: "Starting the SQL injection demo now!"
Read the last 50 messages from the Twitch channel chat
Reply to the viewer question about buffer overflows in Twitch chat
```
