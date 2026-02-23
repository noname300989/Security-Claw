---
name: irc
description: "Send and receive messages on IRC (Internet Relay Chat) via the OpenClaw `message` tool. Use when: (1) sending alerts to an IRC channel, (2) interacting with IRC-based communities or CTF channels, (3) monitoring IRC channels for security research. Requires IRC server and nick configuration in openclaw.json."
metadata: { "openclaw": { "emoji": "📡", "requires": { "config": ["channels.irc.server"] } } }
---

# IRC Channel

Connect and send messages to IRC servers and channels.

## Setup

```json5
{
  channels: {
    irc: {
      server: "irc.libera.chat",
      port: 6697,
      nick: "openclaw-bot",
      username: "openclaw",
      realname: "OpenClaw Bot",
      tls: true,
      enabled: true,
    },
  },
}
```

## Common Operations

### Send to a Channel

```json
{
  "tool": "message",
  "action": "send",
  "provider": "irc",
  "to": "#security",
  "text": "[Alert] Scan complete — 3 critical findings detected"
}
```

### Send a DM (PRIVMSG)

```json
{
  "tool": "message",
  "action": "send",
  "provider": "irc",
  "to": "nickname",
  "text": "Check the report at /tmp/report.txt"
}
```

### Read Messages

```json
{
  "tool": "message",
  "action": "read",
  "provider": "irc",
  "to": "#security",
  "limit": 50
}
```

### Channel Info

```json
{
  "tool": "message",
  "action": "channel-info",
  "provider": "irc",
  "to": "#security"
}
```

## Notes

> [!NOTE]
> IRC messages are plaintext — avoid sending credentials or sensitive data.
> For CTF and security research, use channels like `irc.libera.chat` (`#security`, `#netsec`).

## Usage from Agent

```
Send an IRC message to #security: "Today's scan complete — 3 crits found"
Monitor the #ctf-help IRC channel for new messages
Send a DM to user "alice" on IRC with the lab access details
```
