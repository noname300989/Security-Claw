---
name: synology-chat
description: "Send messages to Synology Chat via the OpenClaw `message` tool. Use when: (1) sending alerts or reports to a self-hosted Synology Chat server, (2) notifying a Synology NAS-based team channel. Requires Synology Chat webhook URL configured in openclaw.json."
metadata:
  { "openclaw": { "emoji": "🗄️", "requires": { "config": ["channels.synology.webhookUrl"] } } }
---

# Synology Chat Channel

Send messages and alerts to a Synology Chat server (self-hosted on Synology NAS).

## Setup

1. In Synology Chat → Integrations → Incoming Webhooks → Create
2. Copy the webhook URL
3. Configure in `openclaw.json`:

```json5
{
  channels: {
    synology: {
      webhookUrl: "https://your-nas.example.com:5001/webapi/entry.cgi?api=SYNO.Chat.External&method=incoming&version=2&token=...",
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
  "provider": "synology",
  "to": "webhook",
  "text": "🔴 Security Alert: Critical vulnerability detected on prod server"
}
```

### Send with Media

```json
{
  "tool": "message",
  "action": "send",
  "provider": "synology",
  "to": "webhook",
  "text": "Daily security scan complete — report attached",
  "media": ["/reports/daily_scan.pdf"]
}
```

## Notes

> [!NOTE]
> Synology Chat is ideal for teams using Synology NAS for self-hosted infrastructure where keeping communications on-premises is a security or compliance requirement.

## Usage from Agent

```
Send a Synology Chat message: "Daily security scan complete — 3 findings"
Notify the Synology Chat channel about the critical RCE finding
Post the engagement report to the Synology NAS team chat
```
