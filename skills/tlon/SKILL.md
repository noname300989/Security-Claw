---
name: tlon
description: "Send messages on Urbit/Tlon via the OpenClaw `message` tool. Use when: (1) sending alerts or notes to Urbit groups or DMs, (2) working with Tlon-based decentralized communities. Requires an Urbit ship and code configured in openclaw.json."
metadata:
  {
    "openclaw":
      { "emoji": "🌐", "requires": { "config": ["channels.tlon.shipUrl", "channels.tlon.code"] } },
  }
---

# Tlon / Urbit Channel

Send and receive messages on the Urbit decentralized network via Tlon.

## Setup

```json5
{
  channels: {
    tlon: {
      shipUrl: "http://localhost:8080",
      code: "YOUR_SHIP_CODE",
      enabled: true,
    },
  },
}
```

Get your ship code: run `+code` in your Urbit dojo.

## Common Operations

### Send a DM

```json
{
  "tool": "message",
  "action": "send",
  "provider": "tlon",
  "to": "~sampel-palnet",
  "text": "Security alert: new exploit chain identified"
}
```

### Send to a Group

```json
{
  "tool": "message",
  "action": "send",
  "provider": "tlon",
  "to": "~sampel/group-name",
  "text": "Daily threat intel report published"
}
```

### Read Messages

```json
{
  "tool": "message",
  "action": "read",
  "provider": "tlon",
  "to": "~sampel-palnet",
  "limit": 20
}
```

## Notes

> [!NOTE]
> Urbit uses galaxy/star/planet identifiers like `~sampel-palnet`.
> Tlon is currently the primary Urbit client. Your ship must be running to send/receive.

## Usage from Agent

```
Send a Tlon/Urbit DM to ~sampel-palnet: "Report is ready"
Post a security update to the Urbit group channel
Read the latest messages from my Urbit ship
```
