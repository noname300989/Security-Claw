---
name: nostr
description: "Publish and read notes on the Nostr decentralized protocol via the OpenClaw `message` tool. Use when: (1) publishing security findings or alerts as Nostr notes, (2) monitoring Nostr feeds for threat intelligence, (3) interacting with Nostr-based communities. Requires a Nostr private key configured in openclaw.json."
metadata: { "openclaw": { "emoji": "⚡", "requires": { "config": ["channels.nostr.privateKey"] } } }
---

# Nostr Channel

Publish and read messages on the Nostr decentralized protocol.

## Setup

```json5
{
  channels: {
    nostr: {
      privateKey: "YOUR_NSEC_OR_HEX_PRIVATE_KEY",
      relays: ["wss://relay.damus.io", "wss://relay.nostr.band", "wss://nos.lol"],
      enabled: true,
    },
  },
}
```

Generate a new keypair: `openssl rand -hex 32`

## Common Operations

### Publish a Note

```json
{
  "tool": "message",
  "action": "send",
  "provider": "nostr",
  "text": "Security alert: CVE-2024-1234 actively exploited in the wild. Patch immediately."
}
```

### Send a DM (NIP-04)

```json
{
  "tool": "message",
  "action": "send",
  "provider": "nostr",
  "to": "npub...",
  "text": "Encrypted message via Nostr DM"
}
```

### Read Feed

```json
{
  "tool": "message",
  "action": "read",
  "provider": "nostr",
  "limit": 20
}
```

### Read from a Specific User

```json
{
  "tool": "message",
  "action": "read",
  "provider": "nostr",
  "to": "npub...",
  "limit": 10
}
```

## Notes

> [!NOTE]
> Nostr is decentralized and censorship-resistant — ideal for publishing threat intel that must stay available.
> Public notes are visible to anyone on the relays.

## Usage from Agent

```
Publish a Nostr note about the CVE-2024-1234 exploit being actively exploited
Send a Nostr DM to npub1abc... with the engagement results
Read the latest 20 notes from the security community on Nostr
```
