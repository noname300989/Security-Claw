---
name: signal
description: "Send and receive Signal messages via the OpenClaw `message` tool using signal-cli. Use when: (1) sending end-to-end encrypted alerts or reports, (2) notifying a Signal contact or group, (3) sending media securely via Signal. Requires signal-cli configured with a registered phone number."
metadata:
  {
    "openclaw":
      {
        "emoji": "🔒",
        "requires": { "bins": ["signal-cli"], "config": ["channels.signal.phoneNumber"] },
        "install":
          [
            {
              "id": "brew-signal-cli",
              "kind": "brew",
              "formula": "signal-cli",
              "bins": ["signal-cli"],
              "label": "Install signal-cli (brew)",
            },
          ],
      },
  }
---

# Signal Channel

Send end-to-end encrypted messages and media via Signal.

## Setup

1. Install signal-cli: `brew install signal-cli`
2. Register or link your number:

```bash
# Register new number
signal-cli -u +1234567890 register

# Or link an existing device
signal-cli link -n "OpenClaw Gateway"
```

3. Configure in `openclaw.json`:

```json5
{
  channels: {
    signal: {
      phoneNumber: "+1234567890",
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
  "provider": "signal",
  "to": "+1234567890",
  "text": "🔴 CRITICAL: Active exploitation detected on prod-web-01"
}
```

### Send to a Group

```json
{
  "tool": "message",
  "action": "send",
  "provider": "signal",
  "to": "group_id",
  "text": "Engagement complete — full report attached"
}
```

### Send Media

```json
{
  "tool": "message",
  "action": "send",
  "provider": "signal",
  "to": "+1234567890",
  "text": "Evidence screenshot",
  "media": ["/evidence/rce_proof.png"]
}
```

### Read Messages

```json
{
  "tool": "message",
  "action": "read",
  "provider": "signal",
  "to": "+1234567890"
}
```

## Notes

> [!NOTE]
> Signal provides end-to-end encryption. Use for sensitive security notifications where confidentiality is required.

> [!CAUTION]
> The phone number must be registered with Signal. Registration requires SMS or voice verification.

## Usage from Agent

```
Send a Signal message to +1234567890: "Critical RCE confirmed — call me"
Notify the security team Signal group that the engagement report is ready
Send the evidence screenshot via Signal to the CISO
```
