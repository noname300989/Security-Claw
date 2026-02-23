---
name: phone-control
description: "Control a paired Android phone via the OpenClaw phone-control extension. Use when: (1) sending SMS or initiating calls from a paired phone, (2) automating phone-based 2FA or OTP capture, (3) managing phone actions for security testing scenarios. Requires the phone-control extension installed and a paired Android device."
metadata: { "openclaw": { "emoji": "📞" } }
---

# Phone Control — Paired Android Device Actions

Automate phone actions on a paired Android device: SMS, calls, and app interactions.

## When to Use

✅ **USE this skill when:**

- Capturing OTP/2FA codes sent via SMS for authentication testing
- Initiating or monitoring calls from a paired phone
- Automating phone-based actions in an authorized security test
- Forwarding SMS alerts to the agent for processing

## When NOT to Use

❌ **DON'T use this skill when:**

- Sending team notifications → use `message` tool (Telegram/WhatsApp/Signal)
- Device screenshots → use `nodes` + `camera_snap`
- Unauthorized interception of messages (this is for your own authorized devices only)

## Setup

1. Install the phone-control extension on the gateway
2. Install the OpenClaw companion app on the Android device
3. Pair via the Nodes pairing flow

```json5
{
  plugins: {
    entries: {
      "phone-control": { enabled: true },
    },
  },
}
```

## Common Operations

### Read Incoming SMS

```json
{
  "tool": "exec",
  "command": "openclaw phone sms list --limit 10 --node android-phone",
  "host": "gateway"
}
```

### Forward SMS OTPs to Agent

The agent can monitor for OTP SMS and automatically extract codes:

```
Watch the paired Android phone for incoming SMS containing a 6-digit OTP and return the code
```

### Initiate a Call

```json
{
  "tool": "exec",
  "command": "openclaw phone call +1234567890 --node android-phone",
  "host": "gateway"
}
```

### Get Device Status

```json
{
  "tool": "nodes",
  "action": "status"
}
```

Look for a node with `type: android` or `type: phone`.

## Security Notes

> [!CAUTION]
> Phone control provides access to SMS and calls. Only use on devices you own and have explicit authorization to control. Never use for unauthorized interception.

## Usage from Agent

```
Read the last 5 SMS messages from the paired Android phone
Watch for an incoming OTP SMS and return the code
Check the status of the paired phone node
Get the current phone's carrier and signal strength
```
