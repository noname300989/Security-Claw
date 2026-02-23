---
name: nodes
description: "Paired node management via the `nodes` tool. Use when: (1) discovering or describing connected nodes, (2) sending macOS notifications to a device, (3) running commands on a paired macOS companion app or headless node host, (4) capturing camera snapshots, screen recordings, or location. NOT for: gateway shell commands (use exec with host=gateway), browser automation (use browser), or scheduling (use cron)."
metadata: { "openclaw": { "emoji": "📱" } }
---

# Nodes — Paired Device Management

Control paired macOS companions and headless node hosts: notifications, commands, camera, screen, and location.

## When to Use

✅ **USE this skill when:**

- Discovering what nodes are paired and available
- Sending push notifications to a macOS device
- Running shell commands on a paired macOS companion
- Capturing camera snapshots or screen recordings for evidence
- Getting device GPS/location data

## When NOT to Use

❌ **DON'T use this skill when:**

- Running commands on the gateway host → use `exec` with `host=gateway`
- Browser automation → use `browser` tool
- Scheduling recurring tasks → use `cron` tool
- Sending chat messages → use `message` tool

## Actions

| Action               | Description                                       |
| -------------------- | ------------------------------------------------- |
| `status`             | All paired nodes + connection state               |
| `describe`           | Details, capabilities, and permissions for a node |
| `pending`            | Pending pairing requests                          |
| `approve` / `reject` | Accept or reject a pairing request                |
| `notify`             | Send macOS system notification                    |
| `run`                | Run a shell command on the node                   |
| `camera_snap`        | Capture a camera photo                            |
| `camera_clip`        | Capture a short camera video                      |
| `screen_record`      | Capture a screen recording                        |
| `location_get`       | Get current GPS location                          |

## Common Patterns

### Discover Nodes

```json
{ "tool": "nodes", "action": "status" }
```

Describe a specific node to see its capabilities:

```json
{ "tool": "nodes", "action": "describe", "node": "office-mac" }
```

### Send a Notification

```json
{
  "tool": "nodes",
  "action": "notify",
  "node": "office-mac",
  "title": "Scan Complete",
  "body": "Nuclei found 3 critical issues — check the report"
}
```

### Run a Command on a Node

```json
{
  "tool": "nodes",
  "action": "run",
  "node": "office-mac",
  "command": ["open", "-a", "Terminal"],
  "commandTimeoutMs": 10000,
  "invokeTimeoutMs": 30000
}
```

With env variables and screen recording:

```json
{
  "tool": "nodes",
  "action": "run",
  "node": "lab-mac",
  "command": ["python3", "/Users/admin/scan.py"],
  "env": ["TARGET=192.168.1.10", "OUTPUT=/tmp/results.json"],
  "needsScreenRecording": true
}
```

### Camera Snapshot

```json
{
  "tool": "nodes",
  "action": "camera_snap",
  "node": "office-mac"
}
```

Returns an image block + `MEDIA:<path>`.

### Screen Recording

```json
{
  "tool": "nodes",
  "action": "screen_record",
  "node": "office-mac",
  "durationSeconds": 10
}
```

Returns `FILE:<path>` (mp4).

### Get Location

```json
{
  "tool": "nodes",
  "action": "location_get",
  "node": "mobile-device"
}
```

Returns JSON: `{ lat, lon, accuracy, timestamp }`.

## Safety Notes

> [!CAUTION]
> Always use `status` / `describe` first to confirm node availability and permissions before invoking camera or screen commands. Camera and screen capture require the node app to be **foregrounded**.

> [!NOTE]
> Images return image blocks + `MEDIA:<path>`. Videos return `FILE:<path>` (mp4). Always obtain explicit user consent for camera/screen capture.

## Workflow

```
1. nodes → status          ← discover connected nodes
2. nodes → describe        ← confirm capabilities + permissions
3. nodes → notify / run / camera_snap / screen_record
```

## Usage from Agent

```
List all connected nodes and their status
Send a macOS notification to office-mac: "Engagement complete — check Slack"
Run the evidence collection script on lab-mac
Take a camera snapshot on the office-mac for visual confirmation
Get the current GPS location of the mobile device
```
