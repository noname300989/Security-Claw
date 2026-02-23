---
name: image-analysis
description: "Analyze images and screenshots via the `image` tool using the configured image model. Use when: (1) analyzing browser/node screenshots, (2) examining captured evidence images, (3) describing visual content from files or URLs. NOT for: generating images, reading text files, or browser DOM inspection (use browser snapshot for that)."
metadata: { "openclaw": { "emoji": "🔬" } }
---

# Image Analysis — Visual Content Understanding

Analyze images using the configured image model — screenshots, evidence photos, diagrams, and more.

## When to Use

✅ **USE this skill when:**

- Analyzing a browser or canvas screenshot for visual content
- Examining evidence images captured by the `nodes` camera tool
- Describing what's visible in a chart, diagram, or UI screenshot
- Verifying visual output of a web page or tool

## When NOT to Use

❌ **DON'T use this skill when:**

- You need DOM or accessibility tree inspection → use `browser` → `snapshot`
- You want to check text in a file → use `read` tool
- You need to generate an image → this tool is for analysis only
- No image model is configured (tool won't be available)

## Parameters

| Parameter    | Description                                                     |
| ------------ | --------------------------------------------------------------- |
| `image`      | Required. Absolute file path or `http/https` URL                |
| `prompt`     | Optional. Analysis instruction (default: "Describe the image.") |
| `model`      | Optional. Override the image model for this call                |
| `maxBytesMb` | Optional. Size cap before sending to model                      |

> [!NOTE]
> The `image` tool is only available when `agents.defaults.imageModel` is configured, or when an image model can be inferred from your default model + configured auth.

## Common Patterns

### Describe a Screenshot

```json
{
  "tool": "image",
  "image": "/tmp/browser-screenshot.png",
  "prompt": "What vulnerabilities or sensitive information is visible on this page?"
}
```

### Analyze a Camera Capture

After using `nodes → camera_snap` which returns `MEDIA:<path>`:

```json
{
  "tool": "image",
  "image": "/path/to/camera_snap.jpg",
  "prompt": "Describe what is visible in this room/environment"
}
```

### Analyze a URL Image

```json
{
  "tool": "image",
  "image": "https://example.com/screenshot.png",
  "prompt": "Identify any error messages, API keys, or sensitive data visible"
}
```

### Analyze Evidence Screenshot

For pentest evidence captured during a scan:

```json
{
  "tool": "image",
  "image": "/evidence/xss_confirmation.png",
  "prompt": "Confirm the XSS alert dialog is visible and describe what it shows"
}
```

### With Model Override

```json
{
  "tool": "image",
  "image": "/tmp/network-diagram.png",
  "prompt": "Map out all hosts, subnets, and connections visible in this diagram",
  "model": "gemini-2.0-flash"
}
```

## Integration Workflow

Typical flow combining browser/nodes + image analysis:

```
1. browser → screenshot          ← capture the page
2. image → analyze screenshot    ← understand what's on it
3. browser → act                 ← take action based on analysis
```

Or for node camera:

```
1. nodes → camera_snap           ← capture image (returns MEDIA:<path>)
2. image → analyze capture       ← describe / analyze what's visible
```

## Config

Set the image model in `openclaw.json`:

```json5
{
  agents: {
    defaults: {
      imageModel: "gemini-flash-2.0",
    },
  },
}
```

## Usage from Agent

```
Analyze the browser screenshot at /tmp/screenshot.png for visible credentials or sensitive data
Describe the camera capture from the office node
Examine the evidence image evidence/xss_001.png and confirm the XSS alert is shown
Analyze the network diagram in /docs/topology.png and list all IP ranges visible
```
