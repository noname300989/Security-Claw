---
name: llm-task
description: "Run JSON-only structured LLM tasks via the `llm-task` plugin tool. Use when: (1) a workflow step needs structured JSON output from an LLM, (2) you need schema-validated LLM output for automation, (3) building Lobster workflow steps that invoke an LLM. NOT for: general agent conversation, tool-using agent runs (use sessions_spawn), or image analysis (use image tool). Requires plugin enablement."
metadata: { "openclaw": { "emoji": "🧠" } }
---

# LLM Task — Structured JSON Output from LLM

Run a JSON-only LLM step and get validated structured output. Ideal for Lobster workflows.

## When to Use

✅ **USE this skill when:**

- A workflow step needs structured JSON from an LLM (no tools, no conversation)
- You need schema-validated output for downstream automation
- Building Lobster workflow nodes that require an LLM decision
- Extracting structured data from unstructured text in a pipeline

## When NOT to Use

❌ **DON'T use this skill when:**

- You need a full tool-using agent run → use `sessions_spawn`
- You want free-form conversation → use normal agent turns
- You need image analysis → use `image` tool
- The plugin is not enabled in config (tool won't be available)

## Enable the Plugin

First, enable the `llm-task` plugin in `openclaw.json`:

```json
{
  "plugins": {
    "entries": {
      "llm-task": { "enabled": true }
    }
  }
}
```

Then allowlist the tool for the relevant agent:

```json
{
  "agents": {
    "list": [
      {
        "id": "main",
        "tools": { "allow": ["llm-task"] }
      }
    ]
  }
}
```

## Tool Parameters

| Parameter       | Type   | Required | Description                        |
| --------------- | ------ | -------- | ---------------------------------- |
| `prompt`        | string | ✅       | The LLM instruction                |
| `input`         | any    | —        | Input data to pass to the model    |
| `schema`        | object | —        | JSON Schema to validate the output |
| `provider`      | string | —        | Override the LLM provider          |
| `model`         | string | —        | Override the model                 |
| `authProfileId` | string | —        | Auth profile to use                |
| `temperature`   | number | —        | Model temperature                  |
| `maxTokens`     | number | —        | Max output tokens                  |
| `timeoutMs`     | number | —        | Timeout in milliseconds            |

## Common Patterns

### Simple Classification

```json
{
  "tool": "llm-task",
  "prompt": "Classify the severity of this finding as: critical, high, medium, low, or info. Return JSON only.",
  "input": {
    "finding": "SQL injection in login endpoint allows full database access"
  },
  "schema": {
    "type": "object",
    "properties": {
      "severity": { "type": "string", "enum": ["critical", "high", "medium", "low", "info"] },
      "rationale": { "type": "string" }
    },
    "required": ["severity", "rationale"],
    "additionalProperties": false
  }
}
```

### Extract Structured Fields

```json
{
  "tool": "llm-task",
  "prompt": "Extract CVE details from the provided text. Return as JSON.",
  "input": {
    "text": "CVE-2024-1234 is a critical buffer overflow in OpenSSL 3.x affecting all platforms..."
  },
  "schema": {
    "type": "object",
    "properties": {
      "cve_id": { "type": "string" },
      "severity": { "type": "string" },
      "affected_product": { "type": "string" },
      "summary": { "type": "string" }
    },
    "required": ["cve_id", "severity", "affected_product", "summary"]
  }
}
```

### Generate a Draft (no schema)

```json
{
  "tool": "llm-task",
  "prompt": "Given the input email, return a JSON object with 'intent' and 'draft_reply' fields.",
  "input": {
    "subject": "Penetration Test Request",
    "body": "We need a pentest of our API by end of month."
  }
}
```

## Lobster Workflow Integration

```lobster
openclaw.invoke --tool llm-task --action json --args-json '{
  "prompt": "Analyze the scan results and return a prioritized list of findings.",
  "input": {
    "findings": ["SQL injection", "XSS", "Open redirect"]
  },
  "schema": {
    "type": "object",
    "properties": {
      "prioritized": {
        "type": "array",
        "items": { "type": "string" }
      }
    },
    "required": ["prioritized"]
  }
}'
```

## Optional Config

```json
{
  "plugins": {
    "entries": {
      "llm-task": {
        "enabled": true,
        "config": {
          "defaultProvider": "openai-codex",
          "defaultModel": "gpt-5.2",
          "maxTokens": 800,
          "timeoutMs": 30000,
          "allowedModels": ["openai-codex/gpt-5.3-codex"]
        }
      }
    }
  }
}
```

## Safety Notes

> [!CAUTION]
> Always validate output with `schema` before using it in side-effecting steps (exec, send, post). Treat LLM output as untrusted.

> [!NOTE]
> The tool runs JSON-only mode — no code fences, no commentary. No tools are given to the model for this run.

## Usage from Agent

```
Use llm-task to classify the severity of these 5 findings as JSON
Extract CVE IDs and affected products from this advisory text using llm-task
Generate a structured pentest report outline with llm-task using the schema provided
Run an llm-task Lobster step to decide the next attack phase based on recon results
```
