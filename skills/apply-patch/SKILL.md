---
name: apply-patch
description: "Apply structured multi-file patches via the `apply_patch` tool. Use when: (1) making multi-file code edits in a single structured patch, (2) applying automated code fixes across multiple files atomically. Experimental — requires explicit enablement and OpenAI models only."
metadata: { "openclaw": { "emoji": "🩹" } }
---

# Apply Patch — Structured Multi-File Edits

Apply structured patches across multiple files in one atomic operation.

## When to Use

✅ **USE this skill when:**

- Making multi-hunk edits across several files simultaneously
- You have a structured patch diff ready to apply
- You want atomic multi-file edits without multiple separate `write` calls

## When NOT to Use

❌ **DON'T use this skill when:**

- Editing a single file → use `write` or `edit` tool
- Non-OpenAI models are in use (apply_patch is OpenAI-only currently)
- Plugin is not enabled in config

## Enable

```json5
{
  tools: {
    exec: {
      applyPatch: {
        enabled: true,
        workspaceOnly: true,
        allowModels: ["gpt-5.2"],
      },
    },
  },
}
```

> [!NOTE]
> `workspaceOnly: true` (default) confines patches to the workspace directory. Set `false` only if you intentionally need to write outside the workspace.

## Patch Format

Apply patches using the standard unified diff format:

```
*** Begin Patch
*** Update File: src/agents/config.ts
@@
-  const timeout = 5000;
+  const timeout = 10000;
*** Update File: src/gateway/handler.ts
@@
-  if (request.method === 'GET') {
+  if (request.method === 'GET' || request.method === 'HEAD') {
*** End Patch
```

Supported operations:

- `*** Update File:` — modify existing file
- `*** Add File:` — create a new file
- `*** Delete File:` — delete a file

## Notes

> [!IMPORTANT]
> `apply_patch` is experimental and only available for OpenAI/OpenAI Codex models.
> Tool policy still applies — `allow: ["exec"]` implicitly allows `apply_patch`.

## Usage from Agent

```
Apply the patch to update the timeout in config.ts and add error handling in handler.ts
Use apply_patch to create the new SKILL.md files across multiple directories
Apply the unified diff to fix the security headers in all three response files
```
