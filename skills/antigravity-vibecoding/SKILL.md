---
name: antigravity-vibecoding
description: "Delegate complex coding tasks to the Antigravity autonomous sub-agent."
---

# Antigravity Vibecoding

This skill provides the Red Team agent with the ability to delegate code generation, refactoring, and complex analytical tasks to an autonomous sub-agent powered by the **Antigravity CLI**.

Using the `vibecode()` OpenClaw tool, the agent can spawn a background terminal session that interacts with the target codebase natively.

## Capabilities

1. **Autonomous Code Generation:** Write new scripts, tools, or entire applications from scratch based on a natural language prompt.
2. **Refactoring & Patching:** Modify existing files or fix complex bugs without the Red Team agent needing to manually read, edit, and lint the files.
3. **Exploit Development:** Generate custom Proof-of-Concept (PoC) scripts for vulnerabilities identified during an engagement.
4. **Environment Context:** Runs with full knowledge of the current workspace directory, allowing it to navigate the filesystem as needed.

## OpenClaw Native Integration

This skill is backed by the `vibecode` TypeScript plugin, which wraps the underlying `antigravity chat "prompt"` CLI command natively. Output from the Vibecoding session is captured and parsed efficiently to inform the Red Team agent of the result.

## Example Use Cases

- _"I found a blind SQLi on the target. @vibecode generate a multithreaded Python time-based extraction script to dump the admin table."_
- _"This web app uses a custom JWT signing structure. @vibecode write a Node.js utility to forge these tokens."_
