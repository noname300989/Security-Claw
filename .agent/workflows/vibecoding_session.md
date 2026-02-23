---
description: "How to use the Antigravity Vibecoding skill to delegate complex coding tasks"
---

# Antigravity Vibecoding Session

This workflow guides the Red Team agent in delegating code generation, scripting, or refactoring tasks to an autonomous Antigravity sub-agent using the `vibecode` tool.

1. **Understand the Objective:** When the user asks to build a script, exploit PoC, or complex utility, identify if it requires writing significant code that would be better handled autonomously in the background.
2. **Determine the Context:** Identify the desired working directory (`cwd`) where the code should be generated (e.g., `./skills/custom-exploit/`).
3. **Formulate the Prompt:** Write a clear, comprehensive prompt for the sub-agent. Include:
   - The exact goal (e.g., "Write a Python script to perform time-based SQLi against target.com/login").
   - Any constraints (e.g., "Use only standard library modules", "Include verbose logging").
4. **Execute Delegation:** Call the `vibecode(prompt: string, cwd: string)` tool.
   - _Note: The tool will block and wait for the Antigravity process to finish successfully or fail._
5. **Review and Report:** Upon completion, carefully read the `terminalOutput` returned by the tool. Summarize the actions taken by the sub-agent and report back to the user via Discord, Telegram, or directly in chat, outlining the files created and their purpose.

**Example Tool Invocation:**

```javascript
{
  "name": "vibecode",
  "arguments": {
    "prompt": "Create a new Node.js script called jwt-forger.js that takes a base64 encoded payload and signs it using the 'none' algorithm flaw for testing.",
    "cwd": "/Users/gayatrirachakonda/Security Claw/payloads"
  }
}
```
