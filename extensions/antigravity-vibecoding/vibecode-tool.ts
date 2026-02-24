import { spawn } from "node:child_process";
import type { AnyAgentTool } from "@openclaw/plugin-sdk";

export const vibecodeTool: AnyAgentTool = {
  name: "vibecode",
  label: "Vibecode",
  description:
    "Delegate a complex coding or analytical task to the Antigravity autonomous sub-agent. " +
    "The sub-agent will run in the background, navigate the filesystem, and write code automatically.",
  parameters: {
    type: "object",
    properties: {
      prompt: {
        type: "string",
        description:
          "A detailed prompt describing what the sub-agent should build, modify, or analyze.",
      },
      cwd: {
        type: "string",
        description:
          "The absolute path to the directory where the sub-agent should execute. Defaults to current workspace.",
      },
    },
    required: ["prompt"],
  },
  execute: async (toolCallId: string, args: Record<string, any>, context: any) => {
    const prompt = args.prompt;
    const cwd = args.cwd || process.cwd();

    return new Promise((resolve) => {
      let outputBody = "";

      // Spawn the antigravity CLI directly
      const child = spawn("antigravity", ["chat", prompt], {
        cwd,
        env: process.env,
        shell: true,
      });

      child.stdout.on("data", (data) => {
        outputBody += data.toString();
      });

      child.stderr.on("data", (data) => {
        outputBody += data.toString();
      });

      child.on("close", (code) => {
        if (code === 0) {
          resolve({
            content: [
              {
                type: "text",
                text: `Vibecoding sub-agent finished successfully.\n\n${outputBody}`,
              },
            ],
            details: {},
          });
        } else {
          resolve({
            content: [
              {
                type: "text",
                text: `Vibecoding sub-agent exited with error code ${code}.\n\n${outputBody}`,
              },
            ],
            details: {},
          });
        }
      });

      child.on("error", (err) => {
        resolve({
          content: [{ type: "text", text: `Failed to spawn: ${err.message}` }],
          details: {},
        });
      });
    });
  },
};
