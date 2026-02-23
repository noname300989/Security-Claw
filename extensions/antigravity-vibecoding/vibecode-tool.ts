import { spawn } from "node:child_process";
import { ToolPlugin, ToolHandler } from "@openclaw/plugin-sdk";

const vibecodeTool: ToolHandler = {
  name: "vibecode",
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
  execute: async (args, context) => {
    const prompt = args.prompt;
    const cwd = args.cwd || context.workspacePath || process.cwd();

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
            success: true,
            terminalOutput: outputBody,
            summary: `Vibecoding sub-agent finished successfully. Review the terminal output for details.`,
          });
        } else {
          resolve({
            success: false,
            terminalOutput: outputBody,
            summary: `Vibecoding sub-agent exited with error code ${code}.`,
          });
        }
      });

      child.on("error", (err) => {
        resolve({
          success: false,
          error: err.message,
          summary: `Failed to spawn the antigravity CLI process. Is it installed in the PATH?`,
        });
      });
    });
  },
};

export default class AntigravityPlugin extends ToolPlugin {
  getTools() {
    return [vibecodeTool];
  }
}
