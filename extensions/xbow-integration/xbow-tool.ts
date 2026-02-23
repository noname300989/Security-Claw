import { spawn } from "node:child_process";
import * as path from "node:path";
import type { OpenClawPluginAPI } from "@openclaw/plugin-sdk";
import { Type as t } from "@sinclair/typebox";

export function createXbowTool(api: OpenClawPluginAPI) {
  return api.createTool({
    name: "xbow_scan",
    description:
      "Launch and monitor autonomous XBOW security assessments using AI agents. " +
      "Provide a target URL and optional authentication headers. Actions include " +
      "launching a new scan, checking status, fetching findings, and generating a report.",
    parameters: t.Object({
      action: t.Union(
        [t.Literal("launch"), t.Literal("status"), t.Literal("findings"), t.Literal("report")],
        { description: "The action to perform with the XBOW platform" },
      ),
      targetUrl: t.Optional(t.String({ description: "Target URL (required for launch action)" })),
      authHeaders: t.Optional(
        t.Record(t.String(), t.String(), {
          description: "Optional HTTP headers for authentication",
        }),
      ),
      scanId: t.Optional(t.String({ description: "XBOW Scan ID" })),
      reportOutput: t.Optional(t.String({ description: "Optional custom path for output report" })),
    }),
    execute: async (params, ctx) => {
      return new Promise((resolve, reject) => {
        // Resolve script path relative to the active workspace
        const workspacePath = ctx.getWorkspaceRoot();
        const scriptPath = path.join(
          workspacePath,
          "skills",
          "xbow-integration",
          "scripts",
          "xbow_client.py",
        );

        const args: string[] = [scriptPath, params.action];

        if (params.action === "launch") {
          if (!params.targetUrl) {
            reject(new Error("targetUrl is required for launch action"));
            return;
          }
          args.push(params.targetUrl);
          if (params.authHeaders && Object.keys(params.authHeaders).length > 0) {
            args.push("--headers", JSON.stringify(params.authHeaders));
          }
        } else {
          // status, findings, report require scanId
          if (!params.scanId) {
            reject(new Error(`scanId is required for action: ${params.action}`));
            return;
          }
          args.push(params.scanId);
          if (params.action === "report" && params.reportOutput) {
            args.push("--output", params.reportOutput);
          }
        }

        ctx.logger.info(`Running XBOW client: python3 ${args.join(" ")}`);

        const proc = spawn("python3", args, {
          cwd: workspacePath,
          env: { ...process.env, PYTHONUNBUFFERED: "1" },
        });

        let stdoutData = "";
        let stderrData = "";

        proc.stdout.on("data", (data) => {
          stdoutData += data.toString();
        });

        proc.stderr.on("data", (data) => {
          stderrData += data.toString();
          ctx.logger.error(`XBOW client error: ${data.toString()}`);
        });

        proc.on("close", (code) => {
          if (code !== 0) {
            reject(new Error(`XBOW client failed with exit code ${code}\nStderr: ${stderrData}`));
            return;
          }

          try {
            // Try to parse JSON output from the script
            let resultData: any;
            try {
              resultData = JSON.parse(stdoutData.trim());
            } catch {
              resultData = { raw_output: stdoutData.trim() };
            }

            let markdownSummary = "";

            if (params.action === "launch") {
              const scanId = resultData.id || "N/A";
              markdownSummary = `### 🏹 XBOW Scan Launched\n**Target:** ${params.targetUrl}\n**Scan ID:** \`${scanId}\`\n\n*Use the status action with this ID to monitor progress.*`;
            } else if (params.action === "status") {
              const status = resultData.status || "Unknown";
              const progress = resultData.progress || "0%";
              markdownSummary = `### 🏹 XBOW Scan Status: ${status}\n**Scan ID:** \`${params.scanId}\`\n**Progress:** ${progress}\n\n`;
            } else if (params.action === "findings") {
              const findingsCount = resultData.findings?.length || 0;
              markdownSummary = `### 🏹 XBOW Findings: ${findingsCount} Verified\n**Scan ID:** \`${params.scanId}\`\n\n`;
              if (findingsCount > 0) {
                resultData.findings.forEach((f: any) => {
                  markdownSummary += `- **${f.severity || "N/A"}**: ${f.title}\n`;
                });
              }
            } else if (params.action === "report") {
              markdownSummary = `### 🏹 XBOW Report Generated\nReport saved to: \`${resultData.report_saved || params.reportOutput}\``;
            }

            resolve({
              content: [
                {
                  type: "text",
                  text: markdownSummary,
                },
                {
                  type: "text",
                  text: JSON.stringify(resultData, null, 2),
                },
              ],
            });
          } catch (e: any) {
            reject(
              new Error(`Failed to parse XBOW output: ${e.message}\nRaw Output: ${stdoutData}`),
            );
          }
        });
      });
    },
  });
}
