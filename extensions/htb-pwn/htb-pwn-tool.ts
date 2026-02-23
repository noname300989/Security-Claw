import { spawn } from "node:child_process";
import path from "node:path";
import { Type } from "@sinclair/typebox";
import type { OpenClawPluginApi } from "../../src/plugins/types.js";

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Resolve the absolute path to htb_auto.py, relative to the repo root.
 * Works regardless of where openclaw is invoked from.
 */
function resolveHtbScriptPath(): string {
  const here = new URL(import.meta.url).pathname;
  const repoRoot = path.resolve(path.dirname(here), "../../");
  return path.join(repoRoot, "skills", "htb-pwn", "scripts", "htb_auto.py");
}

/**
 * Run python3 htb_auto.py with the given args and return stdout.
 */
async function runHtbAuto(args: string[], timeoutMs: number): Promise<string> {
  const scriptPath = resolveHtbScriptPath();
  const env = { ...process.env };

  return new Promise((resolve, reject) => {
    const child = spawn("python3", [scriptPath, ...args], {
      stdio: ["ignore", "pipe", "pipe"],
      env,
    });

    let stdout = "";
    let stderr = "";
    let settled = false;

    const settle = (ok: boolean, value: string) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (ok) resolve(value);
      else reject(new Error(value));
    };

    child.stdout?.setEncoding("utf8");
    child.stderr?.setEncoding("utf8");
    child.stdout?.on("data", (c: string) => {
      stdout += c;
    });
    child.stderr?.on("data", (c: string) => {
      stderr += c;
    });

    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      settle(false, `htb_auto timed out after ${timeoutMs}ms`);
    }, timeoutMs);

    child.once("error", (err) => settle(false, err.message));
    child.once("exit", (code) => {
      if (code !== 0) {
        // Non-zero exit: still return stdout (script prints partial output on error)
        settle(true, stdout || stderr);
      } else {
        settle(true, stdout);
      }
    });
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool definition
// ─────────────────────────────────────────────────────────────────────────────

export function createHtbPwnTool(_api: OpenClawPluginApi) {
  return {
    name: "htb_pwn",
    label: "HackTheBox Automation",
    description: [
      "Full HackTheBox automation pipeline. Uses the HTB v4 API to browse active machines,",
      "select the best target, spawn it, run automated enumeration (nmap, httpx, nuclei, gobuster),",
      "exploitation (sqlmap, SMB, FTP, SSH), capture flags, generate a structured Markdown pentest report,",
      "and return a broadcast-ready summary for Discord, Telegram, and WhatsApp.",
      "",
      "Actions:",
      "  • list    — Show all active HTB machines ranked by recommendation score",
      "  • run     — Auto-select best machine and execute the full pipeline",
      "  • recon   — Enumeration only (no exploitation) against a spawned machine",
      "",
      "Requires HTB_APP_TOKEN env var and HTB VPN connection (10.10.x.x range).",
    ].join("\n"),

    parameters: Type.Object({
      action: Type.Unsafe<"list" | "run" | "recon">({
        type: "string",
        enum: ["list", "run", "recon"],
        description: "list = show active machines | run = full pipeline | recon = enumeration-only",
      }),
      machine_id: Type.Optional(
        Type.Number({
          description: "Target a specific machine by its HTB numeric ID (overrides auto-selection)",
        }),
      ),
      machine_ip: Type.Optional(
        Type.String({
          description:
            "Override the machine IP address (use if auto-spawn IP detection fails, e.g. 10.10.11.50)",
        }),
      ),
      no_spawn: Type.Optional(
        Type.Boolean({
          description:
            "Skip machine spawning (set true if machine is already running; requires machine_ip)",
        }),
      ),
      timeout_ms: Type.Optional(
        Type.Number({
          description: "Total timeout in milliseconds (default: 3600000 = 1 hour)",
        }),
      ),
    }),

    async execute(_id: string, params: Record<string, unknown>) {
      const action = typeof params.action === "string" ? params.action : "list";
      const timeoutMs = typeof params.timeout_ms === "number" ? params.timeout_ms : 3_600_000;

      // Build CLI args for htb_auto.py
      const args: string[] = [];

      if (action === "list") {
        args.push("--list");
      } else if (action === "run") {
        args.push("--run");
        if (params.no_spawn === true) args.push("--no-spawn");
      } else if (action === "recon") {
        // Recon-only: run with --no-exploit
        if (params.machine_id != null) {
          args.push("--machine", String(params.machine_id), "--no-exploit");
        } else {
          args.push("--run", "--no-exploit");
        }
        if (params.no_spawn === true) args.push("--no-spawn");
      }

      // Common optional flags
      if (typeof params.machine_id === "number" && action !== "recon") {
        args.push("--machine", String(params.machine_id));
      }
      if (typeof params.machine_ip === "string" && params.machine_ip.trim()) {
        args.push("--ip", params.machine_ip.trim());
      }

      const rawOutput = await runHtbAuto(args, timeoutMs);

      // Extract broadcast JSON if present (emitted between marker lines)
      let broadcastData: Record<string, unknown> | null = null;
      const broadcastMatch = rawOutput.match(
        /--- BROADCAST_JSON ---\n([\s\S]*?)\n--- END_BROADCAST_JSON ---/,
      );
      if (broadcastMatch?.[1]) {
        try {
          broadcastData = JSON.parse(broadcastMatch[1]) as Record<string, unknown>;
        } catch {
          // ignore parse failure
        }
      }

      // Build human-readable summary
      const summary = buildSummary(action, rawOutput, broadcastData);

      return {
        content: [{ type: "text", text: summary }],
        details: {
          action,
          raw_output: rawOutput,
          broadcast: broadcastData,
        },
      };
    },
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Formatting helpers
// ─────────────────────────────────────────────────────────────────────────────

function buildSummary(
  action: string,
  rawOutput: string,
  broadcast: Record<string, unknown> | null,
): string {
  if (action === "list") {
    return [
      "## ⚔️ Active HackTheBox Machines",
      "",
      rawOutput.trim(),
      "",
      "_🎯 = recommended target. Run `htb_pwn` with `action: run` to start the pipeline._",
    ].join("\n");
  }

  if (!broadcast) {
    // No broadcast JSON — return raw output (likely partial / VPN not connected)
    return ["## ⚔️ HTB Pipeline Output", "", "```", rawOutput.trim().slice(0, 4000), "```"].join(
      "\n",
    );
  }

  const { machine, difficulty, os, status, flags, duration, attack_path, report_path } =
    broadcast as {
      machine?: string;
      difficulty?: string;
      os?: string;
      status?: string;
      flags?: string;
      duration?: string;
      attack_path?: string[];
      report_path?: string;
    };

  const attackSummary = Array.isArray(attack_path)
    ? attack_path
        .slice(0, 3)
        .map((s, i) => `${i + 1}. ${s}`)
        .join("\n")
    : "_No automated attack path recorded._";

  return [
    `## ⚔️ HTB ${status ?? "Run Complete"} — ${machine ?? "Unknown"}`,
    "",
    `| Field       | Value                        |`,
    `|-------------|------------------------------|`,
    `| Machine     | ${machine ?? "—"}            |`,
    `| Difficulty  | ${difficulty ?? "—"}          |`,
    `| OS          | ${os ?? "—"}                 |`,
    `| Flags       | ${flags ?? "—"}              |`,
    `| Duration    | ${duration ?? "—"}            |`,
    "",
    "### Attack Path",
    attackSummary,
    "",
    report_path ? `📋 **Full report:** \`${report_path}\`` : "",
    "",
    "> Next: use the `message` tool to broadcast this result to Discord, Telegram, and WhatsApp.",
  ].join("\n");
}
