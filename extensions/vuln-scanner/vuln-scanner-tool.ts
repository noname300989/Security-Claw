import { spawn } from "node:child_process";
import path from "node:path";
import { Type } from "@sinclair/typebox";
import type { OpenClawPluginApi } from "../../src/plugins/types.js";

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Resolve the absolute path to vuln_scanner.py, relative to the repo root.
 * Works regardless of where openclaw is invoked from.
 */
function resolveVulnScannerPath(): string {
  // __dirname-equivalent for ESM
  const here = new URL(import.meta.url).pathname;
  const repoRoot = path.resolve(path.dirname(here), "../../");
  return path.join(repoRoot, "skills", "vuln-scanner", "vuln_scanner.py");
}

/**
 * Run python3 vuln_scanner.py with the given args and return stdout.
 */
async function runVulnScanner(
  args: string[],
  timeoutMs: number,
): Promise<string> {
  const scriptPath = resolveVulnScannerPath();

  return new Promise((resolve, reject) => {
    const child = spawn("python3", [scriptPath, ...args], {
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env },
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
    child.stdout?.on("data", (c: string) => { stdout += c; });
    child.stderr?.on("data", (c: string) => { stderr += c; });

    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      settle(false, `vuln_scanner timed out after ${timeoutMs}ms`);
    }, timeoutMs);

    child.once("error", (err) => settle(false, err.message));
    child.once("exit", (code) => {
      if (code !== 0) {
        // Non-zero exit but stdout may still have findings
        settle(true, stdout || stderr);
      } else {
        settle(true, stdout);
      }
    });
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Auto-install prerequisites
// ─────────────────────────────────────────────────────────────────────────────

async function runAutoInstall(phase: string): Promise<string> {
  const here = new URL(import.meta.url).pathname;
  const repoRoot = path.resolve(path.dirname(here), "../../");
  const autoInstallPath = path.join(
    repoRoot,
    "skills",
    "distributed-workflows",
    "auto_install.py",
  );

  return new Promise((resolve) => {
    const child = spawn("python3", [autoInstallPath, "--phase", phase], {
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env },
    });
    let out = "";
    child.stdout?.setEncoding("utf8");
    child.stderr?.setEncoding("utf8");
    child.stdout?.on("data", (c: string) => { out += c; });
    child.stderr?.on("data", (c: string) => { out += c; });
    child.once("exit", () => resolve(out));
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool definition
// ─────────────────────────────────────────────────────────────────────────────

export function createVulnScannerTool(_api: OpenClawPluginApi) {
  return {
    name: "vuln_scanner",
    label: "Vulnerability Scanner",
    description: [
      "Active detection and proof-of-concept validation for critical web application vulnerabilities.",
      "Covers all OWASP Top 10 2021 categories:",
      "  • Access Control   — IDOR, privilege escalation, authentication bypass (--checks idor)",
      "  • Injection        — SQL, NoSQL, OS command injection (--checks sqli,nosqli,cmdi)",
      "  • Server-Side      — SSRF, XXE, path traversal, deserialization (--checks ssrf,xxe,traversal,deserialization)",
      "  • Client-Side      — Reflected XSS, DOM XSS, prototype pollution (--checks xss,clientside)",
      "  • Authentication   — JWT alg:none, weak HS256 secret, insecure cookies (--checks jwt)",
      "  • Business Logic   — Race conditions / TOCTOU (--checks race)",
      "  • Infrastructure   — .env, .git, backup files, admin panels, Actuator (--checks infra,headers)",
      "  • CVEs             — Nuclei template scan (--checks nuclei)",
      "",
      "All findings include: severity, OWASP category, CWE, CVSS score, payload, evidence, and remediation.",
    ].join("\n"),

    parameters: Type.Object({
      url: Type.String({
        description: "Target URL to scan (e.g. https://target.com)",
      }),
      checks: Type.Optional(
        Type.String({
          description:
            "Comma-separated check IDs. Default: all checks. " +
            "Options: sqli, nosqli, cmdi, ssrf, xxe, traversal, deserialization, " +
            "xss, clientside, idor, jwt, race, infra, headers, nuclei",
        }),
      ),
      param: Type.Optional(
        Type.String({
          description: "HTTP parameter name to inject into (default: id)",
        }),
      ),
      value: Type.Optional(
        Type.String({
          description: "Baseline value for the parameter (default: 1)",
        }),
      ),
      token: Type.Optional(
        Type.String({
          description: "Bearer token for authenticated endpoint testing",
        }),
      ),
      token_low: Type.Optional(
        Type.String({
          description: "Low-privilege Bearer token for IDOR escalation test",
        }),
      ),
      token_high: Type.Optional(
        Type.String({
          description: "High-privilege Bearer token for IDOR escalation test",
        }),
      ),
      workers: Type.Optional(
        Type.Number({
          description: "Concurrent threads for race-condition test (default: 20)",
        }),
      ),
      severity: Type.Optional(
        Type.String({
          description: "Nuclei severity filter: critical,high,medium,low (default: critical,high)",
        }),
      ),
      output_format: Type.Optional(
        Type.Unsafe<"text" | "json">({
          type: "string",
          enum: ["text", "json"],
          description: "Output format: text (rich terminal) or json (structured, for pipelines)",
        }),
      ),
      auto_install: Type.Optional(
        Type.Boolean({
          description: "Run auto-install for missing prerequisites before scanning (default: false)",
        }),
      ),
      timeout_ms: Type.Optional(
        Type.Number({
          description: "Scan timeout in milliseconds (default: 300000 = 5 minutes)",
        }),
      ),
    }),

    async execute(_id: string, params: Record<string, unknown>) {
      const url = typeof params.url === "string" ? params.url.trim() : "";
      if (!url) throw new Error("url is required");

      // Auto-install prerequisites if requested
      if (params.auto_install === true) {
        const installOut = await runAutoInstall("web");
        if (installOut.includes("Failed")) {
          console.warn("[vuln-scanner] Some tools failed to install:", installOut);
        }
      }

      // Build argument list for vuln_scanner.py
      const args: string[] = ["--url", url, "--output", "json"]; // always JSON for structured return

      if (typeof params.checks === "string" && params.checks.trim()) {
        args.push("--checks", params.checks.trim());
      }
      if (typeof params.param === "string" && params.param.trim()) {
        args.push("--param", params.param.trim());
      }
      if (typeof params.value === "string" && params.value.trim()) {
        args.push("--value", params.value.trim());
      }
      if (typeof params.token === "string" && params.token.trim()) {
        args.push("--token", params.token.trim());
      }
      if (typeof params.token_low === "string" && params.token_low.trim()) {
        args.push("--token-low", params.token_low.trim());
      }
      if (typeof params.token_high === "string" && params.token_high.trim()) {
        args.push("--token-high", params.token_high.trim());
      }
      if (typeof params.workers === "number") {
        args.push("--workers", String(params.workers));
      }
      if (typeof params.severity === "string" && params.severity.trim()) {
        args.push("--severity", params.severity.trim());
      }

      const timeoutMs =
        typeof params.timeout_ms === "number" ? params.timeout_ms : 300_000;

      const rawOutput = await runVulnScanner(args, timeoutMs);

      // Parse JSON findings from scanner
      let findings: unknown[] = [];
      try {
        findings = JSON.parse(rawOutput) as unknown[];
      } catch {
        // Scanner may emit rich text first; try to extract last JSON array
        const match = rawOutput.match(/(\[[\s\S]*\])\s*$/);
        if (match?.[1]) {
          try {
            findings = JSON.parse(match[1]) as unknown[];
          } catch {
            // Return raw output if JSON parsing fails entirely
            return {
              content: [{ type: "text", text: rawOutput }],
            };
          }
        }
      }

      // Build structured summary
      const summary = buildSummary(url, findings as FindingJson[]);

      return {
        content: [
          {
            type: "text",
            text: summary.text,
          },
        ],
        details: {
          target: url,
          total_findings: findings.length,
          by_severity: summary.bySeverity,
          findings,
        },
      };
    },
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Formatting helpers
// ─────────────────────────────────────────────────────────────────────────────

interface FindingJson {
  severity: string;
  vuln_type: string;
  title: string;
  url: string;
  parameter: string;
  payload: string;
  evidence: string;
  owasp: string;
  cwe: string;
  cvss: string;
  remediation: string;
  confirmed: boolean;
}

const SEVERITY_ORDER: Record<string, number> = {
  CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4,
};

function buildSummary(target: string, findings: FindingJson[]) {
  const bySeverity: Record<string, number> = {
    CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0,
  };
  for (const f of findings) {
    const sev = (f.severity ?? "INFO").toUpperCase();
    bySeverity[sev] = (bySeverity[sev] ?? 0) + 1;
  }

  const sorted = [...findings].sort(
    (a, b) =>
      (SEVERITY_ORDER[a.severity?.toUpperCase() ?? "INFO"] ?? 99) -
      (SEVERITY_ORDER[b.severity?.toUpperCase() ?? "INFO"] ?? 99),
  );

  const lines: string[] = [
    `## 🔍 Vulnerability Scan Results — ${target}`,
    "",
    `| Severity | Count |`,
    `|----------|-------|`,
    `| 🔴 Critical | ${bySeverity.CRITICAL} |`,
    `| 🟠 High     | ${bySeverity.HIGH} |`,
    `| 🟡 Medium   | ${bySeverity.MEDIUM} |`,
    `| 🟢 Low      | ${bySeverity.LOW} |`,
    `| ℹ Info      | ${bySeverity.INFO} |`,
    `| **Total**   | **${findings.length}** |`,
    "",
  ];

  if (findings.length === 0) {
    lines.push("✅ No vulnerabilities detected.");
  } else {
    lines.push("### Findings");
    for (const f of sorted) {
      const icon =
        f.severity === "CRITICAL"
          ? "💀"
          : f.severity === "HIGH"
            ? "🔴"
            : f.severity === "MEDIUM"
              ? "🟡"
              : "🟢";
      lines.push(
        `\n**${icon} ${f.severity} — ${f.vuln_type}**`,
        `- **Title:** ${f.title}`,
        `- **Parameter:** \`${f.parameter}\``,
        `- **Payload:** \`${f.payload.slice(0, 80)}\``,
        `- **Evidence:** ${f.evidence.slice(0, 150)}`,
        `- **OWASP:** ${f.owasp}  |  **CWE:** ${f.cwe}  |  **CVSS:** ${f.cvss}`,
        `- **Remediation:** ${f.remediation}`,
        `- **Confirmed:** ${f.confirmed ? "✅ Yes" : "⚠️ Needs manual confirm"}`,
      );
    }
  }

  return { text: lines.join("\n"), bySeverity };
}
