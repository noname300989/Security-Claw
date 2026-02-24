import yargs from "yargs";
import { hideBin } from "yargs/helpers";

interface ScanIssue {
  issue_name: string;
  issue_detail?: string;
  severity: string;
  confidence: string;
  path: string;
  origin: string;
}

interface BurpState {
  scan_id: string;
  status: string;
}

async function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function runBurpScan(targetUrl: string, apiUrl: string, apiKey?: string) {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (apiKey) {
    headers["Authorization"] = apiKey;
  }

  try {
    console.log(`[+] Initializing zero-touch scan against ${targetUrl}...`);

    // Create the scan configuration
    // In Burp REST API (v1337 or Enterprise APIs, depending on the exact deployment)
    // We configure active scanning with a custom configuration limiting to 1 thread.
    // For Burp Suite Pro REST API plugin, the payload varies slightly.
    // We will assume the standard Burp Suite Pro REST API plugin format.

    const scanPayload = {
      urls: [targetUrl],
      scan_configurations: [
        {
          type: "NamedConfiguration",
          name: "Audit coverage - maximum",
        },
        {
          // A custom JSON snippet directly overriding the thread count to 1
          // depending on how the given Burp REST API supports it.
          type: "CustomConfiguration",
          content: JSON.stringify({
            scanner: {
              active_scanning_optimization: {
                concurrent_requests: 1,
              },
            },
          }),
        },
      ],
    };

    const response = await fetch(`${apiUrl}/v0.1/scan`, {
      method: "POST",
      headers,
      body: JSON.stringify(scanPayload),
    });

    if (!response.ok) {
      console.error(`[!] Failed to start scan. Status: ${response.status}`);
      console.error(await response.text());
      process.exit(1);
    }

    const scanLocation = response.headers.get("Location");
    let scanId = "";

    if (scanLocation) {
      scanId = scanLocation;
    } else {
      // Fallback to reading the body depending on the REST API version
      const scanData = (await response.json()) as { task_id?: string; scan_id?: string };
      scanId = scanData.task_id || scanData.scan_id || "";
    }

    if (!scanId) {
      console.error("[!] Scan triggered, but could not retrieve scan ID.");
      process.exit(1);
    }

    console.log(`[+] Scan started successfully. Task ID: ${scanId}`);
    console.log(`[+] Enforcing concurrent requests = 1`);

    // Polling the scan status
    let isComplete = false;
    while (!isComplete) {
      await sleep(10000); // 10s intervals

      // Depending on if the task ID is a full URL or just an ID
      const statusUrl = scanId.startsWith("http") ? scanId : `${apiUrl}/v0.1/scan/${scanId}`;

      const statusRes = await fetch(statusUrl, { headers });
      if (!statusRes.ok) continue;

      const state = (await statusRes.json()) as { scan_status: string; metrics?: any };
      const status = state.scan_status || "unknown";

      console.log(`[*] Scan Status: ${status} | Metrics: ${JSON.stringify(state.metrics || {})}`);

      if (["succeeded", "failed", "cancelled"].includes(status.toLowerCase())) {
        isComplete = true;
      }
    }

    console.log(`[+] Scan complete. Fetching issues...`);

    // Fetch issues
    const issuesUrl = `${apiUrl}/v0.1/knowledge_base/issue_definitions`;
    // Note: The actual endpoint for fetching vulnerabilities depends heavily on the Burp REST API version.
    // This is a common path for grabbing the scan issues from a specific task ID.
    const resultsRes = await fetch(`${apiUrl}/v0.1/scan/${scanId}`, { headers });
    if (!resultsRes.ok) {
      console.error(`[!] Failed to retrieve scan issues. Status: ${resultsRes.status}`);
      process.exit(1);
    }

    const resultsData = (await resultsRes.json()) as { issue_events?: ScanIssue[] };
    const issues = resultsData.issue_events || [];

    // Filter for High and Critical vulnerabilities only
    const severeVulnerabilities = issues.filter((issue) =>
      ["high", "critical"].includes(issue.severity.toLowerCase()),
    );

    console.log(`\n============================`);
    console.log(`      SCAN RESULTS `);
    console.log(`============================`);
    console.log(
      `[!] Found ${severeVulnerabilities.length} High/Critical vulnerabilities out of ${issues.length} total issues.\n`,
    );

    for (const vuln of severeVulnerabilities) {
      console.log(`[${vuln.severity.toUpperCase()}] ${vuln.issue_name}`);
      console.log(`    Path: ${vuln.path}`);
      console.log(`    Confidence: ${vuln.confidence}`);
      if (vuln.issue_detail) console.log(`    Detail: ${vuln.issue_detail.substring(0, 200)}...`);
      console.log("---");
    }

    console.log(`[+] Zero-touch BurpSuite scan completed successfully.`);
  } catch (e: any) {
    console.error(`[!] Error communicating with BurpSuite API: ${e.message}`);
    process.exit(1);
  }
}

// Parse CLI arguments
yargs(hideBin(process.argv))
  .command(
    "$0",
    "Run Burp Suite active scan via REST API",
    (yargs) => {
      return yargs
        .option("target", {
          alias: "t",
          type: "string",
          description: "Target URL to scan",
          demandOption: true,
        })
        .option("apiUrl", {
          alias: "u",
          type: "string",
          description: "Burp Suite REST API Base URL",
          default: "http://127.0.0.1:1337",
        })
        .option("apiKey", {
          alias: "k",
          type: "string",
          description: "API Key (if required)",
        });
    },
    async (argv) => {
      await runBurpScan(argv.target, argv.apiUrl, argv.apiKey);
    },
  )
  .help()
  .parse();
