import type { OpenClawPluginApi } from "../../src/plugins/types.js";
import { createVulnScannerTool } from "./vuln-scanner-tool.js";

export function activate(api: OpenClawPluginApi) {
  const tool = createVulnScannerTool(api);
  api.registerTool(tool as any);
}
