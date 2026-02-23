import type { OpenClawPluginApi } from "../../src/plugins/types.js";
import { createHtbPwnTool } from "./htb-pwn-tool.js";

export function activate(api: OpenClawPluginApi) {
  const tool = createHtbPwnTool(api);
  api.registerTool(tool as any);
}
