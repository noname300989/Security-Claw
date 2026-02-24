import type { OpenClawPluginApi } from "@openclaw/plugin-sdk";
import { vibecodeTool } from "./vibecode-tool.js";

export default async function register(api: OpenClawPluginApi) {
  api.registerTool(vibecodeTool);
  api.logger.info(`Antigravity Vibecoding plugin registered tool: ${vibecodeTool.name}`);
}
