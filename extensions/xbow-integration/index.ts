import { OpenClawPluginApi } from "@openclaw/plugin-sdk";
import { createXbowTool } from "./xbow-tool.js";

export default async function register(api: OpenClawPluginApi) {
  const tool = createXbowTool(api);
  api.registerTool(tool);
  api.logger.info(`XBOW integration plugin registered tools: ${tool.name}`);
}
