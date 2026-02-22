import type { AgentTool } from "@mariozechner/pi-agent-core";

// oxlint-disable-next-line typescript/no-explicit-any
export type AnyAgentTool = AgentTool<any, unknown> & {
  name: string;
  ownerOnly?: boolean;
};

export const OWNER_ONLY_TOOL_ERROR = "Tool restricted to owner senders.";

export function wrapOwnerOnlyToolExecution(
  tool: AnyAgentTool,
  senderIsOwner: boolean,
): AnyAgentTool {
  if (tool.ownerOnly !== true || senderIsOwner || !tool.execute) {
    return tool;
  }
  return {
    ...tool,
    execute: async () => {
      throw new Error(OWNER_ONLY_TOOL_ERROR);
    },
  };
}
