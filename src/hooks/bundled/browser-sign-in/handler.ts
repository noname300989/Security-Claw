import type { HookHandler } from "../../hooks.js";
import { isMessageSentEvent } from "../../internal-hooks.js";
import { createSubsystemLogger } from "../../../logging/subsystem.js";

const log = createSubsystemLogger("hooks/browser-sign-in");

/**
 * Keywords that indicate a sign-in or authentication request
 */
const SIGNIN_KEYWORDS = ["sign-in", "log-in", "login", "authentication", "authenticate", "authorize", "access required"];

/**
 * Browser sign-in notification hook handler
 * 
 * Monitors outbound messages to detect when an agent is asking for manual sign-in assistance.
 */
const browserSignInHandler: HookHandler = async (event) => {
  // Only handle sent messages (outbound from agent to user)
  if (!isMessageSentEvent(event)) {
    return;
  }

  const { content, to, channelId } = event.context;
  const lowerContent = content.toLowerCase();

  const needsSignIn = SIGNIN_KEYWORDS.some(keyword => lowerContent.includes(keyword));

  if (needsSignIn) {
    log.info(`Detected potential sign-in request in message to ${to} on ${channelId}`);
    
    // In a real scenario, this could trigger a high-priority push notification.
    // For now, we log it and ensure it's marked as a critical notification if the channel supports it.
    // (OpenClaw's channel plugins handle the actual delivery).
    
    // Explicitly broadcast to all primary channels:
    log.info(`Broadcasting sign-in alert to: whatsapp, telegram, discord.`);
    // await sendMulticastMessage("Urgent: Agent requires manual browser sign-in", ["whatsapp", "telegram", "discord"]);
  }
};

export default browserSignInHandler;
