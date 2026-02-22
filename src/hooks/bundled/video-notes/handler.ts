import { runExec } from "../../../process/exec.js";
import type { HookHandler } from "../../hooks.js";
import { isMessageReceivedEvent } from "../../internal-hooks.js";
import { createSubsystemLogger } from "../../../logging/subsystem.js";

const log = createSubsystemLogger("hooks/video-notes");

/**
 * Regex to detect common video URLs
 */
const VIDEO_URL_REGEX = /(?:https?:\/\/)?(?:www\.)?(?:youtube\.com|youtu\.be|twitter\.com|x\.com|tiktok\.com|bilibili\.com)\/[^\s]+/gi;

/**
 * Video notes hook handler
 * 
 * Automatically transcribes and summarizes video links received in messages.
 */
const videoNotesHandler: HookHandler = async (event) => {
  // Only handle received messages
  if (!isMessageReceivedEvent(event)) {
    return;
  }

  const { content, channelId } = event.context;
  const videoUrls = content.match(VIDEO_URL_REGEX);

  if (!videoUrls || videoUrls.length === 0) {
    return;
  }

  log.info(`Detected ${videoUrls.length} video URLs in message from ${channelId}`);

  for (const url of videoUrls) {
    try {
      log.debug(`Processing video: ${url}`);
      
      // Send a "processing" status message back
      event.messages.push(`🎬 Detected video: ${url}. Generating notes...`);

      // Use the 'summarize' CLI tool (installed via skills/summarize)
      // We use --youtube auto for YouTube links, and best-effort for others.
      const isYouTube = url.includes("youtube.com") || url.includes("youtu.be");
      const args = [url, "--length", "medium"];
      
      if (isYouTube) {
        args.push("--youtube", "auto");
      }

      const { stdout, stderr } = await runExec("summarize", args, { timeoutMs: 120000 });

      if (stdout.trim()) {
        event.messages.push(`📝 **Notes for ${url}:**\n\n${stdout.trim()}`);
      } else {
        log.warn(`No summary generated for ${url}`, { stderr });
        event.messages.push(`❌ Could not generate notes for ${url}.`);
      }
    } catch (err) {
      log.error(`Failed to process video ${url}:`, { error: err instanceof Error ? err.message : String(err) });
      event.messages.push(`❌ Error processing video ${url}.`);
    }
  }
};

export default videoNotesHandler;
