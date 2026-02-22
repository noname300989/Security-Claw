# Video Notes Hook

Triggers automated video processing when a video link or file is received on messaging channels.

---
events:
  - "message:received"
requires:
  bins:
    - "yt-dlp"
    - "ffmpeg"
  env:
    - "OPENAI_API_KEY"
---

## Workflow
1. Detect video URL (YouTube, X, TikTok, etc.) or video attachment.
2. Download audio/video using `yt-dlp`.
3. Transcribe using the `whisper` skill.
4. Generate notes using the `notebooklm` or `summarize` skill.
5. Post the resulting notes back to the same conversation.
