---
name: video-notes
description: "Automated video processing and note extraction via the video-notes hook. Fires when a video link or file is received on messaging channels. Extracts transcripts, key moments, and written summaries from security conference talks, CTF writeups, or training videos. Triggered by message:received events."
metadata: { "openclaw": { "emoji": "🎬" } }
---

# Video Notes Hook

Automatically process video links/files received in chat and extract structured notes.

## When to Use

✅ **USE this skill when:**

- You receive a YouTube, Vimeo, or direct video link in chat
- You want a transcript and key-points summary from a security talk or CTF writeup video
- Processing conference talk recordings (DEF CON, Black Hat, BSides) for notes
- Extracting actionable takeaways from penetration testing tutorial videos

## How It Works

The `video-notes` hook fires on `message:received` and:

1. Detects video URLs or file paths in incoming messages
2. Downloads or fetches the video/audio stream
3. Transcribes via OpenAI Whisper (or local `sherpa-onnx-tts`)
4. Sends the transcript + key points summary back to chat

## Trigger On-Demand

Send a video link to any connected channel, or ask directly:

```
Process this video and extract notes: https://youtube.com/watch?v=example
Transcribe and summarize the DEF CON talk at [URL]
Extract key points from this recording: /videos/redteam_training.mp4
```

## Supported Sources

| Source             | Notes                                  |
| ------------------ | -------------------------------------- |
| YouTube            | Via `yt-dlp`                           |
| Vimeo              | Via `yt-dlp`                           |
| MP4/MKV/WEBM files | Direct local or URL                    |
| Conference streams | DEF CON, Black Hat, BSides via YouTube |

## Output Format

```markdown
# Video Notes: "Advanced Active Directory Attacks" — John Doe @ DEF CON 2024

## Summary

A deep-dive into modern AD attack chains using BloodHound, impacket, and Rubeus.

## Key Points

1. Kerberoasting is still highly effective in modern environments
2. AS-REP Roasting targets accounts with pre-auth disabled
3. Diamond Tickets bypass PAC validation in patched DCs

## Timestamps

- 00:02:15 — Kerberoasting demo
- 00:18:45 — BloodHound shortest path analysis
- 00:34:20 — Diamond Ticket forge

## Full Transcript

[...]
```

## Related Skills

- **video-frames** — Extract and analyze individual frames from videos
- **openai-whisper** — Direct transcription without the full hook pipeline

## Config

```json5
{
  hooks: {
    entries: {
      "video-notes": {
        enabled: true,
        config: {
          maxDurationMinutes: 120,
          transcriptionModel: "whisper-1",
        },
      },
    },
  },
}
```

## Usage from Agent

```
Transcribe and summarize this DEF CON talk: https://youtube.com/watch?v=...
Extract notes from the Black Hat presentation video
Process the red team training recording and highlight key techniques mentioned
```
