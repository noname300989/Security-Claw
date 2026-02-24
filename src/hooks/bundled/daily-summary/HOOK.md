# Daily Agent Summary Hook

Automatically generates and sends a summary of all agent activities for the day.

---

events:

- "cron:daily"

---

## Workflow

1. At the scheduled time, gather logs from `agent-chronicle` and active session histories.
2. Compile a concise summary of tasks completed, jobs applied to, and security findings.
3. Send this summary directly to the user's primary channel (WhatsApp/Telegram).
