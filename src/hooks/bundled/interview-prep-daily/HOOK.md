# Interview Preparation Generator

Every day, this hook coordinates with the `interview-prep` agent to generate 50 deep technical interview questions.
The output is written locally to `apps/interview-dashboard/data.json` and a broadcast is sent to all messaging channels.

---

events:

- "cron:daily"

---

## Workflow

1. Prompt the `interview-prep` logic for 50 questions across 5 security domains.
2. Format into strict JSON.
3. Write to the Dashboard data store.
4. Broadcast notifications to WhatsApp, Telegram, and Discord.
