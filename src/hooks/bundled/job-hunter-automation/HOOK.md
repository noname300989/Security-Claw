# Job Hunter Automation Hook

Browses job portals daily for "Penetration Testing" and "Application Security" roles, applies to them, and requests browser sign-ins as needed.

---
events:
  - "cron:daily"
---

## Workflow
1. Utilizes `browser-automation`, `job-hunter`, and `linkedin` skills.
2. Searches Naukri, Indeed, and LinkedIn down selection lists.
3. If an active session expires, it triggers the `browser-sign-in` notification system.
4. Completes applications and fires off a report to the user via Telegram/WhatsApp.
