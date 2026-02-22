# Browser Sign-In Hook

Notifies the user via messaging channels when an agent or tool requires a manual browser sign-in.

---
events:
  - "message:sent"
---

## Workflow
1. Watch outbound messages for "sign-in", "log-in", or "authentication" required patterns.
2. If detected, ensure a push notification/alert is sent to the user's primary channel (Telegram/WhatsApp).
