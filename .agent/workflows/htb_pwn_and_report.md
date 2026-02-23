---
description: Full HackTheBox automation — browse active boxes, run enumeration and exploitation, generate a pentest report, and broadcast results to Discord, Telegram, and WhatsApp.
---

# HTB Pwn & Report Workflow

This workflow orchestrates the end-to-end HackTheBox automation pipeline
using the `htb-pwn` skill and the existing messaging integrations.

## Prerequisites

Before running, confirm the following are available:

1. **HTB App Token** — set as `HTB_APP_TOKEN` in `.env` or `openclaw.json`
   - Get it: https://app.hackthebox.com/profile/settings → **App Token**
2. **HTB VPN** — must be connected before the script is run
   - Connect: `sudo openvpn <your_htb_vpn_config>.ovpn`
3. **Discord** — `DISCORD_BOT_TOKEN` must be set, and `HTB_DISCORD_CHANNEL` must be in env
4. **Telegram** — `TELEGRAM_BOT_TOKEN` must be set, and `HTB_TELEGRAM_CHAT` must be in env
5. **WhatsApp** — `wacli` must be installed and authenticated (`wacli auth`),
   and `HTB_WHATSAPP_TO` must be set in env with the recipient number

---

## Step 1 — Verify Configuration

Run the env check before starting:

```bash
python3 -c "
import os, sys
required = ['HTB_APP_TOKEN']
for v in required:
    val = os.environ.get(v, '')
    status = '✅' if val else '❌ MISSING'
    print(f'  {v}: {status}')
for v in ['HTB_DISCORD_CHANNEL', 'HTB_TELEGRAM_CHAT', 'HTB_WHATSAPP_TO']:
    val = os.environ.get(v, '')
    status = f'✅ {val}' if val else '⚠️  not set (channel skipped)'
    print(f'  {v}: {status}')
"
```

---

## Step 2 — Browse Available Machines

List all active HTB machines ranked by recommended target priority:

```bash
cd "/Users/gayatrirachakonda/Security Claw"
python3 skills/htb-pwn/scripts/htb_auto.py --list
```

The output table shows machines ranked from easiest/most recommended (🎯)
to hardest. Confirm the target with the user if desired, or proceed to Step 3
for fully automated selection.

---

## Step 3 — Run Full Automation Pipeline

// turbo

```bash
cd "/Users/gayatrirachakonda/Security Claw"
python3 skills/htb-pwn/scripts/htb_auto.py --run
```

This will:

- Auto-select the highest-priority active machine
- Spawn the machine on HTB (if not already running)
- Run nmap, httpx, nuclei, gobuster, sqlmap
- Prompt for flags if a shell is obtained
- Submit flags to HTB API
- Generate a full Markdown report in `reports/<machine>_<date>/report.md`
- Print a `BROADCAST_JSON` block for the next step

> **Targeting a specific machine?** Use `--machine <ID>` instead of `--run`
> **Recon only?** Add `--no-exploit` to skip active exploitation
> **Already spawned?** Add `--no-spawn --ip 10.10.XX.XX`

---

## Step 4 — Read Broadcast JSON

After Step 3 completes, parse the script's `BROADCAST_JSON` output
(printed between `--- BROADCAST_JSON ---` markers) and extract:

- `machine`, `difficulty`, `os`, `status`, `flags`, `duration`, `attack_path`, `report_path`

These values are used to compose the broadcast messages in Steps 5–7.

---

## Step 5 — Post to Discord

Use the `discord` skill. Replace `<CHANNEL_ID>` with the value of `HTB_DISCORD_CHANNEL`.

```json
{
  "action": "send",
  "channel": "discord",
  "to": "channel:<CHANNEL_ID>",
  "message": "⚔️ HTB Box <STATUS>!",
  "embeds": [
    {
      "title": "HTB: <MachineName> — <STATUS>",
      "color": 5763719,
      "description": "Full automated engagement complete.",
      "fields": [
        { "name": "Machine", "value": "<MachineName>", "inline": true },
        { "name": "Difficulty", "value": "<Difficulty>", "inline": true },
        { "name": "OS", "value": "<OS>", "inline": true },
        { "name": "Flags", "value": "<Flags>", "inline": true },
        { "name": "Duration", "value": "<Duration>", "inline": true },
        { "name": "Attack Path", "value": "<AttackPath[0]>" }
      ],
      "footer": { "text": "OpenClaw htb-pwn skill • HackTheBox" }
    }
  ]
}
```

Also send the full report file as an attachment:

```json
{
  "action": "send",
  "channel": "discord",
  "to": "channel:<CHANNEL_ID>",
  "message": "📋 Full pentest report attached",
  "media": "<report_path>"
}
```

---

## Step 6 — Post to Telegram

Use the `telegram` skill. Replace `<CHAT_ID>` with `HTB_TELEGRAM_CHAT`.

```json
{
  "tool": "message",
  "action": "send",
  "provider": "telegram",
  "to": "<CHAT_ID>",
  "text": "*⚔️ HTB Box <STATUS>*\n\n`Machine:` <MachineName> (<Difficulty> · <OS>)\n`Flags:` <Flags>\n`Duration:` <Duration>\n`Attack:` <AttackPath[0]>\n\nFull report attached 👇"
}
```

Then send the report file:

```json
{
  "tool": "message",
  "action": "send",
  "provider": "telegram",
  "to": "<CHAT_ID>",
  "text": "📋 HTB Report: <MachineName>",
  "media": ["<report_path>"]
}
```

---

## Step 7 — Post to WhatsApp (via wacli)

Send a text summary via `wacli`:

```bash
wacli send text \
  --to "$HTB_WHATSAPP_TO" \
  --message "⚔️ HTB Box <STATUS>! Machine: <MachineName> (<Difficulty> · <OS>) | Flags: <Flags> | Duration: <Duration> | Attack: <AttackPath[0]> | Report: <report_path>"
```

Send the report as a file attachment:

```bash
wacli send file \
  --to "$HTB_WHATSAPP_TO" \
  --file "<report_path>" \
  --caption "HTB Pentest Report: <MachineName>"
```

---

## Full One-Line Agent Prompt

You can trigger the entire workflow with a single prompt to the OpenClaw agent:

```
Run the HTB automation pipeline on HackTheBox — pick the best active box, hack it,
and when done send the report and a summary to Discord, Telegram, and WhatsApp.
```

---

## Troubleshooting

| Issue                       | Fix                                                                  |
| --------------------------- | -------------------------------------------------------------------- |
| `HTB_APP_TOKEN not set`     | Add token to `.env` file                                             |
| Machine IP not returned     | Re-run with `--no-spawn --ip 10.10.XX.XX` after manual spawn         |
| `nmap: command not found`   | `brew install nmap` (macOS) or `apt install nmap` (Linux)            |
| `nuclei: command not found` | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| VPN not connected           | `sudo openvpn <config>.ovpn` in a separate terminal                  |
| WhatsApp not working        | Run `wacli auth` to authenticate first                               |
| Discord bot not posting     | Verify `DISCORD_BOT_TOKEN` and bot has channel permissions           |
