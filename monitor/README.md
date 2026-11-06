# Lamplight Pay 3.0 Monitor

Operational alerting for the AgentEscrowV3 escrow contract on BOT Chain
testnet (chain 968). V3 has no arbiter panel, no votes, no governance —
the monitor watches the AI-Judge dispute system.

## What it watches

| Check | Severity | Trigger |
|---|---|---|
| `settlementInvariant()` returns false | 🚨 CRITICAL | Immediate Telegram alert (invariant is `>=`, a surplus does not trip it) |
| New `DisputeRaised` event | ⚠️ Alert | Telegram with job, raiser, bond, ruling deadline |
| Dispute within 12h of the 72h ruling deadline | ⏰ Reminder | Telegram, at most once per job per 12h |
| 72h valve already open, no ruling yet | ⏰ Reminder | Telegram, at most once per job per 12h |
| `RulingExecuted` event | ⚖️ Alert | Telegram with amounts + where the bond went |
| `DisputeTimeoutRefunded` event (valve refund) | ⏰ Alert | Telegram with amount + bond refunded |
| `SettledByAgreement` event (mutual settle) | 🤝 Alert | Telegram with the agreed split |
| `Credited` event (payout fell back to pull credit) | 💳 Alert | Telegram — the account needs to withdraw |
| New jobs / deliveries / releases | ℹ️ Info | Logged only, no alert |

The ruling deadline (`disputedAt + 72h`) and the agent-claim deadline
(`deliveredAt + reviewWindow`) are read from `getJob` — `reviewWindow`
is in no event, so they are never computed from logs.

## Setup

### 1. Telegram bot

1. Message [@BotFather](https://t.me/BotFather) on Telegram, send `/newbot`, follow the prompts. The token it returns goes into the Secure Vault (registered connection `custom.telegram`) via the secure setup page — never paste it in chat, never put it in a file or an env var.
2. Start a chat with your new bot (send it any message).
3. Get your chat ID: message [@userinfobot](https://t.me/userinfobot) on Telegram; it replies with your numeric ID.
4. Set the chat ID where the monitor can read it — env var, or `monitor/.env` (this file is NOT committed, and holds ONLY the chat ID, never a token):
   ```
   TELEGRAM_CHAT_ID=8822453816
   ```

Alerts are sent by calling the connector helper
`~/workspace/custom-connectors/custom.telegram/bin/send_message.py`
(subprocess, 30s timeout), which carries the vault-stored token
through a surrogate exchange. The monitor itself never holds the
token. Messages go out with `parse_mode` HTML, so alert text may use
`<b>`, `<code>` and `<a>` tags; untrusted text (dispute reasons,
job descriptions) is HTML-escaped before sending.

Without a chat ID configured, the monitor still runs — alerts print to
stdout instead of sending, and are stored for retry once Telegram is
set up. A failed or timed-out send is likewise stored (`sent=0`) and
retried on the next run; no alert is ever silently dropped.

### 2. Contract address

The monitor reads the address from `ESCROW_ADDRESS` (env) or from
`~/workspace/botchain-pay-3.0/botchain-v3-deployment.json` (written by
`deploy_v3_testnet.py`). If neither exists, it logs that the contract
is not deployed yet and exits cleanly.

### 3. Test run

```bash
~/workspace/botchain-pay-3.0/monitor/run-monitor.sh --once
```

Expected output: connects to the contract, prints the operator address,
checks the invariant for known tokens, scans recent blocks for events,
and reports "Monitor run complete."

### 4. Running it

Loop mode (systemd / tmux, polls every 60s by default):

```bash
~/workspace/botchain-pay-3.0/monitor/run-monitor.sh
```

Cron (every 5 minutes, single pass):

```bash
crontab -e
```

Add:

```
*/5 * * * * /home/hatch/workspace/botchain-pay-3.0/monitor/run-monitor.sh --once >> /home/hatch/workspace/botchain-pay-3.0/monitor/monitor.log 2>&1
```

Verify with `crontab -l` and check `monitor.log` after 5–10 minutes.

Poll interval: `POLL_INTERVAL_SECS` env or `--poll-interval` (seconds,
default 60, minimum 5).

## State

`monitor.db` (SQLite, created on first run) tracks:
- `last_block` — last scanned block (no re-processing; never advanced
  past an alert stored unsent, so a failed Telegram send is retried)
- `last_job_count` — for new-job awareness
- `alerts` — every alert sent, deduplicated by `(kind, ref)` so you
  never get the same alert twice; failed sends (`sent=0`) are retried
  on the next run

To reset (e.g., after testing): `rm monitor.db` — the next run
re-initializes from ~20 blocks back.

## Files

- `monitor.py` — the monitor (single file, stdlib + web3 only)
- `run-monitor.sh` — launcher (falls back to `python3` if the venv
  python is missing; passes args through to `monitor.py`)
- `README.md` — this file
- `monitor.db` — state (created on first run, not committed)
- `.env` — chat ID only, `TELEGRAM_CHAT_ID` (created by you, not
  committed; never a token)
