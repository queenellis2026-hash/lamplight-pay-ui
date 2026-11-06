#!/bin/bash
# Lamplight Pay 3.0 Monitor — loop mode by default, --once for cron.
# Exits 0 on success, 1 on failure.
#
# Required env vars (set in crontab or exported before calling):
#   TELEGRAM_CHAT_ID    — numeric chat ID to send alerts to
#
# The bot token is NOT an env var: it lives in the Secure Vault as the
# registered connection custom.telegram, and monitor.py sends alerts by
# calling the connector helper
# ~/workspace/custom-connectors/custom.telegram/bin/send_message.py,
# which carries the token through a surrogate exchange. Never put the
# token in a file, env var, or log.
#
# Optional:
#   BOTCHAIN_RPC        — override default BOT Chain testnet RPC
#   VENV_PYTHON         — path to a python with web3 installed
#                        (default: $HOME/workspace/botchain-port/venv/bin/python)
#   ESCROW_ADDRESS      — override the contract address (default: read from
#                        botchain-v3-deployment.json next to this script's parent)
#   POLL_INTERVAL_SECS  — loop poll interval (default: 60)
#
# Usage:
#   run-monitor.sh            # loop forever (systemd / tmux)
#   run-monitor.sh --once     # single pass (cron every 5 minutes)

set -euo pipefail

MONITOR_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_PYTHON="${VENV_PYTHON:-$HOME/workspace/botchain-port/venv/bin/python}"
if [ ! -x "$VENV_PYTHON" ]; then
    VENV_PYTHON="$(command -v python3)"
fi

# Load the chat ID from a local env file if present (not in git).
# This file holds ONLY TELEGRAM_CHAT_ID (an identifier, not a secret).
# It must NEVER contain a bot token.
if [ -f "$MONITOR_DIR/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    source "$MONITOR_DIR/.env"
    set +a
fi

exec "$VENV_PYTHON" "$MONITOR_DIR/monitor.py" "$@"
