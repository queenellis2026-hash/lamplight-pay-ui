#!/usr/bin/env python3
"""
Lamplight Pay 3.0 Monitor — operational alerting for the AgentEscrowV3
escrow contract.

V3 has no arbiter panel, no votes, no governance. The monitor watches
the AI-Judge dispute system on BOT Chain testnet (chain 968) and alerts
via Telegram on:
  a) settlementInvariant() returning false (CRITICAL)
  b) new DisputeRaised events (with bond, ruling deadline)
  c) disputes approaching the 72h ruling deadline / refund valve
     (within 12h — at most one reminder per job per 12h)
  d) RulingExecuted events (amounts + where the bond went)
  e) DisputeTimeoutRefunded events (valve refund to payer)
  f) SettledByAgreement events (mutual settle)
  g) Credited events (a payout fell back to a pull credit)
  h) new jobs / deliveries / releases (info-level, logged only)

State is tracked in SQLite (monitor.db) to avoid duplicate alerts.

Env vars:
  TELEGRAM_CHAT_ID    — chat ID to send alerts to (an identifier, not a
                        secret). The bot token itself is NEVER here: it
                        lives in the Secure Vault as the registered
                        connection custom.telegram, and alerts are sent by
                        calling the connector helper
                        ~/workspace/custom-connectors/custom.telegram/bin/send_message.py
                        (subprocess, 30s timeout), which carries the token
                        through a surrogate exchange.
  BOTCHAIN_RPC        — RPC URL (default: https://rpc.bohr.life, testnet)
  ESCROW_ADDRESS      — contract address (default: read from
                        botchain-v3-deployment.json; empty = not deployed
                        yet, the monitor logs that and exits cleanly)
  POLL_INTERVAL_SECS  — loop poll interval (default: 60)

Usage:
  run-monitor.sh              # loop forever, polling every 60s
  run-monitor.sh --once       # single pass, then exit (cron-friendly)
  run-monitor.sh --once --poll-interval 30
"""

import argparse
import html
import json
import os
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone

# ---------------------------------------------------------------- config

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
DB_PATH = os.path.join(SCRIPT_DIR, "monitor.db")

# Connector helper that sends Telegram messages using the vault-stored
# bot token (registered connection custom.telegram). The monitor NEVER
# holds the token itself — no token in env, files, or logs.
TELEGRAM_HELPER = os.path.join(
    os.path.expanduser("~"), "workspace", "custom-connectors",
    "custom.telegram", "bin", "send_message.py")
# Bound the helper call so a hung send can never stall the monitor loop.
TELEGRAM_TIMEOUT_SECS = 30

DEFAULT_RPC_URL = "https://rpc.bohr.life"
CHAIN_ID = 968
EXPLORER = "https://scan.bohr.life"
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

# Alert if the 72h ruling deadline / refund valve is within this long
VALVE_WARNING_SECS = 12 * 3600  # 12 hours
# Re-alert for the same valve warning at most once per job per 12h
VALVE_WARN_THROTTLE_SECS = 12 * 3600

# Ruling period after a dispute is raised (contract constant, 72h)
RULING_PERIOD_SECS = 72 * 3600

# State enum from the contract:
# Created, Accepted, Delivered, Disputed, Released, Refunded, Cancelled
STATE_NAMES = ["Created", "Accepted", "Delivered", "Disputed",
               "Released", "Refunded", "Cancelled"]
STATE_DISPUTED = 3

# Job struct field indices (getJob tuple):
# 0 payer, 1 agent, 2 token, 3 amount, 4 deadline, 5 reviewWindow,
# 6 state, 7 deliveryHash, 8 metadataURI, 9 deliveredAt,
# 10 deadlineSeconds, 11 deliveryText, 12 disputeReason,
# 13 bondAmount, 14 disputedAt
JOB_PAYER, JOB_AGENT, JOB_TOKEN, JOB_AMOUNT = 0, 1, 2, 3
JOB_REVIEW_WINDOW, JOB_STATE = 5, 6
JOB_METADATA, JOB_DELIVERED_AT = 8, 9
JOB_DELIVERY_TEXT, JOB_DISPUTE_REASON = 11, 12
JOB_BOND, JOB_DISPUTED_AT = 13, 14


def load_config():
    """Read configuration from the environment. Never exits; missing
    values are reported by main() so the module stays importable."""
    rpc_url = (os.environ.get("BOTCHAIN_RPC")
               or os.environ.get("RPC_URL")
               or DEFAULT_RPC_URL)
    escrow_address = os.environ.get("ESCROW_ADDRESS", "")
    if not escrow_address:
        deploy_path = os.path.join(PROJECT_DIR, "botchain-v3-deployment.json")
        if os.path.exists(deploy_path):
            try:
                with open(deploy_path) as f:
                    escrow_address = json.load(f).get("AgentEscrowV3", "")
            except Exception:
                escrow_address = ""
    try:
        poll_interval = int(os.environ.get("POLL_INTERVAL_SECS", "60"))
    except ValueError:
        poll_interval = 60
    return {
        "rpc_url": rpc_url,
        "escrow_address": escrow_address,
        "telegram_chat_id": os.environ.get("TELEGRAM_CHAT_ID", ""),
        "poll_interval": max(5, poll_interval),
        "db_path": os.environ.get("MONITOR_DB", DB_PATH),
    }


def load_abi():
    build_path = os.path.join(PROJECT_DIR, "contracts", "build-AgentEscrowV3.json")
    if not os.path.exists(build_path):
        raise FileNotFoundError(
            f"contracts/build-AgentEscrowV3.json missing — run `python build.py` first: {build_path}")
    with open(build_path) as f:
        return json.load(f)["abi"]


# ---------------------------------------------------------------- web3

from web3 import Web3


def _topic0(sig):
    """Return the 0x-prefixed topic0 for an event signature, robust across
    web3 versions (some return hex with 0x, some without)."""
    h = Web3.keccak(text=sig).hex()
    return h if h.startswith("0x") else "0x" + h


def get_w3(rpc_url, retries=3):
    for i in range(retries):
        try:
            w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 30}))
            if w3.is_connected():
                return w3
        except Exception as e:
            print(f"[warn] RPC connect attempt {i + 1} failed: {e}", file=sys.stderr)
        time.sleep(2 ** i)
    raise RuntimeError("Could not connect to RPC after retries")


def event_topic_map(abi):
    """Map topic0 hex -> event name for every event in the ABI."""
    out = {}
    for item in abi:
        if item.get("type") != "event":
            continue
        name = item["name"]
        sig = name + "(" + ",".join(inp["type"] for inp in item["inputs"]) + ")"
        out[_topic0(sig)] = name
    return out


# ---------------------------------------------------------------- telegram

def send_telegram(cfg, text):
    """Send a Telegram message via the connector helper. Returns True on
    success, False otherwise. With no chat ID configured, prints the
    message and returns False so the alert is stored as unsent and
    retried on a later run.

    The helper (send_message.py) carries the bot token from the Secure
    Vault through a surrogate exchange — the token is never in this
    process, in env, in a file, or in a log. The message text travels
    as a subprocess argument (no shell), and the call is bounded at
    30s so a hung send can never stall the monitor loop."""
    chat_id = cfg.get("telegram_chat_id", "")
    if not chat_id:
        print("[warn] Telegram not configured (TELEGRAM_CHAT_ID missing). "
              "Message that would have been sent:")
        print("---")
        print(text)
        print("---")
        return False
    if not os.path.exists(TELEGRAM_HELPER):
        print(f"[error] Telegram helper missing: {TELEGRAM_HELPER}",
              file=sys.stderr)
        return False
    try:
        result = subprocess.run(
            [sys.executable, TELEGRAM_HELPER, str(chat_id), text],
            capture_output=True, text=True, timeout=TELEGRAM_TIMEOUT_SECS)
    except subprocess.TimeoutExpired:
        print("[error] Telegram send timed out after "
              f"{TELEGRAM_TIMEOUT_SECS}s", file=sys.stderr)
        return False
    except OSError as e:
        print(f"[error] Telegram send failed to start: {e}", file=sys.stderr)
        return False
    if result.returncode != 0:
        # Never log the full command line; the helper takes no secret,
        # but its stderr may carry API error detail — log that only.
        err = (result.stderr or "").strip()
        print(f"[error] Telegram helper failed (exit {result.returncode})"
              + (f": {err}" if err else ""), file=sys.stderr)
        return False
    try:
        delivered = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        delivered = {}
    if delivered.get("ok") is False:
        print(f"[error] Telegram API refused the message: "
              f"{delivered.get('description', 'unknown error')}",
              file=sys.stderr)
        return False
    message_id = delivered.get("result", {}).get("message_id")
    if message_id is not None:
        print(f"[info] Telegram message sent (id={message_id})")
    return True


def fmt_addr(a):
    return f"{a[:6]}...{a[-4:]}"


def fmt_usd(amount):
    """Format a 6-decimal token amount as dollars, e.g. 12500000 -> $12.50."""
    dollars = amount / 1_000_000
    return f"${dollars:,.2f}"


def fmt_ts(ts):
    """Epoch seconds -> UTC ISO string."""
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, OverflowError, OSError):
        return str(ts)


def job_link(escrow_address):
    return f"{EXPLORER}/address/{escrow_address}"


# ---------------------------------------------------------------- db

def get_db(db_path):
    db = sqlite3.connect(db_path)
    db.execute("""
        CREATE TABLE IF NOT EXISTS state (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER NOT NULL,
            kind TEXT NOT NULL,
            ref TEXT NOT NULL,
            message TEXT NOT NULL,
            sent INTEGER NOT NULL DEFAULT 0,
            UNIQUE(kind, ref)
        )
    """)
    db.commit()
    return db


def db_get(db, key, default=None):
    row = db.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
    return row[0] if row else default


def db_set(db, key, value):
    db.execute("INSERT OR REPLACE INTO state (key, value) VALUES (?, ?)", (key, str(value)))
    db.commit()


def already_alerted(db, kind, ref):
    """True only if this alert was recorded as successfully sent.
    Failed sends (sent=0) are retried on the next run."""
    return db.execute(
        "SELECT 1 FROM alerts WHERE kind = ? AND ref = ? AND sent = 1", (kind, ref)
    ).fetchone() is not None


def alerted_recently(db, kind, ref, within_secs):
    """True if an alert of this kind/ref was recorded (sent or not)
    within the last `within_secs` seconds. Used to throttle repeat
    reminders — e.g. the 12h valve warning fires at most once per job
    per 12h."""
    row = db.execute(
        "SELECT ts FROM alerts WHERE kind = ? AND ref = ? ORDER BY ts DESC LIMIT 1",
        (kind, ref),
    ).fetchone()
    if not row:
        return False
    return (int(time.time()) - int(row[0])) < within_secs


def record_alert(db, kind, ref, message, sent):
    sent_int = 1 if sent else 0
    row = db.execute(
        "SELECT id FROM alerts WHERE kind = ? AND ref = ?", (kind, ref)
    ).fetchone()
    if row:
        # Retry path: update the sent flag (and message) on the existing row.
        db.execute(
            "UPDATE alerts SET sent = ?, message = ?, ts = ? WHERE id = ?",
            (sent_int, message, int(time.time()), row[0]),
        )
    else:
        db.execute(
            "INSERT INTO alerts (ts, kind, ref, message, sent) VALUES (?, ?, ?, ?, ?)",
            (int(time.time()), kind, ref, message, sent_int),
        )
    db.commit()


def clear_alert(db, kind, ref):
    """Drop a recorded alert (used when an invariant recovers, so a
    later failure alerts again instead of being suppressed forever)."""
    db.execute("DELETE FROM alerts WHERE kind = ? AND ref = ?", (kind, ref))
    db.commit()


def resend_unsent(db, cfg):
    """Re-send every alert row stored with sent=0. Marks sent=1 on
    success so the next run skips it; leaves sent=0 on failure so the
    following run retries again."""
    rows = db.execute(
        "SELECT id, kind, ref, message FROM alerts WHERE sent = 0"
    ).fetchall()
    if not rows:
        return
    print(f"[info] Resending {len(rows)} unsent alert(s) from previous runs")
    for row_id, kind, ref, message in rows:
        sent = send_telegram(cfg, message)
        if sent:
            db.execute("UPDATE alerts SET sent = 1 WHERE id = ?", (row_id,))
            print(f"[alert] Resent {kind} alert {ref}")
        else:
            print(f"[warn] Resend failed for {kind} alert {ref}; will retry next run")
    db.commit()


# ---------------------------------------------------------------- checks

def check_invariant(w3, escrow, db, cfg):
    """Check settlementInvariant for all known tokens. CRITICAL if false.
    The invariant is balance >= unsettled + bonded + pending — a surplus
    (e.g. a 1-unit donation) must NOT trip the alert."""
    escrow_address = cfg["escrow_address"]
    tokens = set()
    try:
        topic0 = _topic0("TokenWhitelisted(address,bool)")
        logs = w3.eth.get_logs({
            "fromBlock": 0,
            "toBlock": "latest",
            "address": Web3.to_checksum_address(escrow_address),
            "topics": [topic0],
        })
        for log in logs:
            try:
                ev = escrow.events.TokenWhitelisted().process_log(log)
                if ev["args"]["allowed"]:
                    tokens.add(ev["args"]["token"])
            except Exception:
                continue
    except Exception as e:
        print(f"[warn] Could not fetch TokenWhitelisted events: {e}", file=sys.stderr)

    try:
        job_count = escrow.functions.jobCount().call()
        for i in range(min(job_count, 500)):  # cap at 500 for sanity
            try:
                job = escrow.functions.getJob(i).call()
                tokens.add(job[JOB_TOKEN])
            except Exception:
                continue
    except Exception as e:
        print(f"[warn] Could not scan jobs for tokens: {e}", file=sys.stderr)

    critical = []
    for token in tokens:
        try:
            balance, unsettled, bonded, pending, holds = \
                escrow.functions.settlementInvariant(token).call()
            print(f"[info] Invariant {fmt_addr(token)}: balance={balance} "
                  f"unsettled={unsettled} bonded={bonded} pending={pending} holds={holds}")
            ref = f"invariant-{token}"
            if not holds:
                if not already_alerted(db, "invariant", ref):
                    msg = (
                        f"🚨 <b>CRITICAL: Settlement invariant FAILED</b>\n\n"
                        f"Token: <code>{token}</code>\n"
                        f"Contract balance: {balance}\n"
                        f"Total unsettled: {unsettled}\n"
                        f"Total bonded: {bonded}\n"
                        f"Total pending credits: {pending}\n\n"
                        f"Expected: balance &gt;= unsettled + bonded + pending\n"
                        f"Contract: <a href=\"{job_link(escrow_address)}\">"
                        f"{fmt_addr(escrow_address)}</a>"
                    )
                    sent = send_telegram(cfg, msg)
                    record_alert(db, "invariant", ref, msg, sent)
                    critical.append(token)
            else:
                # Recovered (or never failed): clear any old failure row so
                # a later failure alerts again instead of being suppressed.
                clear_alert(db, "invariant", ref)
        except Exception as e:
            print(f"[warn] Invariant check failed for {token}: {e}", file=sys.stderr)
    return critical


def _job_details(escrow, job_id):
    """Fetch a job struct; returns None on failure (job may not exist)."""
    try:
        return escrow.functions.getJob(job_id).call()
    except Exception:
        return None


def _bond_posted_for_job(escrow, job_id):
    """Bond for a job, read from the BondPosted event — not from live
    state. The contract zeroes job.bondAmount when a ruling, a mutual
    settle, or the 72h valve pays the bond out (_payBond), so a dispute
    alert raised after the ruling would read bond 0 from getJob and
    wrongly report 'none (agent-raised dispute)'. The BondPosted event
    is emitted in the same transaction as DisputeRaised and never
    changes, so it is the source of truth. Returns 0 when no
    BondPosted event exists (genuinely agent-raised) or on any error
    (callers fall back to the live-state value)."""
    try:
        logs = escrow.events.BondPosted.get_logs(
            from_block=0, to_block="latest",
            argument_filters={"jobId": job_id})
    except Exception:
        return 0
    bond = 0
    for log in logs:
        try:
            bond = int(log["args"]["bondAmount"])
        except Exception:
            continue
    return bond


def handle_event(db, escrow, cfg, ev):
    """Handle one decoded contract event. Returns the block number if an
    alert for it was stored but NOT sent (so the scan does not advance
    last_block past it), else None.

    `ev` is the AttributeDict returned by process_log. All fields are
    read dict-style (ev["blockNumber"], ev["args"]["jobId"]) — never
    attribute-style — so no alert is ever silently dropped by an
    AttributeDict access quirk.
    """
    name = ev["event"]
    args = ev["args"]
    blk = ev["blockNumber"]
    txidx = ev["transactionIndex"]
    logidx = ev["logIndex"]
    escrow_address = cfg["escrow_address"]

    if name == "DisputeRaised":
        job_id = args["jobId"]
        raiser = args["by"]
        ref = f"dispute-{job_id}-{blk}-{txidx}-{logidx}"
        if already_alerted(db, "dispute", ref):
            return None
        job = _job_details(escrow, job_id)
        if job is None:
            msg = (
                f"⚠️ <b>New dispute raised — Job #{job_id}</b>\n\n"
                f"Raised by: <code>{fmt_addr(raiser)}</code>\n"
                f"(Could not fetch job details)\n"
                f"<a href=\"{job_link(escrow_address)}\">View contract</a>"
            )
        else:
            amount = job[JOB_AMOUNT]
            bond = job[JOB_BOND]
            if not bond:
                # The ruling / settle / valve may already have executed
                # and zeroed the live bond — read it from the event.
                bond = _bond_posted_for_job(escrow, job_id)
            disputed_at = job[JOB_DISPUTED_AT]
            ruling_deadline = disputed_at + RULING_PERIOD_SECS if disputed_at else 0
            claim_deadline = job[JOB_DELIVERED_AT] + job[JOB_REVIEW_WINDOW]
            bond_line = (f"Bond posted: {fmt_usd(bond)}"
                         if bond else "Bond posted: none (agent-raised dispute)")
            msg = (
                f"⚠️ <b>New dispute raised — Job #{job_id}</b>\n\n"
                f"Raised by: <code>{fmt_addr(raiser)}</code>\n"
                f"Payer: <code>{fmt_addr(job[JOB_PAYER])}</code>\n"
                f"Worker: <code>{fmt_addr(job[JOB_AGENT])}</code>\n"
                f"Amount: {fmt_usd(amount)} <code>{fmt_addr(job[JOB_TOKEN])}</code>\n"
                f"{bond_line}\n"
                f"Review window: {job[JOB_REVIEW_WINDOW] // 3600}h\n"
                f"Agent-claim deadline: {fmt_ts(claim_deadline)}\n"
                f"Ruling deadline (72h valve): {fmt_ts(ruling_deadline)}\n"
                f"Reason: {html.escape(job[JOB_DISPUTE_REASON][:500])}\n"
                f"Description: {html.escape(job[JOB_METADATA][:200])}\n\n"
                f"Decided by AI Judge. Judgment is final — no appeal.\n"
                f"<a href=\"{job_link(escrow_address)}\">View contract</a>"
            )
        sent = send_telegram(cfg, msg)
        record_alert(db, "dispute", ref, msg, sent)
        print(f"[alert] Dispute on job {job_id} by {raiser} (telegram sent: {sent})")
        return None if sent else blk

    if name == "RulingExecuted":
        job_id = args["jobId"]
        ref = f"ruling-{job_id}-{blk}-{txidx}-{logidx}"
        if already_alerted(db, "ruling", ref):
            return None
        bond_to = args["bondTo"]
        msg = (
            f"⚖️ <b>Ruling executed — Job #{job_id}</b>\n\n"
            f"To worker: {fmt_usd(args['amountToWorker'])}\n"
            f"To payer: {fmt_usd(args['amountToPayer'])}\n"
            f"Bond went to: <code>{fmt_addr(bond_to)}</code>\n\n"
            f"Decided by AI Judge. Judgment is final — no appeal.\n"
            f"<a href=\"{job_link(escrow_address)}\">View contract</a>"
        )
        sent = send_telegram(cfg, msg)
        record_alert(db, "ruling", ref, msg, sent)
        print(f"[alert] Ruling executed on job {job_id} (telegram sent: {sent})")
        return None if sent else blk

    if name == "DisputeTimeoutRefunded":
        job_id = args["jobId"]
        ref = f"valve-{job_id}-{blk}-{txidx}-{logidx}"
        if already_alerted(db, "valve", ref):
            return None
        msg = (
            f"⏰ <b>72h valve refund — Job #{job_id}</b>\n\n"
            f"No ruling executed within 72 hours, so the job refunded in full.\n"
            f"Amount refunded to payer: {fmt_usd(args['amount'])}\n"
            f"Bond refunded to payer: {fmt_usd(args['bond'])}\n"
            f"Payer: <code>{fmt_addr(args['payer'])}</code>\n"
            f"<a href=\"{job_link(escrow_address)}\">View contract</a>"
        )
        sent = send_telegram(cfg, msg)
        record_alert(db, "valve", ref, msg, sent)
        print(f"[alert] Valve refund on job {job_id} (telegram sent: {sent})")
        return None if sent else blk

    if name == "SettledByAgreement":
        job_id = args["jobId"]
        ref = f"settle-{job_id}-{blk}-{txidx}-{logidx}"
        if already_alerted(db, "settle", ref):
            return None
        msg = (
            f"🤝 <b>Mutual settlement — Job #{job_id}</b>\n\n"
            f"Both parties agreed on a split.\n"
            f"To worker: {fmt_usd(args['amountToWorker'])}\n"
            f"To payer: {fmt_usd(args['amountToPayer'])}\n"
            f"The dispute bond returned to the payer.\n"
            f"<a href=\"{job_link(escrow_address)}\">View contract</a>"
        )
        sent = send_telegram(cfg, msg)
        record_alert(db, "settle", ref, msg, sent)
        print(f"[alert] Mutual settlement on job {job_id} (telegram sent: {sent})")
        return None if sent else blk

    if name == "Credited":
        token = args["token"]
        account = args["account"]
        amount = args["amount"]
        ref = f"credit-{token}-{account}-{blk}-{txidx}-{logidx}"
        if already_alerted(db, "credit", ref):
            return None
        msg = (
            f"💳 <b>Payout fell back to a pull credit</b>\n\n"
            f"Account: <code>{fmt_addr(account)}</code>\n"
            f"Amount: {fmt_usd(amount)} <code>{fmt_addr(token)}</code>\n"
            f"The payout could not be delivered directly, so the funds are "
            f"held as a credit — the account needs to withdraw.\n"
            f"<a href=\"{job_link(escrow_address)}\">View contract</a>"
        )
        sent = send_telegram(cfg, msg)
        record_alert(db, "credit", ref, msg, sent)
        print(f"[alert] Pull credit for {account} (telegram sent: {sent})")
        return None if sent else blk

    # Low-priority events: log lines only, no Telegram alert.
    if name == "JobCreated":
        print(f"[info] Job #{args['jobId']} created: "
              f"payer {fmt_addr(args['payer'])}, "
              f"amount {fmt_usd(args['amount'])}")
    elif name == "JobAccepted":
        print(f"[info] Job #{args['jobId']} accepted by {fmt_addr(args['agent'])}")
    elif name == "DeliverySubmitted":
        print(f"[info] Job #{args['jobId']} delivery submitted")
    elif name == "JobReleased":
        print(f"[info] Job #{args['jobId']} released: "
              f"{fmt_usd(args['amount'])} to {fmt_addr(args['agent'])}")
    elif name == "JobRefunded":
        print(f"[info] Job #{args['jobId']} refunded: "
              f"{fmt_usd(args['amount'])} to {fmt_addr(args['payer'])}")
    elif name == "JobCancelled":
        print(f"[info] Job #{args['jobId']} cancelled")
    elif name == "JobPartiallyReleased":
        print(f"[info] Job #{args['jobId']} partially released: "
              f"{fmt_usd(args['amountToAgent'])} to worker, "
              f"{fmt_usd(args['amountToPayer'])} to payer")
    elif name == "BondPosted":
        print(f"[info] Bond posted on job #{args['jobId']}: "
              f"{fmt_usd(args['bondAmount'])}")
    elif name == "Withdrawn":
        print(f"[info] Withdrawal: {fmt_usd(args['amount'])} "
              f"to {fmt_addr(args['to'])}")
    elif name == "TokenWhitelisted":
        print(f"[info] Token {fmt_addr(args['token'])} "
              f"whitelisted={args['allowed']}")
    else:
        print(f"[info] Event {name} at block {blk}")
    return None


def scan_events(w3, escrow, db, cfg, topic_map):
    """Scan new blocks for contract events and dispatch them. Does NOT
    advance last_block past an alert stored with sent=0 — the next run
    must reread those logs and retry the send."""
    last_block = db_get(db, "last_block")
    current_block = w3.eth.block_number

    if last_block is None:
        last_block = max(0, current_block - 20)
        print(f"[info] First run, starting from block {last_block}")

    from_block = int(last_block) + 1
    if from_block > current_block:
        print("[info] No new blocks to scan")
        return

    print(f"[info] Scanning blocks {from_block}..{current_block} for contract events")
    try:
        logs = w3.eth.get_logs({
            "fromBlock": from_block,
            "toBlock": current_block,
            "address": Web3.to_checksum_address(cfg["escrow_address"]),
        })
    except Exception as e:
        print(f"[warn] Could not fetch event logs: {e}", file=sys.stderr)
        return

    min_unsent_block = None
    for log in logs:
        topics = log["topics"]
        if not topics:
            continue
        topic0 = topics[0].hex()
        if not topic0.startswith("0x"):
            topic0 = "0x" + topic0
        name = topic_map.get(topic0)
        if name is None:
            continue
        try:
            # Decoded events are AttributeDicts; handle_event reads every
            # field dict-style so no alert is silently dropped.
            ev = getattr(escrow.events, name)().process_log(log)
        except Exception:
            continue
        unsent_block = handle_event(db, escrow, cfg, ev)
        if unsent_block is not None and (
            min_unsent_block is None or unsent_block < min_unsent_block
        ):
            min_unsent_block = unsent_block

    if min_unsent_block is not None:
        db_set(db, "last_block", min_unsent_block - 1)
        print(f"[info] Not advancing past block {min_unsent_block} (unsent alert)")
    else:
        db_set(db, "last_block", current_block)


def check_valve_warnings(w3, escrow, db, cfg, now=None):
    """Alert on disputed jobs whose 72h ruling deadline is near. The
    ruling deadline comes from getJob's disputedAt field (disputedAt +
    72h) — never from logs, because no event carries it. The
    agent-claim deadline (deliveredAt + reviewWindow) also comes from
    getJob. Each warning fires at most once per job per 12h.
    `now` is the chain head timestamp (the time the contract uses),
    never wall-clock time."""
    if now is None:
        try:
            now = w3.eth.get_block("latest")["timestamp"]
        except Exception:
            now = int(time.time())
    try:
        job_count = escrow.functions.jobCount().call()
    except Exception as e:
        print(f"[warn] Could not get jobCount: {e}", file=sys.stderr)
        return

    for job_id in range(job_count):
        try:
            job = escrow.functions.getJob(job_id).call()
            if job[JOB_STATE] != STATE_DISPUTED:
                continue
            disputed_at = job[JOB_DISPUTED_AT]
            if not disputed_at:
                continue
            valve_opens = disputed_at + RULING_PERIOD_SECS
            remaining = valve_opens - now
            amount = job[JOB_AMOUNT]
            bond = job[JOB_BOND]
            if 0 < remaining <= VALVE_WARNING_SECS:
                ref = f"valve-warning-{job_id}"
                if alerted_recently(db, "valve-warning", ref, VALVE_WARN_THROTTLE_SECS):
                    continue
                hours = remaining / 3600
                msg = (
                    f"⏰ <b>Ruling deadline approaching — Job #{job_id}</b>\n\n"
                    f"The 72h ruling period ends in ~{hours:.1f} hours "
                    f"({fmt_ts(valve_opens)}).\n"
                    f"Amount: {fmt_usd(amount)}, bond: {fmt_usd(bond)}\n"
                    f"If no ruling executes by then, anyone may trigger the "
                    f"valve and the job + bond refund to the payer in full.\n"
                    f"<a href=\"{job_link(cfg['escrow_address'])}\">View contract</a>"
                )
                sent = send_telegram(cfg, msg)
                record_alert(db, "valve-warning", ref, msg, sent)
                print(f"[alert] Ruling deadline approaching for job {job_id} "
                      f"(telegram sent: {sent})")
            elif remaining <= 0:
                ref = f"valve-open-{job_id}"
                if alerted_recently(db, "valve-open", ref, VALVE_WARN_THROTTLE_SECS):
                    continue
                msg = (
                    f"⏰ <b>72h valve is open — Job #{job_id}</b>\n\n"
                    f"The ruling period has ended with no ruling executed.\n"
                    f"Amount: {fmt_usd(amount)}, bond: {fmt_usd(bond)}\n"
                    f"The valve refund is now available — the job + bond "
                    f"return to the payer in full when triggered.\n"
                    f"<a href=\"{job_link(cfg['escrow_address'])}\">View contract</a>"
                )
                sent = send_telegram(cfg, msg)
                record_alert(db, "valve-open", ref, msg, sent)
                print(f"[alert] 72h valve open for job {job_id} (telegram sent: {sent})")
        except Exception as e:
            print(f"[warn] Valve check failed for job {job_id}: {e}", file=sys.stderr)
            continue


def check_new_jobs(w3, escrow, db):
    """Log new jobs (info-level, no Telegram alert)."""
    last_job = db_get(db, "last_job_count", "0")
    try:
        job_count = escrow.functions.jobCount().call()
    except Exception as e:
        print(f"[warn] Could not get jobCount: {e}", file=sys.stderr)
        return
    if job_count > int(last_job):
        print(f"[info] {job_count - int(last_job)} new job(s) since last check "
              f"(total: {job_count})")
        db_set(db, "last_job_count", job_count)
    elif db_get(db, "last_job_count") is None:
        db_set(db, "last_job_count", job_count)


# ---------------------------------------------------------------- main

def run_once(cfg, w3, escrow, db, topic_map):
    """One full monitoring pass. Raises on RPC failure so the loop can
    reconnect; per-check failures are logged, not fatal."""
    resend_unsent(db, cfg)
    check_invariant(w3, escrow, db, cfg)
    scan_events(w3, escrow, db, cfg, topic_map)
    check_valve_warnings(w3, escrow, db, cfg)
    check_new_jobs(w3, escrow, db)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Lamplight Pay 3.0 monitor")
    parser.add_argument("--once", action="store_true",
                        help="run a single pass and exit (cron-friendly)")
    parser.add_argument("--poll-interval", type=int, default=None,
                        help="loop poll interval in seconds (default: 60, or POLL_INTERVAL_SECS)")
    args = parser.parse_args(argv)

    print(f"[info] Lamplight Pay 3.0 monitor starting at "
          f"{datetime.now(timezone.utc).isoformat()}")

    cfg = load_config()
    if args.poll_interval is not None:
        cfg["poll_interval"] = max(5, args.poll_interval)

    escrow_address = cfg["escrow_address"]
    if not escrow_address or escrow_address.lower() == ZERO_ADDRESS:
        print("[info] Contract not deployed yet (no ESCROW_ADDRESS and no "
              "botchain-v3-deployment.json). Waiting for deployment — "
              "monitor exiting cleanly, nothing to watch.")
        return 0

    try:
        abi = load_abi()
    except FileNotFoundError as e:
        print(f"[error] {e}", file=sys.stderr)
        return 1

    print(f"[info] Contract: {escrow_address} on chain {CHAIN_ID}")
    if not cfg["telegram_chat_id"]:
        print("[info] Telegram not configured (TELEGRAM_CHAT_ID missing) — "
              "alerts will print to stdout and be stored for retry once "
              "Telegram is set up.")

    db = get_db(cfg["db_path"])
    topic_map = event_topic_map(abi)

    def connect():
        w3 = get_w3(cfg["rpc_url"])
        if w3.eth.chain_id != CHAIN_ID:
            print(f"[warn] Connected chain id is {w3.eth.chain_id}, "
                  f"expected {CHAIN_ID} (BOT Chain testnet). Continuing.",
                  file=sys.stderr)
        escrow = w3.eth.contract(
            address=Web3.to_checksum_address(escrow_address), abi=abi)
        # Sanity: verify we're talking to the escrow contract
        operator = escrow.functions.operator().call()
        if operator.lower() == ZERO_ADDRESS:
            raise RuntimeError("operator() returned the zero address — "
                               "wrong contract or bad address")
        print(f"[info] Connected. Operator = {operator}")
        return w3, escrow

    try:
        w3, escrow = connect()
    except Exception as e:
        print(f"[error] {e}", file=sys.stderr)
        db.close()
        return 1

    if args.once:
        try:
            run_once(cfg, w3, escrow, db, topic_map)
        except Exception as e:
            print(f"[error] Monitor pass failed: {e}", file=sys.stderr)
            db.close()
            return 1
        db.close()
        print("[info] Monitor run complete.")
        return 0

    print(f"[info] Looping every {cfg['poll_interval']}s. Ctrl-C to stop.")
    while True:
        try:
            run_once(cfg, w3, escrow, db, topic_map)
        except Exception as e:
            print(f"[error] Monitor pass failed ({e}); reconnecting next "
                  f"cycle.", file=sys.stderr)
            try:
                w3, escrow = connect()
            except Exception as e2:
                print(f"[error] Reconnect failed: {e2}", file=sys.stderr)
        try:
            time.sleep(cfg["poll_interval"])
        except KeyboardInterrupt:
            print("[info] Stopping monitor.")
            break
    db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
