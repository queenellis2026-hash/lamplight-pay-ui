#!/usr/bin/env python3
"""Tests for the Lamplight Pay 3.0 monitor (monitor/monitor.py).

Handlers are tested against REAL contract events on eth-tester: jobs are
created, disputed, ruled, settled, and valve-refunded on-chain, and the
monitor's scan/handlers run against the resulting logs. This also covers
the AttributeDict regression (Claude's V23 fix #1): decoded events are
real process_log AttributeDicts, and the alert must fire.

Run: ~/workspace/botchain-port/venv/bin/python -m pytest tests/test_monitor.py -q
"""
import os
import sqlite3
import subprocess
import sys

import pytest
from web3.datastructures import AttributeDict

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "monitor"))
import monitor as mon

from conftest import AMOUNT, bond_for

# ---------------------------------------------------------------- helpers


def _cfg(env, tmp_path, telegram=False):
    """Monitor config pointing at the eth-tester deployment."""
    cfg = mon.load_config()
    cfg["escrow_address"] = env.escrow_addr
    cfg["db_path"] = str(tmp_path / "monitor.db")
    if not telegram:
        # No chat ID -> send_telegram prints and returns False, so the
        # alert is stored unsent (sent=0) and retried on a later run.
        cfg["telegram_chat_id"] = ""
    return cfg


def _db(cfg):
    return mon.get_db(cfg["db_path"])


def _alerts(db, kind=None):
    if kind:
        rows = db.execute(
            "SELECT kind, ref, message, sent FROM alerts WHERE kind = ?", (kind,)
        ).fetchall()
    else:
        rows = db.execute("SELECT kind, ref, message, sent FROM alerts").fetchall()
    return rows


def _scan(env, cfg, db):
    """Run the monitor's event scan over all blocks so far."""
    topic_map = mon.event_topic_map(mon.load_abi())
    mon.scan_events(env.w3, env.escrow, db, cfg, topic_map)


def _dispute_as_payer(env, job_id=None, reason="dispute reason"):
    """Create a delivered job and dispute it as the payer (posts bond).
    Returns (job_id, dispute_receipt)."""
    if job_id is None:
        job_id = env.create_delivered_job()
    bond = bond_for(AMOUNT)
    env.mint_and_approve(env.payer, bond, approve=bond)
    r = env.send_as(env.payer, lambda: env.escrow.functions.raiseDispute(job_id, reason))
    assert r["status"] == 1, "raiseDispute failed"
    return job_id, r


# ---------------------------------------------------------------- dispute alert


def test_dispute_alert_fires(env, tmp_path):
    """Real DisputeRaised log -> alert recorded with job, bond, deadlines.
    Also proves the AttributeDict regression is fixed: the decoded event
    is a real process_log AttributeDict and the alert fires."""
    cfg = _cfg(env, tmp_path)
    db = _db(cfg)
    job_id, _receipt = _dispute_as_payer(env)
    _scan(env, cfg, db)

    rows = _alerts(db, "dispute")
    assert len(rows) == 1, f"expected 1 dispute alert, got {len(rows)}"
    msg = rows[0][2]
    assert f"Job #{job_id}" in msg
    assert "$50.00" in msg  # bond: 20% of $1000, capped at $50
    assert "Ruling deadline (72h valve)" in msg
    assert "Decided by AI Judge" in msg
    assert "Bond posted: $50.00" in msg
    db.close()


def test_dispute_alert_no_spam_on_rescan(env, tmp_path):
    """Scanning the same blocks twice records the dispute alert once."""
    cfg = _cfg(env, tmp_path)
    db = _db(cfg)
    _dispute_as_payer(env)
    _scan(env, cfg, db)
    _scan(env, cfg, db)
    assert len(_alerts(db, "dispute")) == 1
    db.close()


def test_html_escape_in_dispute_alert(env, tmp_path):
    """A malicious description/reason must be HTML-escaped in the alert,
    never injected raw."""
    cfg = _cfg(env, tmp_path)
    db = _db(cfg)
    evil_meta = '<script>alert("x")</script> job'
    evil_reason = '<b>bold</b> & <img src=x onerror=alert(1)>'
    env.mint_and_approve(env.payer, AMOUNT)
    r = env.send_as(env.payer, lambda: env.escrow.functions.createJob(
        env.agent.address, env.token_addr, AMOUNT, 24 * 3600, 48 * 3600, evil_meta))
    assert r["status"] == 1
    job_id = env.escrow.functions.jobCount().call() - 1
    r = env.send_as(env.agent, lambda: env.escrow.functions.acceptJob(job_id))
    assert r["status"] == 1
    dh = env.w3.keccak(text=f"delivery-{job_id}")
    r = env.send_as(env.agent, lambda: env.escrow.functions.submitDelivery(
        job_id, dh, "delivery"))
    assert r["status"] == 1
    bond = bond_for(AMOUNT)
    env.mint_and_approve(env.payer, bond, approve=bond)
    r = env.send_as(env.payer, lambda: env.escrow.functions.raiseDispute(job_id, evil_reason))
    assert r["status"] == 1
    _scan(env, cfg, db)

    rows = _alerts(db, "dispute")
    assert len(rows) == 1
    msg = rows[0][2]
    assert "<script>" not in msg
    assert "&lt;script&gt;" in msg
    assert "<b>bold</b>" not in msg
    assert "&lt;b&gt;bold&lt;/b&gt;" in msg
    assert "&amp;" in msg
    db.close()


def test_agent_dispute_alert_no_bond(env, tmp_path):
    """An agent-raised dispute (atomic deliver+dispute) alerts with
    'Bond posted: none'."""
    cfg = _cfg(env, tmp_path)
    db = _db(cfg)
    job_id = env.create_disputed_job(by="agent")
    _scan(env, cfg, db)
    rows = _alerts(db, "dispute")
    assert len(rows) == 1
    assert "Bond posted: none (agent-raised dispute)" in rows[0][2]
    db.close()


# ---------------------------------------------------------------- ruling / valve / settle


def test_ruling_alert_fires(env, tmp_path):
    """RulingExecuted -> alert with amounts and where the bond went."""
    cfg = _cfg(env, tmp_path)
    db = _db(cfg)
    job_id, _ = _dispute_as_payer(env)
    r = env.send_as(env.operator, lambda: env.escrow.functions.executeRuling(
        job_id, 600_000_000))  # 60% to worker
    assert r["status"] == 1, "executeRuling failed"
    _scan(env, cfg, db)
    rows = _alerts(db, "ruling")
    assert len(rows) == 1
    msg = rows[0][2]
    assert f"Job #{job_id}" in msg
    assert "$600.00" in msg  # to worker
    assert "$400.00" in msg  # to payer
    assert "Bond went to" in msg
    # Bond follows the ruling: 60% >= 50% -> bond to the worker
    assert f"{env.agent.address[:6]}...{env.agent.address[-4:]}" in msg
    db.close()


def test_valve_refund_alert_fires(env, tmp_path):
    """DisputeTimeoutRefunded -> alert with amount + bond refunded."""
    cfg = _cfg(env, tmp_path)
    db = _db(cfg)
    job_id, _ = _dispute_as_payer(env)
    env.time_travel(72 * 3600 + 1)
    r = env.send_as(env.payer, lambda: env.escrow.functions.refundDisputeTimeout(job_id))
    assert r["status"] == 1, "refundDisputeTimeout failed"
    _scan(env, cfg, db)
    rows = _alerts(db, "valve")
    assert len(rows) == 1
    msg = rows[0][2]
    assert f"Job #{job_id}" in msg
    assert "$1,000.00" in msg  # job amount refunded
    assert "$50.00" in msg  # bond refunded
    db.close()


def test_settle_alert_fires(env, tmp_path):
    """SettledByAgreement -> alert with the agreed split."""
    cfg = _cfg(env, tmp_path)
    db = _db(cfg)
    job_id, _ = _dispute_as_payer(env)
    sig = env.sign_settle(env.agent, job_id, 700_000_000)
    r = env.send_as(env.payer, lambda: env.escrow.functions.settleByAgreement(
        job_id, 700_000_000, env.deadline_in(86400), sig))
    assert r["status"] == 1, "settleByAgreement failed"
    _scan(env, cfg, db)
    rows = _alerts(db, "settle")
    assert len(rows) == 1
    msg = rows[0][2]
    assert f"Job #{job_id}" in msg
    assert "$700.00" in msg  # to worker
    assert "$300.00" in msg  # to payer
    assert "bond returned to the payer" in msg
    db.close()


def test_credited_alert_fabricated(env, tmp_path):
    """A fabricated Credited event dict -> alert fires (handler path)."""
    cfg = _cfg(env, tmp_path)
    db = _db(cfg)
    ev = AttributeDict({
        "event": "Credited",
        "args": AttributeDict({
            "token": env.token_addr,
            "account": env.agent.address,
            "amount": 123_456,
        }),
        "blockNumber": 42,
        "transactionIndex": 0,
        "logIndex": 0,
    })
    result = mon.handle_event(db, env.escrow, cfg, ev)
    assert result == 42  # Telegram unconfigured -> stored unsent, block returned
    rows = _alerts(db, "credit")
    assert len(rows) == 1
    assert "$0.12" in rows[0][2]  # 123456 units = $0.12
    assert rows[0][3] == 0  # sent=0 (no Telegram configured)
    db.close()


# ---------------------------------------------------------------- telegram send path


def test_config_has_no_token(monkeypatch):
    """The bot token is never read into the monitor config — not even if
    TELEGRAM_BOT_TOKEN is set in the environment. The token lives in the
    Secure Vault; the monitor only ever carries the chat ID."""
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "should-never-be-read")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "8822453816")
    cfg = mon.load_config()
    assert "telegram_bot_token" not in cfg
    assert cfg["telegram_chat_id"] == "8822453816"


def _fake_run(result=None, exc=None):
    """A stub for subprocess.run that records its calls."""
    calls = []

    def fake(argv, **kwargs):
        calls.append((argv, kwargs))
        if exc is not None:
            raise exc
        return result

    fake.calls = calls
    return fake


def test_send_telegram_calls_helper(monkeypatch, tmp_path):
    """send_telegram invokes the connector helper with the chat ID and
    the exact alert text — and nothing else. No token anywhere in the
    call, no shell, 30s timeout."""
    cfg = mon.load_config()
    cfg["telegram_chat_id"] = "8822453816"
    ok = subprocess.CompletedProcess(
        args=[], returncode=0,
        stdout='{"ok": true, "result": {"message_id": 7}}', stderr="")
    fake = _fake_run(result=ok)
    monkeypatch.setattr(mon.subprocess, "run", fake)

    text = "<b>Test alert</b> — Job #0"
    assert mon.send_telegram(cfg, text) is True
    assert len(fake.calls) == 1
    argv, kwargs = fake.calls[0]
    assert argv == [sys.executable, mon.TELEGRAM_HELPER, "8822453816", text]
    assert kwargs["timeout"] == 30
    assert "TELEGRAM_BOT_TOKEN" not in " ".join(argv)
    # The helper path is absolute and points at the connector helper.
    assert argv[1].endswith("custom.telegram/bin/send_message.py")


def test_send_telegram_helper_failure(monkeypatch):
    """A non-zero helper exit (e.g. Telegram refusing the message) is a
    failed send, not a crash — the alert is stored unsent and retried."""
    cfg = mon.load_config()
    cfg["telegram_chat_id"] = "8822453816"
    failed = subprocess.CompletedProcess(
        args=[], returncode=1, stdout="", stderr="Bad Request: chat not found")
    monkeypatch.setattr(mon.subprocess, "run", _fake_run(result=failed))
    assert mon.send_telegram(cfg, "hello") is False


def test_send_telegram_helper_timeout(monkeypatch):
    """A hung helper (30s timeout) returns False instead of stalling
    the monitor loop."""
    cfg = mon.load_config()
    cfg["telegram_chat_id"] = "8822453816"
    exc = subprocess.TimeoutExpired(cmd=["send_message.py"], timeout=30)
    monkeypatch.setattr(mon.subprocess, "run", _fake_run(exc=exc))
    assert mon.send_telegram(cfg, "hello") is False


def test_send_telegram_no_chat_id(monkeypatch):
    """With no chat ID configured, nothing is sent and the helper is
    never invoked — the alert prints and is stored unsent."""
    cfg = mon.load_config()
    cfg["telegram_chat_id"] = ""
    fake = _fake_run(result=subprocess.CompletedProcess(
        args=[], returncode=0, stdout='{"ok": true}', stderr=""))
    monkeypatch.setattr(mon.subprocess, "run", fake)
    assert mon.send_telegram(cfg, "hello") is False
    assert fake.calls == []


# ---------------------------------------------------------------- invariant


def test_invariant_surplus_no_alert(env, tmp_path):
    """A 1-unit donation to the contract (balance > unsettled + bonded +
    pending) must NOT trip the invariant alert — the invariant is >=."""
    cfg = _cfg(env, tmp_path)
    db = _db(cfg)
    job_id = env.create_delivered_job()
    # Donate 1 unit directly to the escrow (surplus, not part of any job)
    env.token.functions.mint(env.escrow_addr, 1).transact({"from": env.funder})
    critical = mon.check_invariant(env.w3, env.escrow, db, cfg)
    assert critical == []
    assert _alerts(db, "invariant") == []
    db.close()


def test_invariant_breach_alerts(monkeypatch, tmp_path):
    """A failing invariant (stubbed) fires a CRITICAL alert whose text
    states the >= expectation, and a recovery clears it so a later
    failure alerts again."""
    cfg = mon.load_config()
    cfg["escrow_address"] = "0x" + "11" * 20
    cfg["db_path"] = str(tmp_path / "monitor.db")
    cfg["telegram_chat_id"] = ""
    db = mon.get_db(cfg["db_path"])

    token = "0x" + "22" * 20

    class _Fn:
        def __init__(self, ret):
            self._ret = ret

        def call(self):
            return self._ret

    class _Fns:
        def __init__(self, ret, token):
            self._ret = ret
            self._token = token

        def settlementInvariant(self, _token):
            return _Fn(self._ret)

        def jobCount(self):
            return _Fn(1)

        def getJob(self, _job_id):
            job = [None] * 15
            job[2] = self._token
            return _Fn(tuple(job))

    class _StubEscrow:
        def __init__(self, ret):
            self.functions = _Fns(ret, token)
            self.events = None

    class _StubEth:
        def get_logs(self, _f):
            return []

    class _StubW3:
        eth = _StubEth()

    # Breach: balance 100 < unsettled 150
    bad = _StubEscrow((100, 150, 0, 0, False))
    critical = mon.check_invariant(_StubW3(), bad, db, cfg)
    assert critical == [token]
    rows = _alerts(db, "invariant")
    assert len(rows) == 1
    assert "CRITICAL" in rows[0][2]
    assert "&gt;=" in rows[0][2]  # the >= expectation, HTML-escaped
    assert "Total bonded: 0" in rows[0][2]

    # Recovery clears the row; a second breach alerts again
    good = _StubEscrow((200, 150, 0, 0, True))
    assert mon.check_invariant(_StubW3(), good, db, cfg) == []
    assert _alerts(db, "invariant") == []
    assert mon.check_invariant(_StubW3(), bad, db, cfg) == [token]
    assert len(_alerts(db, "invariant")) == 1
    db.close()


# ---------------------------------------------------------------- valve warnings


def test_valve_warning_throttle(env, tmp_path, monkeypatch):
    """A disputed job within 12h of the valve warns once; a second check
    in the same 12h does not re-alert; after 12h it warns again. The
    deadline comes from getJob (disputedAt + 72h), never from logs."""
    cfg = _cfg(env, tmp_path)
    db = _db(cfg)
    sent = []
    monkeypatch.setattr(mon, "send_telegram", lambda c, t: sent.append(t) or True)

    job_id, _ = _dispute_as_payer(env)
    env.time_travel(61 * 3600)  # 11h left until the valve opens
    mon.check_valve_warnings(env.w3, env.escrow, db, cfg)
    assert len(sent) == 1
    assert f"Job #{job_id}" in sent[0]
    assert "72h ruling period ends in ~11.0 hours" in sent[0]

    # Second check inside the same 12h: no re-alert
    mon.check_valve_warnings(env.w3, env.escrow, db, cfg)
    assert len(sent) == 1

    # Backdate the recorded alert by 13h: the throttle expires, it warns again
    db.execute(
        "UPDATE alerts SET ts = ts - ? WHERE kind = 'valve-warning'",
        (13 * 3600,))
    db.commit()
    mon.check_valve_warnings(env.w3, env.escrow, db, cfg)
    assert len(sent) == 2
    db.close()


def test_valve_open_alert(env, tmp_path, monkeypatch):
    """Once the 72h period has passed with no ruling, the valve-open
    notice fires (throttled the same way)."""
    cfg = _cfg(env, tmp_path)
    db = _db(cfg)
    sent = []
    monkeypatch.setattr(mon, "send_telegram", lambda c, t: sent.append(t) or True)

    job_id, _ = _dispute_as_payer(env)
    env.time_travel(73 * 3600)
    mon.check_valve_warnings(env.w3, env.escrow, db, cfg)
    assert len(sent) == 1
    assert "valve is open" in sent[0]
    assert f"Job #{job_id}" in sent[0]
    mon.check_valve_warnings(env.w3, env.escrow, db, cfg)
    assert len(sent) == 1
    db.close()


# ---------------------------------------------------------------- run modes


def test_once_placeholder_clean_exit(tmp_path, monkeypatch, capsys):
    """With no ESCROW_ADDRESS and no deployment file, --once exits 0
    and logs that it is waiting for deployment — it does not crash."""
    monkeypatch.delenv("ESCROW_ADDRESS", raising=False)
    monkeypatch.delenv("BOTCHAIN_RPC", raising=False)
    monkeypatch.delenv("RPC_URL", raising=False)
    monkeypatch.setenv("MONITOR_DB", str(tmp_path / "monitor.db"))
    # Point PROJECT_DIR at the empty tmp dir: the real tree now holds
    # botchain-v3-deployment.json (the contract is deployed), so without
    # this the monitor finds a live address and never takes the
    # placeholder path. The placeholder exit is what this test proves.
    monkeypatch.setattr(mon, "PROJECT_DIR", str(tmp_path))
    rc = mon.main(["--once"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "not deployed yet" in out
    assert "Waiting for deployment" in out


def test_run_once_end_to_end(env, tmp_path, monkeypatch):
    """A full run_once pass against the eth-tester chain records the
    dispute alert and advances last_block."""
    cfg = _cfg(env, tmp_path)
    db = _db(cfg)
    monkeypatch.setattr(mon, "get_w3", lambda rpc_url, retries=3: env.w3)
    # Telegram "sends" so the pass advances last_block past the dispute;
    # the unsent-block rule (last_block held back on failed sends) is
    # exercised by the other tests, which run with Telegram unconfigured.
    monkeypatch.setattr(mon, "send_telegram", lambda c, t: True)
    job_id, _ = _dispute_as_payer(env)
    topic_map = mon.event_topic_map(mon.load_abi())
    mon.run_once(cfg, env.w3, env.escrow, db, topic_map)
    rows = _alerts(db, "dispute")
    assert len(rows) == 1
    assert f"Job #{job_id}" in rows[0][2]
    assert int(mon.db_get(db, "last_block")) >= env.w3.eth.block_number
    db.close()
