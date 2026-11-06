#!/usr/bin/env python3
"""V3 72-hour timeout-valve tests (refundDisputeTimeout).

V1  Before 72h from the dispute, the valve reverts
V2  After 72h, job amount + bond refund to the payer in full
V3  Anyone may call it (stranger included)
V4  Cannot run after a ruling executed ("not disputed")
V5  Agent-disputed job (no bond): valve refunds the job amount only
V6  Boundary: exactly at disputedAt + 72h reverts (STRICT); +1s works
"""
from conftest import AMOUNT, REFUNDED, RULING_PERIOD, bond_for


def _past_valve(env, job_id):
    disputed_at = env.job(job_id)[14]
    env.time_travel_to(disputed_at + RULING_PERIOD + 1)


def test_V1_valve_before_72h_reverts(env):
    jid = env.create_disputed_job()
    env.assert_reverts(env.payer,
                       lambda: env.escrow.functions.refundDisputeTimeout(jid),
                       "ruling period not ended")
    # Even 72h minus one second is too early
    disputed_at = env.job(jid)[14]
    env.time_travel_to(disputed_at + RULING_PERIOD - 1)
    env.assert_reverts(env.payer,
                       lambda: env.escrow.functions.refundDisputeTimeout(jid),
                       "ruling period not ended")


def test_V2_valve_refunds_job_and_bond(env):
    jid = env.create_disputed_job()
    bond = bond_for(AMOUNT)
    _past_valve(env, jid)
    r = env.send_as(env.payer, lambda: env.escrow.functions.refundDisputeTimeout(jid))
    assert r['status'] == 1
    assert env.state(jid) == REFUNDED
    assert env.balance(env.agent.address) == 0
    assert env.balance(env.payer.address) == AMOUNT + bond
    ev = env.escrow.events.DisputeTimeoutRefunded().process_receipt(r)
    assert len(ev) == 1
    assert ev[0]['args']['jobId'] == jid
    assert ev[0]['args']['amount'] == AMOUNT
    assert ev[0]['args']['bond'] == bond


def test_V3_valve_callable_by_anyone(env):
    jid = env.create_disputed_job()
    _past_valve(env, jid)
    r = env.send_as(env.stranger, lambda: env.escrow.functions.refundDisputeTimeout(jid))
    assert r['status'] == 1
    assert env.state(jid) == REFUNDED
    assert env.balance(env.payer.address) == AMOUNT + bond_for(AMOUNT)


def test_V4_valve_after_ruling_reverts(env):
    jid = env.create_disputed_job()
    r = env.send_as(env.operator, lambda: env.escrow.functions.executeRuling(jid, AMOUNT // 2))
    assert r['status'] == 1
    _past_valve(env, jid)
    env.assert_reverts(env.payer,
                       lambda: env.escrow.functions.refundDisputeTimeout(jid),
                       "not disputed")


def test_V5_valve_agent_dispute_no_bond(env):
    jid = env.create_disputed_job(by="agent")
    assert env.job(jid)[13] == 0
    _past_valve(env, jid)
    r = env.send_as(env.payer, lambda: env.escrow.functions.refundDisputeTimeout(jid))
    assert r['status'] == 1
    assert env.state(jid) == REFUNDED
    assert env.balance(env.payer.address) == AMOUNT
    ev = env.escrow.events.DisputeTimeoutRefunded().process_receipt(r)
    assert ev[0]['args']['bond'] == 0


def test_V6_valve_boundary_strict(env):
    jid = env.create_disputed_job()
    disputed_at = env.job(jid)[14]
    env.time_travel_to(disputed_at + RULING_PERIOD)
    # Exactly at the boundary: still too early (STRICT >). Call-only
    # check: a confirming tx would mine one second later, past the gate.
    env.assert_call_reverts(env.payer,
                            lambda: env.escrow.functions.refundDisputeTimeout(jid),
                            "ruling period not ended")
    env.time_travel(1)
    r = env.send_as(env.payer, lambda: env.escrow.functions.refundDisputeTimeout(jid))
    assert r['status'] == 1
    assert env.state(jid) == REFUNDED
