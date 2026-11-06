#!/usr/bin/env python3
"""V3 executeRuling tests. The operator executes the AI Judge's ruling;
the operator does not decide. Bond follows the ruling: worker >= 50%
-> bond to worker; < 50% -> bond to payer.

R1  Non-operator cannot execute a ruling ("not operator")
R2  Ruling 100% to worker: worker gets job + bond, payer gets 0
R3  Ruling 0% to worker: full refund, state Refunded, bond to payer
R4  Ruling exactly 50%: bond goes to the worker (>= 50%)
R5  Ruling 49%: bond goes to the payer
R6  Ruling above the job amount reverts ("exceeds job amount")
R7  Ruling on a non-disputed job reverts ("not disputed")
R8  Double ruling reverts ("not disputed")
R9  Ruling on an agent-disputed job (no bond): splits job amount only
R10 RulingExecuted event carries amount + bond recipient
R11 Ruling at exactly disputedAt + 72h succeeds (INCLUSIVE boundary)
R12 Ruling at disputedAt + 72h + 1s reverts ("ruling period ended");
    the valve still refunds job + bond in full afterwards
"""
from conftest import (
    AMOUNT, DELIVERED, DISPUTED, REFUNDED, RELEASED, RULING_PERIOD, bond_for,
)


def test_R1_non_operator_cannot_rule(env):
    jid = env.create_disputed_job()
    for acct in (env.payer, env.agent, env.stranger):
        env.assert_reverts(acct,
                           lambda: env.escrow.functions.executeRuling(jid, AMOUNT // 2),
                           "not operator")


def test_R2_ruling_full_to_worker(env):
    jid = env.create_disputed_job()
    bond = bond_for(AMOUNT)
    r = env.send_as(env.operator, lambda: env.escrow.functions.executeRuling(jid, AMOUNT))
    assert r['status'] == 1
    assert env.state(jid) == RELEASED
    assert env.balance(env.agent.address) == AMOUNT + bond
    assert env.balance(env.payer.address) == 0
    ev = env.escrow.events.RulingExecuted().process_receipt(r)
    assert len(ev) == 1
    assert ev[0]['args']['amountToWorker'] == AMOUNT
    assert ev[0]['args']['amountToPayer'] == 0
    assert ev[0]['args']['bondTo'] == env.agent.address


def test_R3_ruling_zero_to_worker(env):
    jid = env.create_disputed_job()
    bond = bond_for(AMOUNT)
    r = env.send_as(env.operator, lambda: env.escrow.functions.executeRuling(jid, 0))
    assert r['status'] == 1
    assert env.state(jid) == REFUNDED
    assert env.balance(env.agent.address) == 0
    assert env.balance(env.payer.address) == AMOUNT + bond
    refunded = env.escrow.events.JobRefunded().process_receipt(r)
    assert len(refunded) == 1
    assert refunded[0]['args']['amount'] == AMOUNT
    ev = env.escrow.events.RulingExecuted().process_receipt(r)
    assert ev[0]['args']['bondTo'] == env.payer.address


def test_R4_ruling_exactly_half_bond_to_worker(env):
    jid = env.create_disputed_job()
    bond = bond_for(AMOUNT)
    r = env.send_as(env.operator, lambda: env.escrow.functions.executeRuling(jid, AMOUNT // 2))
    assert r['status'] == 1
    assert env.state(jid) == RELEASED
    # 50% is >= 50%: bond goes to the worker
    assert env.balance(env.agent.address) == AMOUNT // 2 + bond
    assert env.balance(env.payer.address) == AMOUNT // 2
    ev = env.escrow.events.RulingExecuted().process_receipt(r)
    assert ev[0]['args']['bondTo'] == env.agent.address


def test_R5_ruling_below_half_bond_to_payer(env):
    jid = env.create_disputed_job()
    bond = bond_for(AMOUNT)
    worker_share = AMOUNT * 49 // 100
    r = env.send_as(env.operator, lambda: env.escrow.functions.executeRuling(jid, worker_share))
    assert r['status'] == 1
    assert env.state(jid) == RELEASED
    assert env.balance(env.agent.address) == worker_share
    assert env.balance(env.payer.address) == (AMOUNT - worker_share) + bond
    ev = env.escrow.events.RulingExecuted().process_receipt(r)
    assert ev[0]['args']['bondTo'] == env.payer.address


def test_R6_ruling_exceeds_amount_reverts(env):
    jid = env.create_disputed_job()
    env.assert_reverts(env.operator,
                       lambda: env.escrow.functions.executeRuling(jid, AMOUNT + 1),
                       "exceeds job amount")


def test_R7_ruling_on_non_disputed_reverts(env):
    jid = env.create_delivered_job()
    assert env.state(jid) == DELIVERED
    env.assert_reverts(env.operator,
                       lambda: env.escrow.functions.executeRuling(jid, AMOUNT // 2),
                       "not disputed")


def test_R8_double_ruling_reverts(env):
    jid = env.create_disputed_job()
    r = env.send_as(env.operator, lambda: env.escrow.functions.executeRuling(jid, AMOUNT // 2))
    assert r['status'] == 1
    env.assert_reverts(env.operator,
                       lambda: env.escrow.functions.executeRuling(jid, AMOUNT // 2),
                       "not disputed")


def test_R9_ruling_on_agent_dispute_no_bond(env):
    jid = env.create_disputed_job(by="agent")
    assert env.job(jid)[13] == 0
    worker_share = AMOUNT * 60 // 100
    r = env.send_as(env.operator, lambda: env.escrow.functions.executeRuling(jid, worker_share))
    assert r['status'] == 1
    assert env.state(jid) == RELEASED
    assert env.balance(env.agent.address) == worker_share
    assert env.balance(env.payer.address) == AMOUNT - worker_share


def test_R10_ruling_event_amounts(env):
    jid = env.create_disputed_job()
    worker_share = AMOUNT * 75 // 100
    r = env.send_as(env.operator, lambda: env.escrow.functions.executeRuling(jid, worker_share))
    assert r['status'] == 1
    ev = env.escrow.events.RulingExecuted().process_receipt(r)
    assert len(ev) == 1
    assert ev[0]['args']['jobId'] == jid
    assert ev[0]['args']['amountToWorker'] == worker_share
    assert ev[0]['args']['amountToPayer'] == AMOUNT - worker_share
    # 75% >= 50%: bond to worker
    assert ev[0]['args']['bondTo'] == env.agent.address


def test_R11_ruling_at_exactly_72h_succeeds(env):
    jid = env.create_disputed_job()
    bond = bond_for(AMOUNT)
    disputed_at = env.job(jid)[14]
    # A confirming tx mines one second after the latest block, so travel
    # to one second before the boundary: the ruling tx lands exactly at
    # disputedAt + 72h, and the INCLUSIVE (<=) deadline still allows it.
    env.time_travel_to(disputed_at + RULING_PERIOD - 1)
    r = env.send_as(env.operator, lambda: env.escrow.functions.executeRuling(jid, AMOUNT // 2))
    assert r['status'] == 1
    assert env.state(jid) == RELEASED
    assert env.balance(env.agent.address) == AMOUNT // 2 + bond
    assert env.balance(env.payer.address) == AMOUNT // 2


def test_R12_ruling_after_72h_reverts_valve_still_refunds(env):
    jid = env.create_disputed_job()
    bond = bond_for(AMOUNT)
    disputed_at = env.job(jid)[14]
    env.time_travel_to(disputed_at + RULING_PERIOD + 1)
    env.assert_reverts(env.operator,
                       lambda: env.escrow.functions.executeRuling(jid, AMOUNT // 2),
                       "ruling period ended")
    assert env.state(jid) == DISPUTED
    # The valve is the only way out now: job + bond refund in full.
    r = env.send_as(env.payer, lambda: env.escrow.functions.refundDisputeTimeout(jid))
    assert r['status'] == 1
    assert env.state(jid) == REFUNDED
    assert env.balance(env.agent.address) == 0
    assert env.balance(env.payer.address) == AMOUNT + bond
