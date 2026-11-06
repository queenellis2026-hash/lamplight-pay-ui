#!/usr/bin/env python3
"""V3 mutual-settle tests (settleByAgreement, ported from V23).

S1  Payer calls with the agent's signature -> settles, bond to payer
S2  Agent calls with the payer's signature -> settles, bond to payer
S3  Wrong counterparty signature reverts ("counterparty sig required")
S4  Signature for a different amount reverts
S5  Expired deadline reverts ("settlement signature expired")
S6  Amount 0 -> full refund, state Refunded
S7  Amount full -> full release, state Released
S8  Dust amount works: no dust rule on mutual settle (1 unit settles)
S9  Replay reverts after settling ("not disputed")
S10 Non-party cannot settle ("not a party")
S11 SettledByAgreement event emitted
"""
from conftest import (
    AMOUNT, DISPUTED, REFUNDED, RELEASED, bond_for,
)


def test_S1_payer_settles_with_agent_sig(env):
    jid = env.create_disputed_job()
    bond = bond_for(AMOUNT)
    amount = AMOUNT * 60 // 100
    sig = env.sign_settle(env.agent, jid, amount)
    r = env.send_as(env.payer, lambda: env.escrow.functions.settleByAgreement(
        jid, amount, env.deadline_in(86400), sig))
    assert r['status'] == 1
    assert env.state(jid) == RELEASED
    assert env.balance(env.agent.address) == amount
    # Bond returns to the payer on mutual settle (no ruling to back)
    assert env.balance(env.payer.address) == (AMOUNT - amount) + bond


def test_S2_agent_settles_with_payer_sig(env):
    jid = env.create_disputed_job()
    bond = bond_for(AMOUNT)
    amount = AMOUNT * 40 // 100
    sig = env.sign_settle(env.payer, jid, amount)
    r = env.send_as(env.agent, lambda: env.escrow.functions.settleByAgreement(
        jid, amount, env.deadline_in(86400), sig))
    assert r['status'] == 1
    assert env.state(jid) == RELEASED
    assert env.balance(env.agent.address) == amount
    assert env.balance(env.payer.address) == (AMOUNT - amount) + bond


def test_S3_wrong_counterparty_sig_reverts(env):
    jid = env.create_disputed_job()
    amount = AMOUNT // 2
    sig = env.sign_settle(env.stranger, jid, amount)
    env.assert_reverts(env.payer, lambda: env.escrow.functions.settleByAgreement(
        jid, amount, env.deadline_in(86400), sig), "counterparty sig required")


def test_S4_sig_for_wrong_amount_reverts(env):
    jid = env.create_disputed_job()
    sig = env.sign_settle(env.agent, jid, AMOUNT // 2)
    env.assert_reverts(env.payer, lambda: env.escrow.functions.settleByAgreement(
        jid, AMOUNT * 3 // 4, env.deadline_in(86400), sig), "counterparty sig required")


def test_S5_expired_deadline_reverts(env):
    jid = env.create_disputed_job()
    amount = AMOUNT // 2
    past = env.now() - 1
    sig = env.sign_settle(env.agent, jid, amount, deadline=past)
    env.assert_reverts(env.payer, lambda: env.escrow.functions.settleByAgreement(
        jid, amount, past, sig), "settlement signature expired")


def test_S6_settle_zero_full_refund(env):
    jid = env.create_disputed_job()
    bond = bond_for(AMOUNT)
    sig = env.sign_settle(env.agent, jid, 0)
    r = env.send_as(env.payer, lambda: env.escrow.functions.settleByAgreement(
        jid, 0, env.deadline_in(86400), sig))
    assert r['status'] == 1
    assert env.state(jid) == REFUNDED
    assert env.balance(env.agent.address) == 0
    assert env.balance(env.payer.address) == AMOUNT + bond


def test_S7_settle_full_release(env):
    jid = env.create_disputed_job()
    bond = bond_for(AMOUNT)
    sig = env.sign_settle(env.agent, jid, AMOUNT)
    r = env.send_as(env.payer, lambda: env.escrow.functions.settleByAgreement(
        jid, AMOUNT, env.deadline_in(86400), sig))
    assert r['status'] == 1
    assert env.state(jid) == RELEASED
    assert env.balance(env.agent.address) == AMOUNT
    assert env.balance(env.payer.address) == bond


def test_S8_dust_amount_settles(env):
    """No dust rule on mutual settle: both parties chose it, even 1 unit."""
    jid = env.create_disputed_job()
    sig = env.sign_settle(env.agent, jid, 1)
    r = env.send_as(env.payer, lambda: env.escrow.functions.settleByAgreement(
        jid, 1, env.deadline_in(86400), sig))
    assert r['status'] == 1
    assert env.state(jid) == RELEASED
    assert env.balance(env.agent.address) == 1


def test_S9_replay_reverts(env):
    jid = env.create_disputed_job()
    amount = AMOUNT // 2
    sig = env.sign_settle(env.agent, jid, amount)
    r = env.send_as(env.payer, lambda: env.escrow.functions.settleByAgreement(
        jid, amount, env.deadline_in(86400), sig))
    assert r['status'] == 1
    env.assert_reverts(env.payer, lambda: env.escrow.functions.settleByAgreement(
        jid, amount, env.deadline_in(86400), sig), "not disputed")


def test_S10_non_party_cannot_settle(env):
    jid = env.create_disputed_job()
    amount = AMOUNT // 2
    sig = env.sign_settle(env.agent, jid, amount)
    env.assert_reverts(env.stranger, lambda: env.escrow.functions.settleByAgreement(
        jid, amount, env.deadline_in(86400), sig), "not a party")


def test_S11_settled_event(env):
    jid = env.create_disputed_job()
    amount = AMOUNT * 70 // 100
    sig = env.sign_settle(env.agent, jid, amount)
    r = env.send_as(env.payer, lambda: env.escrow.functions.settleByAgreement(
        jid, amount, env.deadline_in(86400), sig))
    assert r['status'] == 1
    ev = env.escrow.events.SettledByAgreement().process_receipt(r)
    assert len(ev) == 1
    assert ev[0]['args']['jobId'] == jid
    assert ev[0]['args']['amountToWorker'] == amount
    assert ev[0]['args']['amountToPayer'] == AMOUNT - amount
