#!/usr/bin/env python3
"""V3 dispute-bond tests. Bond = 20% of the job amount, min $1, max $50
(6-decimal token units: $1 = 1,000,000; $50 = 50,000,000).

B1  $3 job -> 20% is $0.60, min binds -> $1 bond
B2  $10 job -> 20% is $2 -> $2 bond
B3  $100 job -> 20% is $20 -> $20 bond
B4  $250 job -> 20% is $50 -> $50 bond (max binds exactly)
B5  $1000 job -> 20% is $200, max caps -> $50 bond
B6  Payer without bond approval cannot dispute ("no allowance")
B7  Non-party cannot dispute ("not a party")
B8  Agent-raised dispute posts no bond (bondAmount 0, no BondPosted)
B9  Dispute after the review window reverts ("review window ended")
B10 Bond is counted in the settlement invariant (bonded sum)
"""
from conftest import AMOUNT, DISPUTED, bond_for

DAY = 24 * 3600


def test_B1_small_job_min_bond(env):
    amount = 3_000_000  # $3
    jid = env.create_disputed_job(review_window=DAY, amount=amount)
    job = env.job(jid)
    assert job[13] == 1_000_000, f"expected $1 min bond, got {job[13]}"
    assert env.state(jid) == DISPUTED
    # Payer paid job + bond; escrow holds both
    assert env.balance(env.payer.address) == 0
    assert env.escrow.functions.settlementInvariant(env.token_addr).call()[0] == amount + 1_000_000


def test_B2_ten_dollar_job_bond(env):
    amount = 10_000_000  # $10
    jid = env.create_disputed_job(review_window=48 * 3600, amount=amount)
    assert env.job(jid)[13] == 2_000_000


def test_B3_hundred_dollar_job_bond(env):
    amount = 100_000_000  # $100
    jid = env.create_disputed_job(review_window=48 * 3600, amount=amount)
    assert env.job(jid)[13] == 20_000_000


def test_B4_max_bond_exact(env):
    amount = 250_000_000  # $250 -> 20% is exactly $50
    jid = env.create_disputed_job(review_window=48 * 3600, amount=amount)
    assert env.job(jid)[13] == 50_000_000


def test_B5_large_job_bond_capped(env):
    jid = env.create_disputed_job(amount=AMOUNT)  # $1000 -> 20% is $200, capped at $50
    assert env.job(jid)[13] == 50_000_000
    assert bond_for(AMOUNT) == 50_000_000


def test_B6_no_bond_approval_reverts(env):
    jid = env.create_delivered_job()
    # Payer approved only the job amount at creation; no bond approval left.
    # The bond pull is a low-level transferFrom, so the token's inner
    # "no allowance" is swallowed and the call reverts "funding failed".
    env.assert_reverts(env.payer,
                       lambda: env.escrow.functions.raiseDispute(jid, "reason"),
                       "funding failed")
    assert env.state(jid) != DISPUTED


def test_B7_non_party_cannot_dispute(env):
    jid = env.create_delivered_job()
    env.assert_reverts(env.stranger,
                       lambda: env.escrow.functions.raiseDispute(jid, "reason"),
                       "not a party")


def test_B8_agent_dispute_no_bond(env):
    jid = env.create_disputed_job(by="agent")
    job = env.job(jid)
    assert env.state(jid) == DISPUTED
    assert job[13] == 0, "agent dispute must post no bond"
    assert job[14] != 0, "disputedAt not set"
    # Payer still holds everything (only the job amount left the payer)
    assert env.balance(env.payer.address) == 0  # job amount funded
    assert env.balance(env.agent.address) == 0


def test_B9_dispute_after_window_reverts(env):
    jid = env.create_delivered_job(review_window=3600)
    env.time_travel(3601)
    env.assert_reverts(env.payer,
                       lambda: env.escrow.functions.raiseDispute(jid, "too late"),
                       "review window ended")


def test_B10_bond_in_invariant(env):
    jid = env.create_disputed_job()
    bal, unsettled, bonded, pending, holds = env.escrow.functions.settlementInvariant(
        env.token_addr).call()
    assert holds
    assert unsettled == AMOUNT
    assert bonded == bond_for(AMOUNT)
    assert pending == 0
    assert bal == AMOUNT + bond_for(AMOUNT)
    # totalBonded view agrees
    assert env.escrow.functions.totalBonded(env.token_addr).call() == bond_for(AMOUNT)
