#!/usr/bin/env python3
"""V3 misc tests (carried from V16, arbiter tests removed).

V3  Expired split signature reverts ("split signature expired")
V5  disputeReason over 10 KB reverts (raiseDispute + submitDeliveryAndDispute)
V6  raiseDispute stores the reason on-chain
V7  Split signature submitted with a different deadline reverts
"""
from conftest import AMOUNT, DISPUTED, REVIEW_WINDOW


# ---- V3: expired split signature reverts ----------------------------------
def test_V3_expired_split_signature_reverts(env):
    jid = env.create_delivered_job()
    half = AMOUNT // 2
    past_deadline = env.now() - 1
    sig = env.sign_partial(env.agent, jid, half, deadline=past_deadline)
    env.assert_reverts(env.payer,
                       lambda: env.escrow.functions.releasePartial(jid, half, past_deadline, sig),
                       "split signature expired")


# ---- V5: disputeReason length cap ------------------------------------------
def test_V5a_raise_dispute_reason_too_long_reverts(env):
    jid = env.create_delivered_job()
    long_reason = "x" * 10241
    env.assert_reverts(env.payer,
                       lambda: env.escrow.functions.raiseDispute(jid, long_reason),
                       "dispute reason too long")


def test_V5b_atomic_dispute_reason_too_long_reverts(env):
    job_id = env.create_job(env.agent.address)
    r = env.send_as(env.agent, lambda: env.escrow.functions.acceptJob(job_id))
    assert r['status'] == 1
    dh = env.w3.keccak(text="delivery")
    long_reason = "y" * 10241
    env.assert_reverts(env.agent, lambda: env.escrow.functions.submitDeliveryAndDispute(
        job_id, dh, "delivery text", long_reason), "dispute reason too long")


def test_V5c_reason_at_exactly_10kb_works(env):
    jid = env.create_delivered_job()
    ok_reason = "z" * 10240
    # A 10 KB calldata string needs a high gas limit (calldata + SSTORE).
    # Payer must have approved the bond too: raiseDispute pulls it.
    from conftest import bond_for
    bond = bond_for(AMOUNT)
    env.mint_and_approve(env.payer, bond, approve=bond)
    r = env.send_as(env.payer, lambda: env.escrow.functions.raiseDispute(jid, ok_reason),
                    gas=8000000)
    assert r['status'] == 1
    assert env.state(jid) == DISPUTED


# ---- V6: raiseDispute stores reason on-chain -------------------------------
def test_V6_raise_dispute_stores_reason_on_chain(env):
    jid = env.create_delivered_job()
    from conftest import bond_for
    bond = bond_for(AMOUNT)
    env.mint_and_approve(env.payer, bond, approve=bond)
    r = env.send_as(env.payer,
                    lambda: env.escrow.functions.raiseDispute(jid, "work was garbage"))
    assert r['status'] == 1
    job = env.job(jid)
    assert env.state(jid) == DISPUTED
    assert job[12] == "work was garbage"


# ---- V7: split signature with mismatched deadline reverts ------------------
def test_V7_split_sig_wrong_deadline_reverts(env):
    jid = env.create_delivered_job()
    half = AMOUNT // 2
    deadline_a = env.deadline_in(3600)
    deadline_b = env.deadline_in(7200)
    sig = env.sign_partial(env.agent, jid, half, deadline=deadline_a)
    env.assert_reverts(env.payer,
                       lambda: env.escrow.functions.releasePartial(jid, half, deadline_b, sig),
                       "worker sig required")
