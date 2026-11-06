#!/usr/bin/env python3
"""V3 split / signature tests (carried from V16, updated).

N1  Worker signature required for releasePartial
N2  Dust rejection (< 1% of job amount, unless full amount)
N3  Atomic deliver+dispute (submitDeliveryAndDispute)

V3 changes: PartialRelease is now (jobId, amountToWorker, deadline) —
the per-job nonce is gone. Replay protection is the Delivered ->
Released state transition: a captured signature cannot replay because
a second split reverts on "not delivered". N1e now proves that.
"""
from conftest import (
    AMOUNT, DELIVERED, DISPUTED, RELEASED, REVIEW_WINDOW,
)

DUMMY_SIG = b'\x00' * 65


# ---- N1: worker signature required --------------------------------------
def test_N1a_empty_sig_reverts(env):
    jid = env.create_delivered_job()
    env.assert_reverts(env.payer,
                       lambda: env.escrow.functions.releasePartial(jid, AMOUNT // 2, env.deadline_in(86400), b''),
                       "bad sig length")


def test_N1b_payer_sig_reverts(env):
    """The payer signing the split themselves is not the worker's consent."""
    jid = env.create_delivered_job()
    half = AMOUNT // 2
    sig = env.sign_partial(env.payer, jid, half)
    env.assert_reverts(env.payer,
                       lambda: env.escrow.functions.releasePartial(jid, half, env.deadline_in(86400), sig),
                       "worker sig required")


def test_N1c_worker_sig_for_wrong_amount_reverts(env):
    """Worker signed for half; payer submits for three-quarters."""
    jid = env.create_delivered_job()
    half = AMOUNT // 2
    three_quarters = (AMOUNT * 3) // 4
    sig = env.sign_partial(env.agent, jid, half)
    env.assert_reverts(env.payer,
                       lambda: env.escrow.functions.releasePartial(jid, three_quarters, env.deadline_in(86400), sig),
                       "worker sig required")


def test_N1d_stranger_sig_reverts(env):
    jid = env.create_delivered_job()
    half = AMOUNT // 2
    sig = env.sign_partial(env.stranger, jid, half)
    env.assert_reverts(env.payer,
                       lambda: env.escrow.functions.releasePartial(jid, half, env.deadline_in(86400), sig),
                       "worker sig required")


def test_N1e_replayed_worker_sig_reverts(env):
    """A worker signature is single-use: after a successful split the job
    is Released, so the same signature cannot replay (reverts "not delivered")."""
    jid = env.create_delivered_job()
    half = AMOUNT // 2
    sig = env.sign_partial(env.agent, jid, half)
    r = env.send_as(env.payer,
                    lambda: env.escrow.functions.releasePartial(jid, half, env.deadline_in(86400), sig))
    assert r['status'] == 1
    assert env.state(jid) == RELEASED
    env.assert_reverts(env.payer,
                       lambda: env.escrow.functions.releasePartial(jid, half, env.deadline_in(86400), sig),
                       "not delivered")


# ---- N2: dust rejection --------------------------------------------------
def test_N2a_one_wei_partial_reverts(env):
    jid = env.create_delivered_job()
    sig = env.sign_partial(env.agent, jid, 1)
    env.assert_reverts(env.payer,
                       lambda: env.escrow.functions.releasePartial(jid, 1, env.deadline_in(86400), sig),
                       "dust partial rejected")


def test_N2b_just_below_one_percent_reverts(env):
    one_percent = AMOUNT // 100
    jid = env.create_delivered_job()
    sig = env.sign_partial(env.agent, jid, one_percent - 1)
    env.assert_reverts(env.payer,
                       lambda: env.escrow.functions.releasePartial(jid, one_percent - 1, env.deadline_in(86400), sig),
                       "dust partial rejected")


def test_N2c_exactly_one_percent_works(env):
    one_percent = AMOUNT // 100
    jid = env.create_delivered_job()
    sig = env.sign_partial(env.agent, jid, one_percent)
    r = env.send_as(env.payer,
                    lambda: env.escrow.functions.releasePartial(jid, one_percent, env.deadline_in(86400), sig))
    assert r['status'] == 1
    assert env.state(jid) == RELEASED
    assert env.balance(env.agent.address) == one_percent
    assert env.balance(env.payer.address) == AMOUNT - one_percent


# ---- N3: atomic deliver+dispute -----------------------------------------
def test_N3_atomic_deliver_and_dispute(env):
    job_id = env.create_job(env.agent.address)
    r = env.send_as(env.agent, lambda: env.escrow.functions.acceptJob(job_id))
    assert r['status'] == 1
    dh = env.w3.keccak(text=f"delivery-{job_id}")
    r = env.send_as(env.agent, lambda: env.escrow.functions.submitDeliveryAndDispute(
        job_id, dh, "delivered work package", "payer ghosted me"))
    assert r['status'] == 1
    job = env.job(job_id)
    assert env.state(job_id) == DISPUTED
    assert job[9] != 0, "deliveredAt not set"          # deliveredAt
    assert job[11] == "delivered work package"         # deliveryText
    assert job[12] == "payer ghosted me"               # disputeReason
    assert job[13] == 0, "agent dispute posts no bond"  # bondAmount
    assert job[14] != 0, "disputedAt not set"           # disputedAt
    # DisputeRaised event emitted, no BondPosted event
    events = env.escrow.events.DisputeRaised().process_receipt(r)
    assert len(events) == 1 and events[0]['args']['jobId'] == job_id
    bonds = env.escrow.events.BondPosted().process_receipt(r)
    assert len(bonds) == 0
    # Payer can no longer releasePartial: job skipped Delivered entirely
    half = AMOUNT // 2
    sig = env.sign_partial(env.agent, job_id, half)
    env.assert_reverts(env.payer,
                       lambda: env.escrow.functions.releasePartial(job_id, half, env.deadline_in(86400), sig),
                       "not delivered")


def test_N3b_atomic_dispute_requires_accepted_job(env):
    """submitDeliveryAndDispute on a merely-Created job reverts."""
    job_id = env.create_job(env.agent.address)
    dh = env.w3.keccak(text="delivery")
    env.assert_reverts(env.agent, lambda: env.escrow.functions.submitDeliveryAndDispute(
        job_id, dh, "text", "reason"), "not accepted")
