#!/usr/bin/env python3
"""V3 core escrow tests: happy path, cancel paths, deadline refund,
settlement invariant, and claim windows.

C1  Payer releases after delivery -> agent paid in full
C2  Agent claims via release() after the review window
C3  Payer cancels a Created job -> funds return at once
C4  (removed) cancelUnaccepted was byte-identical to cancel; deleted.
    Covered by C3.
C5  cancel() on an Accepted job past its deadline refunds (ghosted
    agent exit, folded in from refundAfterDeadline)
C6  cancel() boundary: Accepted before the deadline reverts
    "deadline not passed"; the job is untouched and cancel works
    once the deadline passes
C7  Open job: a stranger may accept and becomes the agent; the payer
    may not accept their own open job
C8  Settlement invariant holds (balance >= unsettled + bonded + pending)
    across create / dispute / ruling
C9  Windows computed from getJob (claimWindows / jobWindows removed):
    agent claim time and ruling timeout
"""
from conftest import (
    ACCEPTED, AMOUNT, CANCELLED, CREATED, DEADLINE_SECONDS, DISPUTED,
    REFUNDED, RELEASED, REVIEW_WINDOW, RULING_PERIOD,
)


def test_C1_payer_release_after_delivery(env):
    jid = env.create_delivered_job()
    r = env.send_as(env.payer, lambda: env.escrow.functions.release(jid))
    assert r['status'] == 1
    assert env.state(jid) == RELEASED
    assert env.balance(env.agent.address) == AMOUNT
    assert env.balance(env.payer.address) == 0
    released = env.escrow.events.JobReleased().process_receipt(r)
    assert len(released) == 1
    assert released[0]['args']['amount'] == AMOUNT


def test_C2_agent_claim_after_window(env):
    jid = env.create_delivered_job(review_window=3600)
    env.time_travel(3601)
    r = env.send_as(env.agent, lambda: env.escrow.functions.release(jid))
    assert r['status'] == 1
    assert env.state(jid) == RELEASED
    assert env.balance(env.agent.address) == AMOUNT


def test_C3_cancel_before_accept(env):
    jid = env.create_job(env.agent.address)
    r = env.send_as(env.payer, lambda: env.escrow.functions.cancel(jid))
    assert r['status'] == 1
    assert env.state(jid) == CANCELLED
    assert env.balance(env.payer.address) == AMOUNT


def test_C5_cancel_after_deadline_accepted(env):
    """Merged cancel: an Accepted job past its deadline refunds —
    the ghosted-agent exit, folded in from refundAfterDeadline."""
    jid = env.create_job(env.agent.address)
    r = env.send_as(env.agent, lambda: env.escrow.functions.acceptJob(jid))
    assert r['status'] == 1
    assert env.state(jid) == ACCEPTED
    # Before the deadline, cancel reverts
    env.assert_reverts(env.payer,
                       lambda: env.escrow.functions.cancel(jid),
                       "deadline not passed")
    env.time_travel(DEADLINE_SECONDS + 1)
    r = env.send_as(env.payer, lambda: env.escrow.functions.cancel(jid))
    assert r['status'] == 1
    assert env.state(jid) == REFUNDED
    assert env.balance(env.payer.address) == AMOUNT
    refunded = env.escrow.events.JobRefunded().process_receipt(r)
    assert len(refunded) == 1
    assert refunded[0]['args']['amount'] == AMOUNT


def test_C6_cancel_accepted_before_deadline_reverts(env):
    """Merged cancel boundary: Accepted before the deadline reverts
    "deadline not passed"; the job is untouched and cancel works once
    the deadline passes."""
    jid = env.create_job(env.agent.address)
    r = env.send_as(env.agent, lambda: env.escrow.functions.acceptJob(jid))
    assert r['status'] == 1
    assert env.state(jid) == ACCEPTED
    env.assert_reverts(env.payer,
                       lambda: env.escrow.functions.cancel(jid),
                       "deadline not passed")
    assert env.state(jid) == ACCEPTED
    env.time_travel(DEADLINE_SECONDS + 1)
    r = env.send_as(env.payer, lambda: env.escrow.functions.cancel(jid))
    assert r['status'] == 1
    assert env.state(jid) == REFUNDED


def test_C7_open_job_accept(env):
    jid = env.create_job(agent_addr=None)
    # The payer cannot accept their own open job
    env.assert_reverts(env.payer,
                       lambda: env.escrow.functions.acceptJob(jid),
                       "payer cannot be agent")
    r = env.send_as(env.stranger, lambda: env.escrow.functions.acceptJob(jid))
    assert r['status'] == 1
    assert env.job(jid)[1] == env.stranger.address
    assert env.state(jid) == ACCEPTED


def test_C8_settlement_invariant_holds(env):
    def check():
        bal, unsettled, bonded, pending, holds = env.escrow.functions.settlementInvariant(
            env.token_addr).call()
        assert holds, f"invariant broken: {bal} < {unsettled} + {bonded} + {pending}"
        return bal, unsettled, bonded, pending

    check()  # empty escrow
    jid = env.create_disputed_job()
    bal, unsettled, bonded, pending = check()
    assert unsettled == AMOUNT
    from conftest import bond_for
    assert bonded == bond_for(AMOUNT)
    assert bal == AMOUNT + bond_for(AMOUNT)
    # Ruling settles everything: invariant still holds, sums zero
    r = env.send_as(env.operator, lambda: env.escrow.functions.executeRuling(jid, AMOUNT // 2))
    assert r['status'] == 1
    bal, unsettled, bonded, pending = check()
    assert unsettled == 0 and bonded == 0 and pending == 0 and bal == 0


def test_C9_windows_from_get_job(env):
    """Windows computed from getJob fields (claimWindows / jobWindows
    were removed as redundant views): agent claim time is
    deliveredAt + reviewWindow; the ruling timeout is disputedAt +
    72h once disputed, else window end + 72h."""
    jid = env.create_delivered_job(review_window=REVIEW_WINDOW)
    job = env.job(jid)
    delivered_at, review_window = job[9], job[5]
    agent_claim_at = delivered_at + review_window
    # Not disputed: latest possible timeout = window end + 72h
    dispute_timeout_at = agent_claim_at + RULING_PERIOD
    assert delivered_at != 0
    # After a dispute, the timeout is disputedAt + 72h
    from conftest import bond_for
    env.mint_and_approve(env.payer, bond_for(AMOUNT), approve=bond_for(AMOUNT))
    r = env.send_as(env.payer, lambda: env.escrow.functions.raiseDispute(jid, "reason"))
    assert r['status'] == 1
    job = env.job(jid)
    disputed_at = job[14]
    assert env.state(jid) == DISPUTED
    # Dispute raised inside the window, so disputedAt <= window end and
    # the disputed timeout is no later than the undisputed one.
    assert disputed_at <= delivered_at + review_window
    assert disputed_at + RULING_PERIOD <= dispute_timeout_at
