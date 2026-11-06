#!/usr/bin/env python3
"""V3 releasePartial security tests (carried from V16).

releasePartial(jobId, amountToWorker, deadline, workerSig) requires the
WORKER's EIP-712 signature over
  PartialRelease(uint256 jobId, uint256 amountToWorker, uint256 deadline)
(domain: AgentEscrowV3 / "1"), and dust partials (< 1% of the job amount,
unless the full amount) revert.
  S1  releasePartial(jobId, 0) reverts ("cannot release zero to worker")
  S2  releasePartial after the review window reverts ("review window passed")
  S3  releasePartial with valid amount DURING window works (honest split) —
      now with the worker's signature
  S4  Agent can still claim via release() after the window
  S5  Payer cannot front-run agent claim with releasePartial after window
"""
from conftest import AMOUNT, RELEASED

DUMMY_SIG = b'\x00' * 65


def test_S1_release_partial_zero_reverts(env):
    jid = env.create_delivered_job()
    env.assert_reverts(env.payer,
                       lambda: env.escrow.functions.releasePartial(jid, 0, env.deadline_in(86400), DUMMY_SIG),
                       "cannot release zero to worker")


def test_S3_honest_split_with_worker_sig_works(env):
    jid = env.create_delivered_job()
    half = AMOUNT // 2
    sig = env.sign_partial(env.agent, jid, half)
    r = env.send_as(env.payer,
                    lambda: env.escrow.functions.releasePartial(jid, half, env.deadline_in(86400), sig))
    assert r['status'] == 1, "releasePartial with worker sig failed"
    assert env.state(jid) == RELEASED
    assert env.balance(env.agent.address) == half
    assert env.balance(env.payer.address) == half
    # A second split with the same signature cannot replay (state is Released)
    env.assert_reverts(env.payer,
                       lambda: env.escrow.functions.releasePartial(jid, half, env.deadline_in(86400), sig),
                       "not delivered")


def test_S2_release_partial_after_window_reverts(env):
    jid = env.create_delivered_job(review_window=3600)
    env.time_travel(3601)
    half = AMOUNT // 2
    sig = env.sign_partial(env.agent, jid, half)
    env.assert_reverts(env.payer,
                       lambda: env.escrow.functions.releasePartial(jid, half, env.deadline_in(86400), sig),
                       "review window passed")


def test_S4_agent_claim_via_release_after_window(env):
    jid = env.create_delivered_job(review_window=3600)
    env.time_travel(3601)
    r = env.send_as(env.agent, lambda: env.escrow.functions.release(jid))
    assert r['status'] == 1
    assert env.state(jid) == RELEASED
    assert env.balance(env.agent.address) == AMOUNT


def test_S5_payer_front_run_after_window_reverts_agent_claim_works(env):
    jid = env.create_delivered_job(review_window=3600)
    env.time_travel(3601)
    half = AMOUNT // 2
    sig = env.sign_partial(env.agent, jid, half)
    env.assert_reverts(env.payer,
                       lambda: env.escrow.functions.releasePartial(jid, half, env.deadline_in(86400), sig),
                       "review window passed")
    # Agent claim still works after the failed front-run
    r = env.send_as(env.agent, lambda: env.escrow.functions.release(jid))
    assert r['status'] == 1
    assert env.state(jid) == RELEASED
    assert env.balance(env.agent.address) == AMOUNT
