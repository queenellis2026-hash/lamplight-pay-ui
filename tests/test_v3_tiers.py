#!/usr/bin/env python3
"""V3 review-window tier tests. Max window by job amount (USD):
under $10 -> 24h; $10-$100 -> 72h; over $100 -> 7 days. Min 1h for all.

T1  Under $10: 24h works, 25h reverts
T2  Under $10: below 1h reverts ("review window too short")
T3  Exactly $10: 72h works, 73h reverts (lands in the $10-$100 tier)
T4  Exactly $100: 72h works, 73h reverts
T5  Over $100 ($101): 7 days works, 7 days + 1h reverts
T6  $1000 job: 7 days works
T7  1h exactly works (minimum bound, inclusive)
"""
from conftest import AMOUNT

HOUR = 3600
DAY = 24 * 3600


def _create(env, amount, window):
    """Create a job with the given amount/window; returns the receipt."""
    env.mint_and_approve(env.payer, amount)
    return env.send_as(env.payer, lambda: env.escrow.functions.createJob(
        env.agent.address, env.token_addr, amount, DAY, window, "tier test"))


def _reverts_too_long(env, amount, window):
    """Attempt a create with a too-long window; must revert on the tier cap.
    Funds the payer first: the max-window check runs after funding, so a
    spent allowance would mask it with 'no allowance'."""
    env.mint_and_approve(env.payer, amount)
    env.assert_reverts(env.payer, lambda: env.escrow.functions.createJob(
        env.agent.address, env.token_addr, amount, DAY, window, "tier test"),
        "review window too long")


def test_T1_under_ten_dollars_24h_max(env):
    r = _create(env, 3_000_000, 24 * HOUR)
    assert r['status'] == 1, "24h window on a $3 job must work"
    _reverts_too_long(env, 3_000_000, 25 * HOUR)


def test_T2_below_one_hour_reverts(env):
    env.assert_reverts(env.payer, lambda: env.escrow.functions.createJob(
        env.agent.address, env.token_addr, 3_000_000, DAY, 3599, "tier test"),
        "review window too short")


def test_T3_exactly_ten_dollars_72h(env):
    r = _create(env, 10_000_000, 72 * HOUR)
    assert r['status'] == 1, "72h window on a $10 job must work ($10 lands in tier 2)"
    _reverts_too_long(env, 10_000_000, 73 * HOUR)


def test_T4_exactly_hundred_dollars_72h(env):
    r = _create(env, 100_000_000, 72 * HOUR)
    assert r['status'] == 1, "72h window on a $100 job must work ($100 lands in tier 2)"
    _reverts_too_long(env, 100_000_000, 73 * HOUR)


def test_T5_over_hundred_dollars_7d(env):
    r = _create(env, 101_000_000, 7 * DAY)
    assert r['status'] == 1, "7-day window on a $101 job must work"
    _reverts_too_long(env, 101_000_000, 7 * DAY + HOUR)


def test_T6_thousand_dollar_job_7d(env):
    r = _create(env, AMOUNT, 7 * DAY)
    assert r['status'] == 1, "7-day window on a $1000 job must work"


def test_T7_one_hour_minimum_works(env):
    r = _create(env, 3_000_000, HOUR)
    assert r['status'] == 1, "1h window (the minimum) must work"
    assert env.escrow.functions.getJob(
        env.escrow.functions.jobCount().call() - 1).call()[5] == HOUR
