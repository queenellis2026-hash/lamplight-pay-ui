#!/usr/bin/env python3
"""Phase 2: Idempotency & Replay Resistance for AgentEscrowV3.

Question: can any on-chain action be replayed, duplicated, or reentered
to steal funds or corrupt state?

Adapted from the V9 Phase 2 suite (test_v9_phase2_replay.py). V9's
arbiter panel is gone; V3's new replay targets are executeRuling,
settleByAgreement, the dispute bond, and the 72h refund valve.

Test groups:
  T1  Double-spend: every state-changing fn called twice; 2nd must revert
      (setTokenAllowed is the exception: idempotent by design, 2nd succeeds)
  T2  Double-spend combinations: funds can't exit twice through ANY pair
      of paths (release + ruling, ruling + valve, settle + ruling, ...)
  T3  Reentrancy: malicious token tries to reenter during payouts
  T4  Front-running: races for open jobs, and the atomic dispute window
  T5  Invalid transitions: every fn from every wrong state must revert
  T6  Partial payment edge cases: 0, full, over-amount, double-partial

NOT covered here (honest gap): withdraw() replay. A pending credit only
exists when a payout leg fails, which needs a failing token — that is
Phase 3 (hostile tokens) territory. withdraw() zeroes the credit before
transferring, so the replay protection is structural; Phase 3 will
prove it with a real failing token.
"""
import pytest
import solcx
from eth_account import Account
from conftest import (
    AMOUNT, BOND_MIN, CREATED, ACCEPTED, DELIVERED, DISPUTED, RELEASED,
    REFUNDED, CANCELLED, DEADLINE_SECONDS, REVIEW_WINDOW, RULING_PERIOD,
    bond_for,
)

DH = b"\x11" * 32  # dummy delivery hash


# ---------------------------------------------------------------- helpers

def _balances(env):
    """(payer, agent, escrow) MockToken balances."""
    return (
        env.balance(env.payer.address),
        env.balance(env.agent.address),
        env.balance(env.escrow_addr),
    )


def _assert_invariant(env, token=None):
    token = token or env.token_addr
    bal, unsettled, bonded, pending, holds = (
        env.escrow.functions.settlementInvariant(token).call())
    assert holds, (
        f"invariant broken: bal={bal} unsettled={unsettled} "
        f"bonded={bonded} pending={pending}")
    return bal, unsettled, bonded, pending


def _past_valve(env, job_id):
    disputed_at = env.job(job_id)[14]
    env.time_travel_to(disputed_at + RULING_PERIOD + 1)


def _past_review(env, job_id):
    job = env.job(job_id)
    env.time_travel_to(job[9] + job[5] + 1)  # deliveredAt + reviewWindow + 1


def _past_deadline(env, job_id):
    job = env.job(job_id)
    env.time_travel_to(job[4] + 1)  # deadline + 1


def _new_account(env):
    acct = Account.create()
    env.w3.eth.send_transaction({
        'from': env.funder, 'to': acct.address,
        'value': env.w3.to_wei(10, 'ether'), 'gas': 21000,
    })
    return acct


def _job_created(env, amount=AMOUNT):
    return env.create_job(env.agent.address, amount=amount)


def _job_accepted(env, amount=AMOUNT):
    jid = env.create_job(env.agent.address, amount=amount)
    r = env.send_as(env.agent, lambda: env.escrow.functions.acceptJob(jid))
    assert r['status'] == 1
    return jid


def _job_released(env, amount=AMOUNT):
    jid = env.create_delivered_job(amount=amount)
    r = env.send_as(env.payer, lambda: env.escrow.functions.release(jid))
    assert r['status'] == 1
    return jid


def _job_refunded_by_ruling(env, amount=AMOUNT):
    jid = env.create_disputed_job(amount=amount)
    r = env.send_as(env.operator,
                    lambda: env.escrow.functions.executeRuling(jid, 0))
    assert r['status'] == 1
    return jid


def _job_cancelled(env, amount=AMOUNT):
    jid = env.create_job(env.agent.address, amount=amount)
    r = env.send_as(env.payer, lambda: env.escrow.functions.cancel(jid))
    assert r['status'] == 1
    return jid


def _settle(env, jid, amount, caller, counterparty):
    """Mutual settle with a fresh signature; returns the receipt."""
    dl = env.deadline_in(86400)
    sig = env.sign_settle(counterparty, jid, amount, dl)
    r = env.send_as(caller, lambda: env.escrow.functions.settleByAgreement(
        jid, amount, dl, sig))
    assert r['status'] == 1, "settleByAgreement failed"
    return r


# ---------------------------------------------------------------- evil token

REENTRANT_TOKEN_SRC = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
interface IEscrowV3 {
    function release(uint256 jobId) external;
    function releasePartial(uint256 jobId, uint256 amt, uint256 deadline, bytes calldata sig) external;
    function executeRuling(uint256 jobId, uint256 amt) external;
    function refundDisputeTimeout(uint256 jobId) external;
    function settleByAgreement(uint256 jobId, uint256 amt, uint256 deadline, bytes calldata sig) external;
    function cancel(uint256 jobId) external;
    function withdraw(address token) external;
}
contract ReentrantToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint8 public decimals = 6;
    address public escrow;
    uint256 public targetJob;
    bool public attackArmed;
    uint256 public reenterCount;
    uint256 public breachCount;
    function setEscrow(address e) external { escrow = e; }
    function arm(uint256 jobId) external { attackArmed = true; targetJob = jobId; }
    function mint(address to, uint256 amt) external { balanceOf[to] += amt; }
    function approve(address spender, uint256 amt) external returns (bool) {
        allowance[msg.sender][spender] = amt;
        return true;
    }
    function transfer(address to, uint256 amt) external returns (bool) {
        require(balanceOf[msg.sender] >= amt, "insufficient");
        balanceOf[msg.sender] -= amt;
        balanceOf[to] += amt;
        // ATTACK: reenter the escrow mid-payout, every money-moving fn.
        // breachCount only rises if an inner call SUCCEEDS.
        if (attackArmed && reenterCount == 0) {
            reenterCount += 1;
            attackArmed = false;
            try IEscrowV3(escrow).release(targetJob) { breachCount += 1; } catch { }
            try IEscrowV3(escrow).releasePartial(targetJob, 1, block.timestamp + 3600, "") { breachCount += 1; } catch { }
            try IEscrowV3(escrow).executeRuling(targetJob, 1) { breachCount += 1; } catch { }
            try IEscrowV3(escrow).refundDisputeTimeout(targetJob) { breachCount += 1; } catch { }
            try IEscrowV3(escrow).settleByAgreement(targetJob, 1, block.timestamp + 3600, "") { breachCount += 1; } catch { }
            try IEscrowV3(escrow).cancel(targetJob) { breachCount += 1; } catch { }
            try IEscrowV3(escrow).withdraw(address(this)) { breachCount += 1; } catch { }
        }
        return true;
    }
    function transferFrom(address from, address to, uint256 amt) external returns (bool) {
        require(balanceOf[from] >= amt, "insufficient");
        require(allowance[from][msg.sender] >= amt, "no allowance");
        allowance[from][msg.sender] -= amt;
        balanceOf[from] -= amt;
        balanceOf[to] += amt;
        return true;
    }
}
"""


def _compile_evil():
    out = solcx.compile_source(
        REENTRANT_TOKEN_SRC, output_values=["abi", "bin"], solc_version="0.8.24",
        optimize=True, optimize_runs=200,
    )
    key = [k for k in out if "ReentrantToken" in k][0]
    return out[key]["abi"], out[key]["bin"]


def _evil_env(env):
    """Deploy the malicious token, whitelist it, return it."""
    evil_abi, evil_bin = _compile_evil()
    c = env.w3.eth.contract(abi=evil_abi, bytecode=evil_bin)
    txh = c.constructor().transact({'from': env.funder, 'gas': 3000000})
    rcpt = env.w3.eth.wait_for_transaction_receipt(txh)
    evil = env.w3.eth.contract(address=rcpt.contractAddress, abi=evil_abi)
    evil.functions.setEscrow(env.escrow_addr).transact({'from': env.funder})
    r = env.send_as(env.operator,
                    lambda: env.escrow.functions.setTokenAllowed(evil.address, True))
    assert r['status'] == 1, "evil token whitelist failed"
    return evil


def _fund_evil(env, evil, acct, amount, approve=None):
    evil.functions.mint(acct.address, amount).transact({'from': env.funder})
    env.send_as(acct, lambda: evil.functions.approve(
        env.escrow_addr, amount if approve is None else approve))


def _evil_job(env, evil, amount=AMOUNT, review_window=REVIEW_WINDOW):
    """Create a job funded in the evil token. Returns jobId."""
    _fund_evil(env, evil, env.payer, amount)
    r = env.send_as(env.payer, lambda: env.escrow.functions.createJob(
        env.agent.address, evil.address, amount, DEADLINE_SECONDS,
        review_window, "evil job"))
    assert r['status'] == 1, "evil createJob failed"
    return env.escrow.functions.jobCount().call() - 1


def _evil_delivered(env, evil, amount=AMOUNT):
    jid = _evil_job(env, evil, amount=amount)
    r = env.send_as(env.agent, lambda: env.escrow.functions.acceptJob(jid))
    assert r['status'] == 1
    r = env.send_as(env.agent, lambda: env.escrow.functions.submitDelivery(
        jid, DH, "evil delivery"))
    assert r['status'] == 1
    return jid


def _evil_disputed(env, evil, amount=AMOUNT):
    """Delivered + payer-disputed job in the evil token (bond posted in evil)."""
    bond = bond_for(amount)
    jid = _evil_delivered(env, evil, amount=amount)
    _fund_evil(env, evil, env.payer, bond)
    r = env.send_as(env.payer, lambda: env.escrow.functions.raiseDispute(
        jid, "evil dispute"))
    assert r['status'] == 1
    return jid


def _evil_bal(evil, addr):
    return evil.functions.balanceOf(addr).call()


# ================================================================ T1: double-spend

class TestDoubleSpend:
    def test_release_twice(self, env):
        jid = env.create_delivered_job()
        r = env.send_as(env.payer, lambda: env.escrow.functions.release(jid))
        assert r['status'] == 1
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.release(jid),
                           "not delivered")
        assert _balances(env) == (0, AMOUNT, 0)
        _assert_invariant(env)

    def test_release_partial_twice_same_sig(self, env):
        jid = env.create_delivered_job()
        half = AMOUNT // 2
        dl = env.deadline_in(86400)
        sig = env.sign_partial(env.agent, jid, half, dl)
        r = env.send_as(env.payer, lambda: env.escrow.functions.releasePartial(
            jid, half, dl, sig))
        assert r['status'] == 1
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.releasePartial(
                               jid, half, dl, sig),
                           "not delivered")
        assert _balances(env) == (half, half, 0)
        _assert_invariant(env)

    def test_release_partial_twice_fresh_sig(self, env):
        jid = env.create_delivered_job()
        half = AMOUNT // 2
        dl = env.deadline_in(86400)
        sig = env.sign_partial(env.agent, jid, half, dl)
        r = env.send_as(env.payer, lambda: env.escrow.functions.releasePartial(
            jid, half, dl, sig))
        assert r['status'] == 1
        # A FRESH signature for the same split must also fail: the job is
        # Released, so the state transition is the replay protection.
        dl2 = env.deadline_in(86400)
        sig2 = env.sign_partial(env.agent, jid, half, dl2)
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.releasePartial(
                               jid, half, dl2, sig2),
                           "not delivered")
        assert _balances(env) == (half, half, 0)

    def test_accept_twice_same_caller(self, env):
        jid = env.create_job(env.agent.address)
        r = env.send_as(env.agent, lambda: env.escrow.functions.acceptJob(jid))
        assert r['status'] == 1
        env.assert_reverts(env.agent,
                           lambda: env.escrow.functions.acceptJob(jid),
                           "not created")

    def test_accept_twice_different_caller(self, env):
        jid = env.create_job(env.agent.address)
        r = env.send_as(env.agent, lambda: env.escrow.functions.acceptJob(jid))
        assert r['status'] == 1
        env.assert_reverts(env.stranger,
                           lambda: env.escrow.functions.acceptJob(jid),
                           "not agent")

    def test_accept_open_job_twice(self, env):
        worker2 = _new_account(env)
        jid = env.create_job(None)  # open job
        r = env.send_as(env.agent, lambda: env.escrow.functions.acceptJob(jid))
        assert r['status'] == 1
        env.assert_reverts(worker2,
                           lambda: env.escrow.functions.acceptJob(jid),
                           "not agent")
        assert env.job(jid)[1] == env.agent.address

    def test_submit_delivery_twice(self, env):
        jid = _job_accepted(env)
        r = env.send_as(env.agent, lambda: env.escrow.functions.submitDelivery(
            jid, DH, "delivery one"))
        assert r['status'] == 1
        env.assert_reverts(env.agent,
                           lambda: env.escrow.functions.submitDelivery(
                               jid, b"\x22" * 32, "delivery two"),
                           "not accepted")

    def test_execute_ruling_twice_same_amount(self, env):
        jid = env.create_disputed_job()
        bond = bond_for(AMOUNT)
        r = env.send_as(env.operator,
                        lambda: env.escrow.functions.executeRuling(jid, AMOUNT // 2))
        assert r['status'] == 1
        env.assert_reverts(env.operator,
                           lambda: env.escrow.functions.executeRuling(
                               jid, AMOUNT // 2),
                           "not disputed")
        # 50% ruling: bond to worker (>= 50%)
        assert _balances(env) == (AMOUNT // 2, AMOUNT // 2 + bond, 0)
        _assert_invariant(env)

    def test_execute_ruling_twice_different_amount(self, env):
        jid = env.create_disputed_job()
        r = env.send_as(env.operator,
                        lambda: env.escrow.functions.executeRuling(jid, AMOUNT * 60 // 100))
        assert r['status'] == 1
        env.assert_reverts(env.operator,
                           lambda: env.escrow.functions.executeRuling(jid, 0),
                           "not disputed")
        env.assert_reverts(env.operator,
                           lambda: env.escrow.functions.executeRuling(jid, AMOUNT),
                           "not disputed")
        assert _balances(env) == (AMOUNT * 40 // 100,
                                  AMOUNT * 60 // 100 + bond_for(AMOUNT), 0)

    def test_settle_by_agreement_twice_same_sig(self, env):
        jid = env.create_disputed_job()
        bond = bond_for(AMOUNT)
        amount = AMOUNT // 2
        dl = env.deadline_in(86400)
        sig = env.sign_settle(env.agent, jid, amount, dl)
        r = env.send_as(env.payer, lambda: env.escrow.functions.settleByAgreement(
            jid, amount, dl, sig))
        assert r['status'] == 1
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.settleByAgreement(
                               jid, amount, dl, sig),
                           "not disputed")
        assert _balances(env) == (AMOUNT - amount + bond, amount, 0)
        _assert_invariant(env)

    def test_settle_by_agreement_twice_fresh_sig(self, env):
        jid = env.create_disputed_job()
        amount = AMOUNT * 3 // 4
        dl = env.deadline_in(86400)
        sig = env.sign_settle(env.agent, jid, amount, dl)
        r = env.send_as(env.payer, lambda: env.escrow.functions.settleByAgreement(
            jid, amount, dl, sig))
        assert r['status'] == 1
        # A fresh signature for the same amount must also fail.
        dl2 = env.deadline_in(86400)
        sig2 = env.sign_settle(env.agent, jid, amount, dl2)
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.settleByAgreement(
                               jid, amount, dl2, sig2),
                           "not disputed")

    def test_refund_dispute_timeout_twice(self, env):
        jid = env.create_disputed_job()
        bond = bond_for(AMOUNT)
        _past_valve(env, jid)
        r = env.send_as(env.payer,
                        lambda: env.escrow.functions.refundDisputeTimeout(jid))
        assert r['status'] == 1
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.refundDisputeTimeout(jid),
                           "not disputed")
        assert _balances(env) == (AMOUNT + bond, 0, 0)
        _assert_invariant(env)

    def test_cancel_after_deadline_twice(self, env):
        # Merged cancel: Accepted + past deadline refunds; a second
        # cancel reverts — the ghosted-agent exit is single-use.
        jid = _job_accepted(env)
        _past_deadline(env, jid)
        r = env.send_as(env.payer,
                        lambda: env.escrow.functions.cancel(jid))
        assert r['status'] == 1
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.cancel(jid),
                           "cannot cancel in this state")
        assert _balances(env) == (AMOUNT, 0, 0)
        _assert_invariant(env)

    def test_cancel_twice(self, env):
        jid = env.create_job(env.agent.address)
        r = env.send_as(env.payer, lambda: env.escrow.functions.cancel(jid))
        assert r['status'] == 1
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.cancel(jid),
                           "cannot cancel in this state")
        assert _balances(env) == (AMOUNT, 0, 0)

    def test_raise_dispute_twice_payer(self, env):
        jid = env.create_disputed_job()
        bond = bond_for(AMOUNT)
        # The bond moved exactly once: payer holds 0, escrow holds amount + bond.
        assert _balances(env) == (0, 0, AMOUNT + bond)
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.raiseDispute(jid, "again"),
                           "only after delivery")
        assert _balances(env) == (0, 0, AMOUNT + bond)
        assert env.escrow.functions.totalBonded(env.token_addr).call() == bond

    def test_raise_dispute_then_agent_dispute(self, env):
        jid = env.create_disputed_job()
        env.assert_reverts(env.agent,
                           lambda: env.escrow.functions.raiseDispute(jid, "agent too"),
                           "only after delivery")

    def test_submit_delivery_and_dispute_twice(self, env):
        jid = env.create_job(env.agent.address)
        r = env.send_as(env.agent, lambda: env.escrow.functions.acceptJob(jid))
        assert r['status'] == 1
        r = env.send_as(env.agent,
                        lambda: env.escrow.functions.submitDeliveryAndDispute(
                            jid, DH, "delivery", "dispute reason"))
        assert r['status'] == 1
        env.assert_reverts(env.agent,
                           lambda: env.escrow.functions.submitDeliveryAndDispute(
                               jid, DH, "delivery", "again"),
                           "not accepted")
        assert env.job(jid)[13] == 0  # agent dispute posts no bond

    def test_set_token_allowed_twice_idempotent(self, env):
        # Whitelist changes are idempotent BY DESIGN: repeating the same
        # call succeeds and changes nothing. That is the correct behaviour
        # for an admin setter, and the test proves it (not a revert).
        r = env.send_as(env.operator, lambda: env.escrow.functions.setTokenAllowed(
            env.token_addr, True))
        assert r['status'] == 1
        assert env.escrow.functions.allowedTokens(env.token_addr).call() is True
        r = env.send_as(env.operator, lambda: env.escrow.functions.setTokenAllowed(
            env.token_addr, True))
        assert r['status'] == 1
        assert env.escrow.functions.allowedTokens(env.token_addr).call() is True
        # Toggle off and back on works; a delisted token cannot fund a job.
        r = env.send_as(env.operator, lambda: env.escrow.functions.setTokenAllowed(
            env.token_addr, False))
        assert r['status'] == 1
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.createJob(
                               env.agent.address, env.token_addr, AMOUNT,
                               DEADLINE_SECONDS, REVIEW_WINDOW, "blocked"),
                           "token not allowed")


# ================================================================ T2: double-spend combinations

class TestDoubleSpendCombinations:
    """The same funds can't exit twice through ANY pair of paths."""

    def test_ruling_then_valve(self, env):
        jid = env.create_disputed_job()
        bond = bond_for(AMOUNT)
        r = env.send_as(env.operator, lambda: env.escrow.functions.executeRuling(
            jid, AMOUNT * 60 // 100))
        assert r['status'] == 1
        _past_valve(env, jid)
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.refundDisputeTimeout(jid),
                           "not disputed")
        assert _balances(env) == (AMOUNT * 40 // 100,
                                  AMOUNT * 60 // 100 + bond, 0)
        _assert_invariant(env)

    def test_ruling_then_settle(self, env):
        jid = env.create_disputed_job()
        bond = bond_for(AMOUNT)
        r = env.send_as(env.operator, lambda: env.escrow.functions.executeRuling(
            jid, AMOUNT * 30 // 100))
        assert r['status'] == 1
        dl = env.deadline_in(86400)
        sig = env.sign_settle(env.agent, jid, AMOUNT * 30 // 100, dl)
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.settleByAgreement(
                               jid, AMOUNT * 30 // 100, dl, sig),
                           "not disputed")
        # 30% ruling: bond to payer (< 50%)
        assert _balances(env) == (AMOUNT * 70 // 100 + bond,
                                  AMOUNT * 30 // 100, 0)
        _assert_invariant(env)

    def test_settle_then_ruling(self, env):
        jid = env.create_disputed_job()
        bond = bond_for(AMOUNT)
        _settle(env, jid, AMOUNT // 2, env.payer, env.agent)
        env.assert_reverts(env.operator,
                           lambda: env.escrow.functions.executeRuling(jid, AMOUNT // 2),
                           "not disputed")
        assert _balances(env) == (AMOUNT // 2 + bond, AMOUNT // 2, 0)
        _assert_invariant(env)

    def test_settle_then_valve(self, env):
        jid = env.create_disputed_job()
        _settle(env, jid, AMOUNT * 3 // 4, env.agent, env.payer)
        _past_valve(env, jid)
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.refundDisputeTimeout(jid),
                           "not disputed")
        assert _balances(env) == (AMOUNT // 4 + bond_for(AMOUNT),
                                  AMOUNT * 3 // 4, 0)

    def test_valve_then_ruling(self, env):
        jid = env.create_disputed_job()
        bond = bond_for(AMOUNT)
        _past_valve(env, jid)
        r = env.send_as(env.stranger,
                        lambda: env.escrow.functions.refundDisputeTimeout(jid))
        assert r['status'] == 1
        env.assert_reverts(env.operator,
                           lambda: env.escrow.functions.executeRuling(jid, AMOUNT),
                           "not disputed")
        assert _balances(env) == (AMOUNT + bond, 0, 0)
        _assert_invariant(env)

    def test_valve_then_settle(self, env):
        jid = env.create_disputed_job()
        _past_valve(env, jid)
        r = env.send_as(env.payer,
                        lambda: env.escrow.functions.refundDisputeTimeout(jid))
        assert r['status'] == 1
        dl = env.deadline_in(86400)
        sig = env.sign_settle(env.agent, jid, AMOUNT, dl)
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.settleByAgreement(
                               jid, AMOUNT, dl, sig),
                           "not disputed")
        assert _balances(env) == (AMOUNT + bond_for(AMOUNT), 0, 0)

    def test_release_partial_then_release(self, env):
        jid = env.create_delivered_job()
        half = AMOUNT // 2
        dl = env.deadline_in(86400)
        sig = env.sign_partial(env.agent, jid, half, dl)
        r = env.send_as(env.payer, lambda: env.escrow.functions.releasePartial(
            jid, half, dl, sig))
        assert r['status'] == 1
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.release(jid),
                           "not delivered")
        assert _balances(env) == (half, half, 0)
        _assert_invariant(env)

    def test_release_then_release_partial(self, env):
        jid = env.create_delivered_job()
        r = env.send_as(env.payer, lambda: env.escrow.functions.release(jid))
        assert r['status'] == 1
        half = AMOUNT // 2
        dl = env.deadline_in(86400)
        sig = env.sign_partial(env.agent, jid, half, dl)
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.releasePartial(
                               jid, half, dl, sig),
                           "not delivered")
        assert _balances(env) == (0, AMOUNT, 0)

    def test_ruling_then_release(self, env):
        jid = env.create_disputed_job()
        r = env.send_as(env.operator, lambda: env.escrow.functions.executeRuling(
            jid, AMOUNT))
        assert r['status'] == 1
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.release(jid),
                           "not delivered")
        assert _balances(env) == (0, AMOUNT + bond_for(AMOUNT), 0)

    def test_ruling_zero_then_settle(self, env):
        jid = env.create_disputed_job()
        bond = bond_for(AMOUNT)
        r = env.send_as(env.operator,
                        lambda: env.escrow.functions.executeRuling(jid, 0))
        assert r['status'] == 1
        assert env.state(jid) == REFUNDED
        dl = env.deadline_in(86400)
        sig = env.sign_settle(env.agent, jid, 0, dl)
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.settleByAgreement(
                               jid, 0, dl, sig),
                           "not disputed")
        assert _balances(env) == (AMOUNT + bond, 0, 0)
        _assert_invariant(env)

    def test_cancel_then_cancel(self, env):
        jid = env.create_job(env.agent.address)
        r = env.send_as(env.payer, lambda: env.escrow.functions.cancel(jid))
        assert r['status'] == 1
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.cancel(jid),
                           "cannot cancel in this state")
        assert _balances(env) == (AMOUNT, 0, 0)

    def test_cancel_after_deadline_then_cancel(self, env):
        jid = _job_accepted(env)
        _past_deadline(env, jid)
        r = env.send_as(env.payer,
                        lambda: env.escrow.functions.cancel(jid))
        assert r['status'] == 1
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.cancel(jid),
                           "cannot cancel in this state")
        assert _balances(env) == (AMOUNT, 0, 0)

    def test_accept_then_cancel(self, env):
        jid = _job_accepted(env)
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.cancel(jid),
                           "deadline not passed")
        # The job is still live and undisputed; the funds are still escrowed.
        assert _balances(env) == (0, 0, AMOUNT)
        assert env.state(jid) == ACCEPTED

    def test_ruling_full_then_valve(self, env):
        jid = env.create_disputed_job()
        bond = bond_for(AMOUNT)
        r = env.send_as(env.operator,
                        lambda: env.escrow.functions.executeRuling(jid, AMOUNT))
        assert r['status'] == 1
        _past_valve(env, jid)
        env.assert_reverts(env.stranger,
                           lambda: env.escrow.functions.refundDisputeTimeout(jid),
                           "not disputed")
        assert _balances(env) == (0, AMOUNT + bond, 0)
        _assert_invariant(env)


# ================================================================ T3: reentrancy

class TestReentrancy:
    """A malicious token executes a battery of escrow calls mid-payout.
    Every inner call must fail (breachCount stays 0) and the payout must
    move exactly the intended amount — nothing double-paid, nothing lost.
    Defence in depth: state transitions happen before payouts, caller
    checks gate every money fn, and the nonReentrant guard backs both."""

    def test_reenter_release_during_payout(self, env):
        evil = _evil_env(env)
        jid = _evil_delivered(env, evil)
        evil.functions.arm(jid).transact({'from': env.funder})
        w_before = _evil_bal(evil, env.agent.address)
        r = env.send_as(env.payer, lambda: env.escrow.functions.release(jid),
                        gas=1000000)
        assert r['status'] == 1
        assert evil.functions.reenterCount().call() == 1, "attack never fired?"
        assert evil.functions.breachCount().call() == 0, "reentrancy breached!"
        assert _evil_bal(evil, env.agent.address) - w_before == AMOUNT
        assert env.escrow.functions.totalUnsettled(evil.address).call() == 0
        _assert_invariant(env, evil.address)

    def test_reenter_ruling_during_payout(self, env):
        evil = _evil_env(env)
        jid = _evil_disputed(env, evil)
        bond = bond_for(AMOUNT)
        evil.functions.arm(jid).transact({'from': env.funder})
        w_before = _evil_bal(evil, env.agent.address)
        p_before = _evil_bal(evil, env.payer.address)
        r = env.send_as(env.operator,
                        lambda: env.escrow.functions.executeRuling(
                            jid, AMOUNT * 60 // 100),
                        gas=1000000)
        assert r['status'] == 1
        assert evil.functions.reenterCount().call() == 1, "attack never fired?"
        assert evil.functions.breachCount().call() == 0, "reentrancy breached!"
        # 60% ruling: worker gets 60% + bond, payer gets 40% — exactly.
        assert _evil_bal(evil, env.agent.address) - w_before == AMOUNT * 60 // 100 + bond
        assert _evil_bal(evil, env.payer.address) - p_before == AMOUNT * 40 // 100
        assert env.escrow.functions.totalUnsettled(evil.address).call() == 0
        assert env.escrow.functions.totalBonded(evil.address).call() == 0
        _assert_invariant(env, evil.address)

    def test_reenter_partial_during_payout(self, env):
        evil = _evil_env(env)
        jid = _evil_delivered(env, evil)
        evil.functions.arm(jid).transact({'from': env.funder})
        w_before = _evil_bal(evil, env.agent.address)
        p_before = _evil_bal(evil, env.payer.address)
        dl = env.deadline_in(86400)
        partial = AMOUNT * 40 // 100
        sig = env.sign_partial(env.agent, jid, partial, dl)
        r = env.send_as(env.payer, lambda: env.escrow.functions.releasePartial(
            jid, partial, dl, sig), gas=1000000)
        assert r['status'] == 1
        assert evil.functions.reenterCount().call() == 1, "attack never fired?"
        assert evil.functions.breachCount().call() == 0, "reentrancy breached!"
        assert _evil_bal(evil, env.agent.address) - w_before == partial
        assert _evil_bal(evil, env.payer.address) - p_before == AMOUNT - partial
        assert env.escrow.functions.totalUnsettled(evil.address).call() == 0
        _assert_invariant(env, evil.address)

    def test_reenter_valve_during_payout(self, env):
        evil = _evil_env(env)
        jid = _evil_disputed(env, evil)
        bond = bond_for(AMOUNT)
        _past_valve(env, jid)
        evil.functions.arm(jid).transact({'from': env.funder})
        p_before = _evil_bal(evil, env.payer.address)
        r = env.send_as(env.stranger,
                        lambda: env.escrow.functions.refundDisputeTimeout(jid),
                        gas=1000000)
        assert r['status'] == 1
        assert evil.functions.reenterCount().call() == 1, "attack never fired?"
        assert evil.functions.breachCount().call() == 0, "reentrancy breached!"
        assert _evil_bal(evil, env.payer.address) - p_before == AMOUNT + bond
        assert env.escrow.functions.totalUnsettled(evil.address).call() == 0
        assert env.escrow.functions.totalBonded(evil.address).call() == 0
        _assert_invariant(env, evil.address)


# ================================================================ T4: front-running

class TestFrontRunning:
    def test_two_workers_race_one_open_job(self, env):
        worker2 = _new_account(env)
        jid = env.create_job(None)  # open job
        r = env.send_as(env.agent, lambda: env.escrow.functions.acceptJob(jid))
        assert r['status'] == 1
        env.assert_reverts(worker2,
                           lambda: env.escrow.functions.acceptJob(jid),
                           "not agent")
        assert env.job(jid)[1] == env.agent.address

    def test_payer_cannot_self_accept_open_job(self, env):
        jid = env.create_job(None)
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.acceptJob(jid),
                           "payer cannot be agent")

    def test_operator_may_accept_open_job(self, env):
        # The operator is not the payer, so the contract does not forbid
        # the operator from accepting an open job as a worker. This test
        # pins that behaviour: no special-case exclusion exists for the
        # operator, only for the payer. (V9 forbade arbiters; V3 has no
        # such rule — the operator is an ordinary address here.)
        jid = env.create_job(None)
        r = env.send_as(env.operator,
                        lambda: env.escrow.functions.acceptJob(jid))
        assert r['status'] == 1
        assert env.job(jid)[1] == env.operator.address

    def test_open_job_accept_sets_deadline_and_agent(self, env):
        worker2 = _new_account(env)
        jid = env.create_job(None, deadline_seconds=7200)
        assert env.job(jid)[4] == 0, "deadline should be 0 before accept"
        r = env.send_as(worker2, lambda: env.escrow.functions.acceptJob(jid))
        assert r['status'] == 1
        after = env.job(jid)
        ts = env.w3.eth.get_block(r['blockNumber'])['timestamp']
        assert after[4] == ts + 7200, f"deadline wrong: {after[4]} != {ts + 7200}"
        assert after[1] == worker2.address

    def test_atomic_dispute_closes_split_window(self, env):
        # The payer sees a delivery in the mempool and tries to split
        # first. Atomic deliver+dispute moves Accepted -> Disputed in
        # one tx, so there is no window: releasePartial reverts.
        jid = _job_accepted(env)
        r = env.send_as(env.agent,
                        lambda: env.escrow.functions.submitDeliveryAndDispute(
                            jid, DH, "delivery", "agent dispute"))
        assert r['status'] == 1
        half = AMOUNT // 2
        dl = env.deadline_in(86400)
        sig = env.sign_partial(env.agent, jid, half, dl)
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.releasePartial(
                               jid, half, dl, sig),
                           "not delivered")

    def test_agent_claim_beats_late_payer_split(self, env):
        # After the review window the payer's split is dead; only the
        # agent may claim. A payer racing the agent loses.
        jid = env.create_delivered_job()
        _past_review(env, jid)
        half = AMOUNT // 2
        dl = env.deadline_in(86400)
        sig = env.sign_partial(env.agent, jid, half, dl)
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.releasePartial(
                               jid, half, dl, sig),
                           "review window passed")
        r = env.send_as(env.agent, lambda: env.escrow.functions.release(jid))
        assert r['status'] == 1
        assert _balances(env) == (0, AMOUNT, 0)


# ================================================================ T5: invalid transitions

class TestInvalidTransitions:
    def test_release_wrong_states(self, env):
        for build, label in (
            (lambda: _job_created(env), "created"),
            (lambda: _job_accepted(env), "accepted"),
            (lambda: env.create_disputed_job(), "disputed"),
            (lambda: _job_released(env), "released"),
            (lambda: _job_refunded_by_ruling(env), "refunded"),
            (lambda: _job_cancelled(env), "cancelled"),
        ):
            jid = build()
            env.assert_reverts(env.payer,
                               lambda jid=jid: env.escrow.functions.release(jid),
                               "not delivered", )

    def test_accept_wrong_states(self, env):
        jid = env.create_delivered_job()
        env.assert_reverts(env.agent,
                           lambda: env.escrow.functions.acceptJob(jid),
                           "not created")
        jid = env.create_disputed_job()
        env.assert_reverts(env.agent,
                           lambda: env.escrow.functions.acceptJob(jid),
                           "not created")
        jid = _job_released(env)
        env.assert_reverts(env.agent,
                           lambda: env.escrow.functions.acceptJob(jid),
                           "not created")
        jid = _job_cancelled(env)
        env.assert_reverts(env.agent,
                           lambda: env.escrow.functions.acceptJob(jid),
                           "not created")

    def test_accept_nonexistent_job(self, env):
        env.assert_reverts(env.agent,
                           lambda: env.escrow.functions.acceptJob(999),
                           "job does not exist")

    def test_submit_delivery_wrong_states(self, env):
        jid = env.create_job(env.agent.address)
        env.assert_reverts(env.agent,
                           lambda: env.escrow.functions.submitDelivery(
                               jid, DH, "early"),
                           "not accepted")
        jid = env.create_delivered_job()
        env.assert_reverts(env.agent,
                           lambda: env.escrow.functions.submitDelivery(
                               jid, DH, "again"),
                           "not accepted")
        jid = env.create_disputed_job()
        env.assert_reverts(env.agent,
                           lambda: env.escrow.functions.submitDelivery(
                               jid, DH, "again"),
                           "not accepted")

    def test_raise_dispute_wrong_states(self, env):
        jid = env.create_job(env.agent.address)
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.raiseDispute(jid, "early"),
                           "only after delivery")
        jid = _job_accepted(env)
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.raiseDispute(jid, "early"),
                           "only after delivery")
        jid = _job_released(env)
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.raiseDispute(jid, "late"),
                           "only after delivery")

    def test_dispute_after_review_window(self, env):
        jid = env.create_delivered_job()
        _past_review(env, jid)
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.raiseDispute(jid, "late"),
                           "review window ended")

    def test_execute_ruling_wrong_states(self, env):
        for build in (
            lambda: _job_created(env),
            lambda: _job_accepted(env),
            lambda: env.create_delivered_job(),
            lambda: _job_released(env),
            lambda: _job_refunded_by_ruling(env),
        ):
            jid = build()
            env.assert_reverts(env.operator,
                               lambda jid=jid: env.escrow.functions.executeRuling(
                                   jid, AMOUNT // 2),
                               "not disputed")

    def test_settle_wrong_states(self, env):
        jid = env.create_delivered_job()
        dl = env.deadline_in(86400)
        sig = env.sign_settle(env.agent, jid, AMOUNT // 2, dl)
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.settleByAgreement(
                               jid, AMOUNT // 2, dl, sig),
                           "not disputed")
        jid = _job_released(env)
        dl = env.deadline_in(86400)
        sig = env.sign_settle(env.agent, jid, AMOUNT // 2, dl)
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.settleByAgreement(
                               jid, AMOUNT // 2, dl, sig),
                           "not disputed")

    def test_valve_wrong_states(self, env):
        jid = env.create_delivered_job()
        # Delivered, even long past the would-be valve time: not disputed.
        env.time_travel(RULING_PERIOD + 100)
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.refundDisputeTimeout(jid),
                           "not disputed")
        jid = _job_released(env)
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.refundDisputeTimeout(jid),
                           "not disputed")

    def test_cancel_wrong_states(self, env):
        # Merged cancel state matrix: Accepted before the deadline hits
        # the deadline gate; every other non-exitable state hits the
        # state gate. (Created success is C3; Accepted-past-deadline
        # success is C5.)
        jid = _job_accepted(env)
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.cancel(jid),
                           "deadline not passed")
        for build in (
            lambda: env.create_delivered_job(),
            lambda: env.create_disputed_job(),
            lambda: _job_released(env),
        ):
            jid = build()
            env.assert_reverts(env.payer,
                               lambda jid=jid: env.escrow.functions.cancel(jid),
                               "cannot cancel in this state")

    def test_deliver_and_dispute_wrong_states(self, env):
        jid = env.create_job(env.agent.address)
        env.assert_reverts(env.agent,
                           lambda: env.escrow.functions.submitDeliveryAndDispute(
                               jid, DH, "d", "r"),
                           "not accepted")
        jid = env.create_delivered_job()
        env.assert_reverts(env.agent,
                           lambda: env.escrow.functions.submitDeliveryAndDispute(
                               jid, DH, "d", "r"),
                           "not accepted")

    def test_wrong_callers(self, env):
        jid = env.create_delivered_job()
        env.assert_reverts(env.stranger,
                           lambda: env.escrow.functions.release(jid),
                           "not payer")
        env.assert_reverts(env.agent,
                           lambda: env.escrow.functions.release(jid),
                           "review window not ended")
        env.assert_reverts(env.stranger,
                           lambda: env.escrow.functions.raiseDispute(jid, "no"),
                           "not a party")
        env.assert_reverts(env.stranger,
                           lambda: env.escrow.functions.cancel(jid),
                           "not payer")
        env.assert_reverts(env.agent,
                           lambda: env.escrow.functions.cancel(jid),
                           "not payer")
        jid2 = env.create_disputed_job()
        for acct in (env.payer, env.agent, env.stranger):
            env.assert_reverts(acct,
                               lambda: env.escrow.functions.executeRuling(
                                   jid2, AMOUNT // 2),
                               "not operator")
        env.assert_reverts(env.stranger,
                           lambda: env.escrow.functions.settleByAgreement(
                               jid2, AMOUNT // 2, env.deadline_in(86400),
                               b"\x00" * 65),
                           "not a party")
        for acct in (env.payer, env.agent, env.stranger):
            env.assert_reverts(acct,
                               lambda: env.escrow.functions.setTokenAllowed(
                                   env.token_addr, True),
                               "not operator")

    def test_nonexistent_job_all_fns(self, env):
        dl = env.deadline_in(86400)
        sig = env.sign_settle(env.agent, 999, AMOUNT // 2, dl)
        psig = env.sign_partial(env.agent, 999, AMOUNT // 2, dl)
        env.assert_reverts(env.agent,
                           lambda: env.escrow.functions.acceptJob(999),
                           "job does not exist")
        env.assert_reverts(env.agent,
                           lambda: env.escrow.functions.submitDelivery(999, DH, "x"),
                           "job does not exist")
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.release(999),
                           "not delivered")
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.raiseDispute(999, "x"),
                           "job does not exist")
        env.assert_reverts(env.operator,
                           lambda: env.escrow.functions.executeRuling(999, 1),
                           "not disputed")
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.settleByAgreement(
                               999, AMOUNT // 2, dl, sig),
                           "not disputed")
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.refundDisputeTimeout(999),
                           "not disputed")
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.cancel(999),
                           "not payer")
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.releasePartial(
                               999, AMOUNT // 2, dl, psig),
                           "not delivered")


# ================================================================ T6: partial edges

class TestPartialEdges:
    def test_partial_zero_reverts(self, env):
        # V3 differs from V9 here: a zero split reverts outright.
        jid = env.create_delivered_job()
        dl = env.deadline_in(86400)
        sig = env.sign_partial(env.agent, jid, 0, dl)
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.releasePartial(
                               jid, 0, dl, sig),
                           "cannot release zero to worker")

    def test_partial_full_amount(self, env):
        jid = env.create_delivered_job()
        dl = env.deadline_in(86400)
        sig = env.sign_partial(env.agent, jid, AMOUNT, dl)
        r = env.send_as(env.payer, lambda: env.escrow.functions.releasePartial(
            jid, AMOUNT, dl, sig))
        assert r['status'] == 1
        assert _balances(env) == (0, AMOUNT, 0)
        assert env.state(jid) == RELEASED

    def test_partial_over_amount_reverts(self, env):
        jid = env.create_delivered_job()
        dl = env.deadline_in(86400)
        sig = env.sign_partial(env.agent, jid, AMOUNT + 1, dl)
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.releasePartial(
                               jid, AMOUNT + 1, dl, sig),
                           "exceeds job amount")

    def test_double_partial_reverts_with_exact_balances(self, env):
        jid = env.create_delivered_job()
        first = AMOUNT * 40 // 100
        dl = env.deadline_in(86400)
        sig = env.sign_partial(env.agent, jid, first, dl)
        r = env.send_as(env.payer, lambda: env.escrow.functions.releasePartial(
            jid, first, dl, sig))
        assert r['status'] == 1
        assert _balances(env) == (AMOUNT - first, first, 0)
        dl2 = env.deadline_in(86400)
        sig2 = env.sign_partial(env.agent, jid, AMOUNT // 10, dl2)
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.releasePartial(
                               jid, AMOUNT // 10, dl2, sig2),
                           "not delivered")
        # Nothing moved a second time.
        assert _balances(env) == (AMOUNT - first, first, 0)

    def test_partial_then_release_reverts(self, env):
        jid = env.create_delivered_job()
        half = AMOUNT // 2
        dl = env.deadline_in(86400)
        sig = env.sign_partial(env.agent, jid, half, dl)
        r = env.send_as(env.payer, lambda: env.escrow.functions.releasePartial(
            jid, half, dl, sig))
        assert r['status'] == 1
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.release(jid),
                           "not delivered")

    def test_release_then_partial_reverts(self, env):
        jid = env.create_delivered_job()
        r = env.send_as(env.payer, lambda: env.escrow.functions.release(jid))
        assert r['status'] == 1
        half = AMOUNT // 2
        dl = env.deadline_in(86400)
        sig = env.sign_partial(env.agent, jid, half, dl)
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.releasePartial(
                               jid, half, dl, sig),
                           "not delivered")

    def test_partial_split_sums_exactly(self, env):
        # Odd amount: 999 units split 333/666 — no dust, no rounding loss.
        # 999 units is under the $10 tier, so the review window must fit
        # the 24h tier cap (the 48h default would revert).
        amount = 999
        jid = env.create_delivered_job(review_window=3600, amount=amount)
        dl = env.deadline_in(86400)
        sig = env.sign_partial(env.agent, jid, 333, dl)
        r = env.send_as(env.payer, lambda: env.escrow.functions.releasePartial(
            jid, 333, dl, sig))
        assert r['status'] == 1
        assert _balances(env) == (666, 333, 0)
        _assert_invariant(env)

    def test_failed_dust_partial_does_not_consume_job(self, env):
        jid = env.create_delivered_job()
        dust = AMOUNT // 1000  # 0.1% — below the 1% floor
        dl = env.deadline_in(86400)
        sig = env.sign_partial(env.agent, jid, dust, dl)
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.releasePartial(
                               jid, dust, dl, sig),
                           "dust partial rejected")
        # The job is untouched: a valid split still works afterwards.
        half = AMOUNT // 2
        dl2 = env.deadline_in(86400)
        sig2 = env.sign_partial(env.agent, jid, half, dl2)
        r = env.send_as(env.payer, lambda: env.escrow.functions.releasePartial(
            jid, half, dl2, sig2))
        assert r['status'] == 1
        assert _balances(env) == (half, half, 0)

    def test_partial_after_window_reverts(self, env):
        jid = env.create_delivered_job()
        _past_review(env, jid)
        half = AMOUNT // 2
        dl = env.deadline_in(86400)
        sig = env.sign_partial(env.agent, jid, half, dl)
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.releasePartial(
                               jid, half, dl, sig),
                           "review window passed")
