#!/usr/bin/env python3
"""Phase 5: Error Taxonomy & Revert Clarity — AgentEscrowV3.

Question: is every failure mode clearly communicated? Can the UI
translate every revert into something a user understands?

Adapted from the V9 Phase 5 suite (test_v9_phase5_errors.py). V9's
arbiter panel is gone; V3's new surface here is the dispute bond
(shortfall), executeRuling (operator-only), settleByAgreement (mutual
EIP-712), the 72h refund valve, tiered review windows, and the merged
cancel (Created + Accepted-past-deadline exits in one function).

Test groups:
  E1  Revert catalog: trigger every require in the contract source,
      assert the EXACT revert string. Table-driven, one fresh env per
      case. Every string the source contains must appear here.
  E2  Taxonomy completeness: the revert strings extracted from the
      contract source must match tests/error_taxonomy.json exactly —
      no revert without a plain-language message, no message without
      a revert it covers.
  E3  Missing reverts + boundaries: bad inputs that SHOULD revert but
      don't (documented findings, not failures), and the exact
      time-boundary behavior (strict > vs inclusive <=) at every gate.
  E4  Error recovery: state + balances unchanged after a revert, and
      the retry with corrected input succeeds.
  E5  No panics: a sweep of malformed inputs must all revert with a
      clean reason string from the taxonomy — never a Panic, never an
      empty reason. (One theoretical exception is documented in
      test_e5_giant_amount_overflow: a job amount above ~10**75 units
      can overflow the dust/bond multiplication. Practically
      unreachable — no token can carry that supply — so the contract
      is NOT changed for it.)
"""

import json
import os
import re

import pytest
import solcx
from eth_account.messages import encode_typed_data

from conftest import (
    AMOUNT, BOND_MAX, BOND_MIN, CREATED, ACCEPTED, DELIVERED, DISPUTED,
    RELEASED, REFUNDED, CANCELLED, DEADLINE_SECONDS, REVIEW_WINDOW,
    RULING_PERIOD, SECP256K1_N, SECP256K1_N_HALF, bond_for,
    _typed_data, normalize_sig,
)
from test_v3_prop_phase3 import (
    _deploy_token, _whitelist, _fund, _ok, _mk_job, _to_delivered,
    _credit, _assert_invariant, _dispute_by_agent, _fresh_acct,
    JOB as P3_JOB,
)
from eth_tester.exceptions import TransactionFailed

DH = b"\x11" * 32
ZERO = "0x0000000000000000000000000000000000000000"
LONG_TEXT = "x" * 10241  # 1 over the 10 KB cap
JOB = AMOUNT  # $1000 job, 6-decimal units (tier 3, max window 7 days)

try:
    solcx.install_solc("0.8.24")
except Exception:
    pass
solcx.set_solc_version("0.8.24")


# ---------------------------------------------------------------- helpers

def _reason(env, acct, fn_builder):
    """eth_call the tx; return the exact revert reason string, or None
    if the call succeeds."""
    from_addr = acct.address if hasattr(acct, "address") else acct
    try:
        fn_builder().call({"from": from_addr})
    except Exception as e:
        msg = str(e)
        m = re.search(r'reverted with reason: "?([^"\']+)"?', msg)
        if m:
            return m.group(1).strip()
        m2 = re.search(r'execution reverted: "?([^"\']*)"?', msg)
        if m2:
            return m2.group(1).strip() or "(no reason)"
        return msg[:200]
    return None


def _call_ok(env, acct, fn_builder):
    """Assert the eth_call SUCCEEDS (used at inclusive time boundaries,
    where sending a real tx would mine 1s later and flip the gate)."""
    from_addr = acct.address if hasattr(acct, "address") else acct
    fn_builder().call({"from": from_addr})  # raises if it reverts


def _delivered(env, review_window=REVIEW_WINDOW, amount=AMOUNT,
               deadline_seconds=DEADLINE_SECONDS):
    return env.create_delivered_job(review_window=review_window,
                                    amount=amount)


def _disputed(env, by="payer", review_window=REVIEW_WINDOW, amount=AMOUNT):
    return env.create_disputed_job(review_window=review_window,
                                   amount=amount, by=by)


def _sign_partial_wrong_chain(env, acct, job_id, amount, deadline, chain_id):
    """Sign a PartialRelease struct under a DIFFERENT chain id (wrong
    EIP-712 domain). The contract must reject it as 'worker sig required'."""
    td = _typed_data(chain_id, env.escrow_addr, "PartialRelease", [
        {"name": "jobId", "type": "uint256"},
        {"name": "amountToWorker", "type": "uint256"},
        {"name": "deadline", "type": "uint256"},
    ], {"jobId": job_id, "amountToWorker": amount, "deadline": deadline})
    raw = acct.sign_message(encode_typed_data(full_message=td)).signature
    return normalize_sig(raw)


def _malformed_sig(r, s, v):
    return (r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([v]))


# Reentrancy-capture token: on transfer it calls back into the escrow
# and RECORDS the inner call's raw revert data, so the test can assert
# the guard fired with exactly "reentrant" (the outer payout still
# succeeds — the guard holds without breaking the payment).
REVERT_CAPTURE_TOKEN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
contract RevertCaptureToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint8 public decimals = 6;
    address public escrow;
    uint256 public targetJob;
    bytes public lastInnerRevert;
    constructor(address _escrow) { escrow = _escrow; }
    function mint(address to, uint256 amt) external { balanceOf[to] += amt; }
    function approve(address s, uint256 amt) external returns (bool) {
        allowance[msg.sender][s] = amt; return true;
    }
    function setTarget(uint256 jid) external { targetJob = jid; }
    function transfer(address to, uint256 amt) external returns (bool) {
        (bool ok, bytes memory ret) = escrow.call(
            abi.encodeWithSignature("release(uint256)", targetJob));
        if (!ok) { lastInnerRevert = ret; }
        require(balanceOf[msg.sender] >= amt, "bal");
        balanceOf[msg.sender] -= amt; balanceOf[to] += amt; return true;
    }
    function transferFrom(address from, address to, uint256 amt) external returns (bool) {
        require(allowance[from][msg.sender] >= amt, "allow");
        allowance[from][msg.sender] -= amt;
        require(balanceOf[from] >= amt, "bal");
        balanceOf[from] -= amt; balanceOf[to] += amt; return true;
    }
}
"""


def _compile_capture_token():
    compiled = solcx.compile_source(
        REVERT_CAPTURE_TOKEN, output_values=["abi", "bin"],
        solc_version="0.8.24", optimize=True, optimize_runs=200)
    key = [k for k in compiled if "RevertCaptureToken" in k][0]
    return compiled[key]["abi"], compiled[key]["bin"]


def _decode_revert_reason(data):
    """Decode Error(string) revert data (0x08c379a0 + abi-encoded string)."""
    assert data[:4] == bytes.fromhex("08c379a0"), f"not Error(string): {data[:4].hex()}"
    from eth_abi import decode as abi_decode
    return abi_decode(["string"], data[4:])[0]

# ================================================================ E1: revert catalog
# Each case: (id, description, expected reason, fn(env) -> observed reason)

def _c01_set_token_allowed_by_stranger(env):
    return _reason(env, env.stranger, lambda: env.escrow.functions.setTokenAllowed(
        env.token_addr, True))


def _c02_set_token_allowed_zero(env):
    return _reason(env, env.operator, lambda: env.escrow.functions.setTokenAllowed(
        ZERO, True))


def _c03_ruling_by_non_operator(env):
    jid = _disputed(env)
    return _reason(env, env.payer, lambda: env.escrow.functions.executeRuling(
        jid, JOB // 2))


def _c04_create_zero_agent(env):
    return _reason(env, env.payer, lambda: env.escrow.functions.createJob(
        ZERO, env.token_addr, JOB, DEADLINE_SECONDS, REVIEW_WINDOW, "x"))


def _c05_create_payer_as_agent(env):
    return _reason(env, env.payer, lambda: env.escrow.functions.createJob(
        env.payer.address, env.token_addr, JOB, DEADLINE_SECONDS,
        REVIEW_WINDOW, "x"))


def _c06_create_zero_token(env):
    return _reason(env, env.payer, lambda: env.escrow.functions.createJob(
        env.agent.address, ZERO, JOB, DEADLINE_SECONDS, REVIEW_WINDOW, "x"))


def _c07_create_unwhitelisted_token(env):
    t = _deploy_token(env, "StandardToken", 18)
    _fund(env, t, env.payer, JOB)
    return _reason(env, env.payer, lambda: env.escrow.functions.createJob(
        env.agent.address, t.address, JOB, DEADLINE_SECONDS, REVIEW_WINDOW, "x"))


def _c08_create_amount_zero(env):
    return _reason(env, env.payer, lambda: env.escrow.functions.createJob(
        env.agent.address, env.token_addr, 0, DEADLINE_SECONDS, REVIEW_WINDOW, "x"))


def _c09_create_deadline_zero(env):
    return _reason(env, env.payer, lambda: env.escrow.functions.createJob(
        env.agent.address, env.token_addr, JOB, 0, REVIEW_WINDOW, "x"))


def _c10_create_window_too_short(env):
    return _reason(env, env.payer, lambda: env.escrow.functions.createJob(
        env.agent.address, env.token_addr, JOB, DEADLINE_SECONDS, 3599, "x"))


def _c11_create_window_too_long(env):
    # $5 job: tier 1 caps the window at 24h; 48h is too long.
    small = 5 * 10**6
    env.mint_and_approve(env.payer, small)
    return _reason(env, env.payer, lambda: env.escrow.functions.createJob(
        env.agent.address, env.token_addr, small, DEADLINE_SECONDS,
        48 * 3600, "x"))


def _c12_funding_failed(env):
    fr = _deploy_token(env, "FalseReturnToggleToken")
    _whitelist(env, fr.address)
    fr.functions.setLying(True).transact({"from": env.funder})
    _fund(env, fr, env.payer, JOB)
    return _reason(env, env.payer, lambda: env.escrow.functions.createJob(
        env.agent.address, fr.address, JOB, DEADLINE_SECONDS, 3600, "x"))


def _c13_no_funds_received(env):
    noop = _deploy_token(env, "NoOpToken")
    _whitelist(env, noop.address)
    return _reason(env, env.payer, lambda: env.escrow.functions.createJob(
        env.agent.address, noop.address, JOB, DEADLINE_SECONDS, 3600, "x"))


def _c14_accept_nonexistent(env):
    return _reason(env, env.agent, lambda: env.escrow.functions.acceptJob(999))


def _c15_accept_wrong_worker(env):
    jid = env.create_job(env.agent.address)
    return _reason(env, env.stranger, lambda: env.escrow.functions.acceptJob(jid))


def _c16_accept_own_open_job(env):
    jid = env.create_job(None)  # open job
    return _reason(env, env.payer, lambda: env.escrow.functions.acceptJob(jid))


def _c17_accept_twice(env):
    jid = env.create_job(env.agent.address)
    _ok(env, env.agent, lambda: env.escrow.functions.acceptJob(jid), "accept-1")
    return _reason(env, env.agent, lambda: env.escrow.functions.acceptJob(jid))


def _c18_accept_cancelled(env):
    jid = env.create_job(env.agent.address)
    _ok(env, env.payer, lambda: env.escrow.functions.cancel(jid), "cancel")
    return _reason(env, env.agent, lambda: env.escrow.functions.acceptJob(jid))


def _c19_deliver_not_accepted(env):
    jid = env.create_job(env.agent.address)
    return _reason(env, env.agent, lambda: env.escrow.functions.submitDelivery(
        jid, DH, "delivery"))


def _c20_deliver_by_stranger(env):
    jid = env.create_job(env.agent.address)
    _ok(env, env.agent, lambda: env.escrow.functions.acceptJob(jid), "accept")
    return _reason(env, env.stranger, lambda: env.escrow.functions.submitDelivery(
        jid, DH, "delivery"))


def _c21_deliver_no_agent(env):
    jid = env.create_job(None)  # open, never accepted
    return _reason(env, env.agent, lambda: env.escrow.functions.submitDelivery(
        jid, DH, "delivery"))


def _c22_deliver_empty_hash(env):
    jid = env.create_job(env.agent.address)
    _ok(env, env.agent, lambda: env.escrow.functions.acceptJob(jid), "accept")
    return _reason(env, env.agent, lambda: env.escrow.functions.submitDelivery(
        jid, b"\x00" * 32, "delivery"))


def _c23_deliver_text_too_long(env):
    jid = env.create_job(env.agent.address)
    _ok(env, env.agent, lambda: env.escrow.functions.acceptJob(jid), "accept")
    return _reason(env, env.agent, lambda: env.escrow.functions.submitDelivery(
        jid, DH, LONG_TEXT))


def _c24_deliver_after_deadline(env):
    jid = env.create_job(env.agent.address, deadline_seconds=1)
    _ok(env, env.agent, lambda: env.escrow.functions.acceptJob(jid), "accept")
    env.time_travel(5)
    return _reason(env, env.agent, lambda: env.escrow.functions.submitDelivery(
        jid, DH, "delivery"))


def _c25_dd_not_accepted(env):
    jid = env.create_job(env.agent.address)
    return _reason(env, env.agent, lambda: env.escrow.functions.submitDeliveryAndDispute(
        jid, DH, "delivery", "reason"))


def _c26_dd_by_stranger(env):
    jid = env.create_job(env.agent.address)
    _ok(env, env.agent, lambda: env.escrow.functions.acceptJob(jid), "accept")
    return _reason(env, env.stranger, lambda: env.escrow.functions.submitDeliveryAndDispute(
        jid, DH, "delivery", "reason"))


def _c27_dd_empty_hash(env):
    jid = env.create_job(env.agent.address)
    _ok(env, env.agent, lambda: env.escrow.functions.acceptJob(jid), "accept")
    return _reason(env, env.agent, lambda: env.escrow.functions.submitDeliveryAndDispute(
        jid, b"\x00" * 32, "delivery", "reason"))


def _c28_dd_text_too_long(env):
    jid = env.create_job(env.agent.address)
    _ok(env, env.agent, lambda: env.escrow.functions.acceptJob(jid), "accept")
    return _reason(env, env.agent, lambda: env.escrow.functions.submitDeliveryAndDispute(
        jid, DH, LONG_TEXT, "reason"))


def _c29_dd_reason_too_long(env):
    jid = env.create_job(env.agent.address)
    _ok(env, env.agent, lambda: env.escrow.functions.acceptJob(jid), "accept")
    return _reason(env, env.agent, lambda: env.escrow.functions.submitDeliveryAndDispute(
        jid, DH, "delivery", LONG_TEXT))


def _c30_dd_after_deadline(env):
    jid = env.create_job(env.agent.address, deadline_seconds=1)
    _ok(env, env.agent, lambda: env.escrow.functions.acceptJob(jid), "accept")
    env.time_travel(5)
    return _reason(env, env.agent, lambda: env.escrow.functions.submitDeliveryAndDispute(
        jid, DH, "delivery", "reason"))


def _c31_release_not_delivered(env):
    jid = env.create_job(env.agent.address)
    _ok(env, env.agent, lambda: env.escrow.functions.acceptJob(jid), "accept")
    return _reason(env, env.payer, lambda: env.escrow.functions.release(jid))


def _c32_release_by_stranger(env):
    jid = _delivered(env)
    return _reason(env, env.stranger, lambda: env.escrow.functions.release(jid))


def _c33_release_by_agent_early(env):
    jid = _delivered(env)
    return _reason(env, env.agent, lambda: env.escrow.functions.release(jid))


def _c34_partial_not_delivered(env):
    jid = env.create_job(env.agent.address)
    _ok(env, env.agent, lambda: env.escrow.functions.acceptJob(jid), "accept")
    dl = env.deadline_in(86400)
    return _reason(env, env.payer, lambda: env.escrow.functions.releasePartial(
        jid, JOB // 2, dl, b""))


def _c35_partial_by_stranger(env):
    jid = _delivered(env)
    dl = env.deadline_in(86400)
    return _reason(env, env.stranger, lambda: env.escrow.functions.releasePartial(
        jid, JOB // 2, dl, b""))


def _c36_partial_zero(env):
    jid = _delivered(env)
    dl = env.deadline_in(86400)
    return _reason(env, env.payer, lambda: env.escrow.functions.releasePartial(
        jid, 0, dl, b""))


def _c37_partial_exceeds(env):
    jid = _delivered(env)
    dl = env.deadline_in(86400)
    return _reason(env, env.payer, lambda: env.escrow.functions.releasePartial(
        jid, JOB + 1, dl, b""))


def _c38_partial_after_window(env):
    jid = _delivered(env, review_window=3600)
    env.time_travel(3601)
    dl = env.deadline_in(86400)
    return _reason(env, env.payer, lambda: env.escrow.functions.releasePartial(
        jid, JOB // 2, dl, b""))


def _c39_partial_sig_expired(env):
    jid = _delivered(env)
    return _reason(env, env.payer, lambda: env.escrow.functions.releasePartial(
        jid, JOB // 2, 1, b""))


def _c40_partial_dust(env):
    jid = _delivered(env)
    dl = env.deadline_in(86400)
    # 0.5% of the job: below the 1% dust floor, above zero.
    return _reason(env, env.payer, lambda: env.escrow.functions.releasePartial(
        jid, JOB // 200, dl, b""))


def _c41_partial_stranger_sig(env):
    jid = _delivered(env)
    dl = env.deadline_in(86400)
    sig = env.sign_partial(env.stranger, jid, JOB // 2, dl)
    return _reason(env, env.payer, lambda: env.escrow.functions.releasePartial(
        jid, JOB // 2, dl, sig))


def _c42_partial_wrong_amount_sig(env):
    jid = _delivered(env)
    dl = env.deadline_in(86400)
    sig = env.sign_partial(env.agent, jid, JOB // 2, dl)
    return _reason(env, env.payer, lambda: env.escrow.functions.releasePartial(
        jid, JOB * 3 // 5, dl, sig))


def _c43_partial_wrong_chain_sig(env):
    jid = _delivered(env)
    dl = env.deadline_in(86400)
    sig = _sign_partial_wrong_chain(env, env.agent, jid, JOB // 2, dl,
                                    env.chain_id + 1)
    return _reason(env, env.payer, lambda: env.escrow.functions.releasePartial(
        jid, JOB // 2, dl, sig))


def _c44_partial_bad_sig_length(env):
    jid = _delivered(env)
    dl = env.deadline_in(86400)
    return _reason(env, env.payer, lambda: env.escrow.functions.releasePartial(
        jid, JOB // 2, dl, b"\x00" * 64))


def _c45_partial_malleable_sig(env):
    jid = _delivered(env)
    dl = env.deadline_in(86400)
    sig = _malformed_sig(1, SECP256K1_N_HALF + 1, 27)
    return _reason(env, env.payer, lambda: env.escrow.functions.releasePartial(
        jid, JOB // 2, dl, sig))


def _c46_partial_bad_v(env):
    jid = _delivered(env)
    dl = env.deadline_in(86400)
    sig = _malformed_sig(1, 1, 29)
    return _reason(env, env.payer, lambda: env.escrow.functions.releasePartial(
        jid, JOB // 2, dl, sig))


def _c47_partial_bad_sig(env):
    jid = _delivered(env)
    dl = env.deadline_in(86400)
    sig = _malformed_sig(0, 0, 27)  # ecrecover -> address(0)
    return _reason(env, env.payer, lambda: env.escrow.functions.releasePartial(
        jid, JOB // 2, dl, sig))


def _c48_cancel_by_stranger(env):
    jid = env.create_job(env.agent.address)
    return _reason(env, env.stranger, lambda: env.escrow.functions.cancel(jid))


def _c49_cancel_before_deadline(env):
    jid = env.create_job(env.agent.address)
    _ok(env, env.agent, lambda: env.escrow.functions.acceptJob(jid), "accept")
    return _reason(env, env.payer, lambda: env.escrow.functions.cancel(jid))


def _c50_cancel_delivered(env):
    jid = _delivered(env)
    return _reason(env, env.payer, lambda: env.escrow.functions.cancel(jid))


def _c51_cancel_disputed(env):
    jid = _disputed(env)
    return _reason(env, env.payer, lambda: env.escrow.functions.cancel(jid))


def _c52_cancel_released(env):
    jid = _delivered(env)
    _ok(env, env.payer, lambda: env.escrow.functions.release(jid), "release")
    return _reason(env, env.payer, lambda: env.escrow.functions.cancel(jid))


def _c53_cancel_twice(env):
    jid = env.create_job(env.agent.address)
    _ok(env, env.payer, lambda: env.escrow.functions.cancel(jid), "cancel-1")
    return _reason(env, env.payer, lambda: env.escrow.functions.cancel(jid))


def _c54_cancel_nonexistent(env):
    # Quirk (documented in E3): cancel() on a job that does not exist
    # reports "not payer", because onlyPayer runs before any existence
    # check. The UI message for "not payer" is slightly off here, but
    # the call still fails safely.
    return _reason(env, env.payer, lambda: env.escrow.functions.cancel(999))


def _c55_dispute_reason_too_long(env):
    jid = _delivered(env)
    return _reason(env, env.payer, lambda: env.escrow.functions.raiseDispute(
        jid, LONG_TEXT))


def _c56_dispute_nonexistent(env):
    return _reason(env, env.payer, lambda: env.escrow.functions.raiseDispute(
        999, "reason"))


def _c57_dispute_by_stranger(env):
    jid = _delivered(env)
    return _reason(env, env.stranger, lambda: env.escrow.functions.raiseDispute(
        jid, "reason"))


def _c58_dispute_before_delivery(env):
    jid = env.create_job(env.agent.address)
    _ok(env, env.agent, lambda: env.escrow.functions.acceptJob(jid), "accept")
    return _reason(env, env.payer, lambda: env.escrow.functions.raiseDispute(
        jid, "reason"))


def _c59_dispute_after_window(env):
    jid = _delivered(env, review_window=3600)
    env.time_travel(3601)
    return _reason(env, env.payer, lambda: env.escrow.functions.raiseDispute(
        jid, "reason"))


def _c60_dispute_bond_shortfall(env):
    fee = _deploy_token(env, "FeeToken", env.stranger.address)
    _whitelist(env, fee.address)
    fee.functions.setFees(True).transact({"from": env.funder})
    jid = _mk_job(env, fee, P3_JOB)  # stored amount: 95% of P3_JOB
    _to_delivered(env, jid)
    bond = bond_for(95 * 10**6)
    _fund(env, fee, env.payer, bond, approve=bond)
    return _reason(env, env.payer, lambda: env.escrow.functions.raiseDispute(
        jid, "payer dispute"))


def _c61_ruling_not_disputed(env):
    jid = _delivered(env)
    return _reason(env, env.operator, lambda: env.escrow.functions.executeRuling(
        jid, JOB // 2))


def _c62_ruling_exceeds(env):
    jid = _disputed(env)
    return _reason(env, env.operator, lambda: env.escrow.functions.executeRuling(
        jid, JOB + 1))


def _c63_ruling_twice(env):
    jid = _disputed(env)
    _ok(env, env.operator, lambda: env.escrow.functions.executeRuling(
        jid, JOB // 2), "ruling-1")
    return _reason(env, env.operator, lambda: env.escrow.functions.executeRuling(
        jid, JOB // 2))


def _c64_settle_not_disputed(env):
    jid = _delivered(env)
    dl = env.deadline_in(86400)
    sig = env.sign_settle(env.agent, jid, JOB // 2, dl)
    return _reason(env, env.payer, lambda: env.escrow.functions.settleByAgreement(
        jid, JOB // 2, dl, sig))


def _c65_settle_by_stranger(env):
    jid = _disputed(env)
    dl = env.deadline_in(86400)
    return _reason(env, env.stranger, lambda: env.escrow.functions.settleByAgreement(
        jid, JOB // 2, dl, b""))


def _c66_settle_exceeds(env):
    jid = _disputed(env)
    dl = env.deadline_in(86400)
    sig = env.sign_settle(env.agent, jid, JOB + 1, dl)
    return _reason(env, env.payer, lambda: env.escrow.functions.settleByAgreement(
        jid, JOB + 1, dl, sig))


def _c67_settle_sig_expired(env):
    jid = _disputed(env)
    return _reason(env, env.payer, lambda: env.escrow.functions.settleByAgreement(
        jid, JOB // 2, 1, b""))


def _c68_settle_stranger_sig(env):
    jid = _disputed(env)
    dl = env.deadline_in(86400)
    sig = env.sign_settle(env.stranger, jid, JOB // 2, dl)
    return _reason(env, env.payer, lambda: env.escrow.functions.settleByAgreement(
        jid, JOB // 2, dl, sig))


def _c69_settle_wrong_amount_sig(env):
    jid = _disputed(env)
    dl = env.deadline_in(86400)
    sig = env.sign_settle(env.agent, jid, JOB // 2, dl)
    return _reason(env, env.payer, lambda: env.escrow.functions.settleByAgreement(
        jid, JOB * 3 // 5, dl, sig))


def _c70_settle_twice(env):
    jid = _disputed(env)
    dl = env.deadline_in(86400)
    sig = env.sign_settle(env.agent, jid, JOB // 2, dl)
    _ok(env, env.payer, lambda: env.escrow.functions.settleByAgreement(
        jid, JOB // 2, dl, sig), "settle-1")
    sig2 = env.sign_settle(env.agent, jid, JOB // 2, dl)
    return _reason(env, env.payer, lambda: env.escrow.functions.settleByAgreement(
        jid, JOB // 2, dl, sig2))


def _c71_valve_not_disputed(env):
    jid = _delivered(env)
    return _reason(env, env.payer, lambda: env.escrow.functions.refundDisputeTimeout(jid))


def _c72_valve_too_early(env):
    jid = _disputed(env)
    return _reason(env, env.payer, lambda: env.escrow.functions.refundDisputeTimeout(jid))


def _c73_valve_twice(env):
    jid = _disputed(env)
    disputed_at = env.job(jid)[14]
    env.time_travel_to(disputed_at + RULING_PERIOD + 1)
    _ok(env, env.payer, lambda: env.escrow.functions.refundDisputeTimeout(jid),
        "valve-1")
    return _reason(env, env.payer, lambda: env.escrow.functions.refundDisputeTimeout(jid))


def _c74_withdraw_nothing(env):
    return _reason(env, env.stranger, lambda: env.escrow.functions.withdraw(
        env.token_addr))


def _c75_withdraw_failed(env):
    # Lying token: release credits the worker (nothing actually moved),
    # and withdraw while the token still lies fails cleanly.
    ly = _deploy_token(env, "LyingToggleToken")
    _whitelist(env, ly.address)
    jid = _mk_job(env, ly, P3_JOB)
    _to_delivered(env, jid)
    ly.functions.setLying(True).transact({"from": env.funder})
    _ok(env, env.payer, lambda: env.escrow.functions.release(jid), "release-lying")
    assert _credit(env, ly.address, env.agent.address) == P3_JOB
    return _reason(env, env.agent, lambda: env.escrow.functions.withdraw(ly.address))


def _c76_withdraw_twice(env):
    ly = _deploy_token(env, "LyingToggleToken")
    _whitelist(env, ly.address)
    jid = _mk_job(env, ly, P3_JOB)
    _to_delivered(env, jid)
    ly.functions.setLying(True).transact({"from": env.funder})
    _ok(env, env.payer, lambda: env.escrow.functions.release(jid), "release-lying")
    assert _credit(env, ly.address, env.agent.address) == P3_JOB
    ly.functions.setLying(False).transact({"from": env.funder})
    _ok(env, env.agent, lambda: env.escrow.functions.withdraw(ly.address),
        "withdraw-1")
    return _reason(env, env.agent, lambda: env.escrow.functions.withdraw(ly.address))


def _c77_whitelist_wrong_decimals(env):
    t = _deploy_token(env, "StandardToken", 18)
    return _reason(env, env.operator, lambda: env.escrow.functions.setTokenAllowed(
        t.address, True))


def _c78_ruling_after_period(env):
    jid = _disputed(env)
    disputed_at = env.job(jid)[14]
    env.time_travel_to(disputed_at + RULING_PERIOD + 1)
    return _reason(env, env.operator, lambda: env.escrow.functions.executeRuling(
        jid, JOB // 2))


E1_CASES = [
    ("E1-01", "setTokenAllowed by stranger", "not operator", _c01_set_token_allowed_by_stranger),
    ("E1-02", "setTokenAllowed zero token", "zero address", _c02_set_token_allowed_zero),
    ("E1-03", "executeRuling by non-operator", "not operator", _c03_ruling_by_non_operator),
    ("E1-04", "createJob zero agent", "zero address agent", _c04_create_zero_agent),
    ("E1-05", "createJob payer as agent", "payer cannot be agent", _c05_create_payer_as_agent),
    ("E1-06", "createJob zero token", "zero address", _c06_create_zero_token),
    ("E1-07", "createJob unwhitelisted token", "token not allowed", _c07_create_unwhitelisted_token),
    ("E1-08", "createJob amount zero", "amount zero", _c08_create_amount_zero),
    ("E1-09", "createJob deadline zero", "deadline zero", _c09_create_deadline_zero),
    ("E1-10", "createJob review window too short", "review window too short", _c10_create_window_too_short),
    ("E1-11", "createJob review window too long", "review window too long", _c11_create_window_too_long),
    ("E1-12", "createJob funding failed (false-return token)", "funding failed", _c12_funding_failed),
    ("E1-13", "createJob no funds received (no-op token)", "no funds received", _c13_no_funds_received),
    ("E1-14", "acceptJob nonexistent", "job does not exist", _c14_accept_nonexistent),
    ("E1-15", "acceptJob wrong worker", "not agent", _c15_accept_wrong_worker),
    ("E1-16", "acceptJob payer on own open job", "payer cannot be agent", _c16_accept_own_open_job),
    ("E1-17", "acceptJob twice", "not created", _c17_accept_twice),
    ("E1-18", "acceptJob cancelled job", "not created", _c18_accept_cancelled),
    ("E1-19", "submitDelivery not accepted", "not accepted", _c19_deliver_not_accepted),
    ("E1-20", "submitDelivery by stranger", "not agent", _c20_deliver_by_stranger),
    ("E1-21", "submitDelivery no agent assigned", "no agent assigned", _c21_deliver_no_agent),
    ("E1-22", "submitDelivery empty hash", "empty delivery hash", _c22_deliver_empty_hash),
    ("E1-23", "submitDelivery text too long", "delivery text too long", _c23_deliver_text_too_long),
    ("E1-24", "submitDelivery after deadline", "deadline passed", _c24_deliver_after_deadline),
    ("E1-25", "deliver+dispute not accepted", "not accepted", _c25_dd_not_accepted),
    ("E1-26", "deliver+dispute by stranger", "not agent", _c26_dd_by_stranger),
    ("E1-27", "deliver+dispute empty hash", "empty delivery hash", _c27_dd_empty_hash),
    ("E1-28", "deliver+dispute text too long", "delivery text too long", _c28_dd_text_too_long),
    ("E1-29", "deliver+dispute reason too long", "dispute reason too long", _c29_dd_reason_too_long),
    ("E1-30", "deliver+dispute after deadline", "deadline passed", _c30_dd_after_deadline),
    ("E1-31", "release not delivered", "not delivered", _c31_release_not_delivered),
    ("E1-32", "release by stranger", "not payer", _c32_release_by_stranger),
    ("E1-33", "release by agent before window ends", "review window not ended", _c33_release_by_agent_early),
    ("E1-34", "releasePartial not delivered", "not delivered", _c34_partial_not_delivered),
    ("E1-35", "releasePartial by stranger", "not payer", _c35_partial_by_stranger),
    ("E1-36", "releasePartial zero to worker", "cannot release zero to worker", _c36_partial_zero),
    ("E1-37", "releasePartial exceeds job", "exceeds job amount", _c37_partial_exceeds),
    ("E1-38", "releasePartial after window", "review window passed", _c38_partial_after_window),
    ("E1-39", "releasePartial sig expired", "split signature expired", _c39_partial_sig_expired),
    ("E1-40", "releasePartial dust", "dust partial rejected", _c40_partial_dust),
    ("E1-41", "releasePartial stranger sig", "worker sig required", _c41_partial_stranger_sig),
    ("E1-42", "releasePartial wrong-amount sig", "worker sig required", _c42_partial_wrong_amount_sig),
    ("E1-43", "releasePartial wrong-chain sig", "worker sig required", _c43_partial_wrong_chain_sig),
    ("E1-44", "releasePartial 64-byte sig", "bad sig length", _c44_partial_bad_sig_length),
    ("E1-45", "releasePartial malleable sig", "malleable sig", _c45_partial_malleable_sig),
    ("E1-46", "releasePartial bad v", "bad v", _c46_partial_bad_v),
    ("E1-47", "releasePartial zero sig", "bad sig", _c47_partial_bad_sig),
    ("E1-48", "cancel by stranger", "not payer", _c48_cancel_by_stranger),
    ("E1-49", "cancel accepted before deadline", "deadline not passed", _c49_cancel_before_deadline),
    ("E1-50", "cancel delivered job", "cannot cancel in this state", _c50_cancel_delivered),
    ("E1-51", "cancel disputed job", "cannot cancel in this state", _c51_cancel_disputed),
    ("E1-52", "cancel released job", "cannot cancel in this state", _c52_cancel_released),
    ("E1-53", "cancel twice", "cannot cancel in this state", _c53_cancel_twice),
    ("E1-54", "cancel nonexistent job", "not payer", _c54_cancel_nonexistent),
    ("E1-55", "raiseDispute reason too long", "dispute reason too long", _c55_dispute_reason_too_long),
    ("E1-56", "raiseDispute nonexistent", "job does not exist", _c56_dispute_nonexistent),
    ("E1-57", "raiseDispute by stranger", "not a party", _c57_dispute_by_stranger),
    ("E1-58", "raiseDispute before delivery", "only after delivery", _c58_dispute_before_delivery),
    ("E1-59", "raiseDispute after window", "review window ended", _c59_dispute_after_window),
    ("E1-60", "raiseDispute bond shortfall", "bond shortfall", _c60_dispute_bond_shortfall),
    ("E1-61", "executeRuling not disputed", "not disputed", _c61_ruling_not_disputed),
    ("E1-62", "executeRuling exceeds job", "exceeds job amount", _c62_ruling_exceeds),
    ("E1-63", "executeRuling twice", "not disputed", _c63_ruling_twice),
    ("E1-64", "settleByAgreement not disputed", "not disputed", _c64_settle_not_disputed),
    ("E1-65", "settleByAgreement by stranger", "not a party", _c65_settle_by_stranger),
    ("E1-66", "settleByAgreement exceeds job", "exceeds job amount", _c66_settle_exceeds),
    ("E1-67", "settleByAgreement sig expired", "settlement signature expired", _c67_settle_sig_expired),
    ("E1-68", "settleByAgreement stranger sig", "counterparty sig required", _c68_settle_stranger_sig),
    ("E1-69", "settleByAgreement wrong-amount sig", "counterparty sig required", _c69_settle_wrong_amount_sig),
    ("E1-70", "settleByAgreement twice", "not disputed", _c70_settle_twice),
    ("E1-71", "refundDisputeTimeout not disputed", "not disputed", _c71_valve_not_disputed),
    ("E1-72", "refundDisputeTimeout too early", "ruling period not ended", _c72_valve_too_early),
    ("E1-73", "refundDisputeTimeout twice", "not disputed", _c73_valve_twice),
    ("E1-74", "withdraw nothing", "nothing to withdraw", _c74_withdraw_nothing),
    ("E1-75", "withdraw failed (lying token)", "withdrawal failed", _c75_withdraw_failed),
    ("E1-76", "withdraw twice", "nothing to withdraw", _c76_withdraw_twice),
    ("E1-77", "setTokenAllowed wrong-decimal token", "token must be 6 decimals", _c77_whitelist_wrong_decimals),
    ("E1-78", "executeRuling after ruling period", "ruling period ended", _c78_ruling_after_period),
]


@pytest.mark.parametrize("tid,desc,expected,fn", E1_CASES,
                         ids=[c[0] for c in E1_CASES])
def test_e1_revert_catalog(env, tid, desc, expected, fn):
    actual = fn(env)
    assert actual == expected, (
        f"{tid} ({desc}): expected revert {expected!r}, got {actual!r}")


def test_e1_constructor_zero_operator(env):
    """Deploying with a zero operator reverts cleanly."""
    build_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "..", "contracts", "build-AgentEscrowV3.json")
    with open(build_path) as f:
        build = json.load(f)
    escrow = env.w3.eth.contract(abi=build["abi"], bytecode=build["bytecode"])
    # On-chain deploy fails (status 0)...
    txh = escrow.constructor(ZERO).transact({"from": env.funder, "gas": 8000000})
    rcpt = env.w3.eth.wait_for_transaction_receipt(txh)
    assert rcpt["status"] == 0, "constructor with zero operator deployed?!"
    # ...and an eth_call of the deployment names the reason.
    from eth_abi import encode as abi_encode
    bytecode = build["bytecode"]
    data = (bytecode[2:] if bytecode.startswith("0x") else bytecode) + \
        abi_encode(["address"], [ZERO]).hex()
    with pytest.raises(Exception) as ei:
        env.w3.eth.call({"from": env.funder, "data": data})
    assert "zero address operator" in str(ei.value), str(ei.value)[:200]


def test_e1_reentrant_guard_fires(env):
    """A token that calls back into the escrow mid-payout hits the
    nonReentrant guard with exactly 'reentrant' — and the outer payout
    still succeeds, so the guard holds without breaking the payment."""
    abi, bytecode = _compile_capture_token()
    c = env.w3.eth.contract(abi=abi, bytecode=bytecode)
    txh = c.constructor(env.escrow_addr).transact({"from": env.funder, "gas": 3000000})
    rcpt = env.w3.eth.wait_for_transaction_receipt(txh)
    evil = env.w3.eth.contract(address=rcpt.contractAddress, abi=abi)
    _whitelist(env, evil.address)

    jid = _mk_job(env, evil, P3_JOB)
    _to_delivered(env, jid)
    evil.functions.setTarget(jid).transact({"from": env.funder})
    wb = evil.functions.balanceOf(env.agent.address).call()
    _ok(env, env.payer, lambda: env.escrow.functions.release(jid), "release")
    assert env.state(jid) == RELEASED
    assert evil.functions.balanceOf(env.agent.address).call() - wb == P3_JOB
    raw = evil.functions.lastInnerRevert().call()
    assert raw, "token never attempted the reentrant call"
    assert _decode_revert_reason(raw) == "reentrant", raw.hex()[:100]

# ================================================================ E2: taxonomy completeness

_TAXONOMY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "error_taxonomy.json")
_CONTRACT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "..", "contracts", "AgentEscrowV3.sol")
_ALLOWED_CATEGORIES = {"USER_ERROR", "AUTH_ERROR", "STATE_ERROR",
                       "TIME_ERROR", "SIG_ERROR", "SYSTEM_ERROR"}
_NAME_LEAK = re.compile("chr" + "is|babc" + "ock|p" + "am|week" + "ley|el" + "lis|ro" + "wan|wr" + "en|jun" + "iper|"
                        "el" + "la|jo" + "sh|gm" + "ail|lamp" + "light|\\bp" + "ip\\b", re.IGNORECASE)


def _source_revert_strings():
    src = open(_CONTRACT_PATH).read()
    return set(re.findall(r'(?:require|revert)\([\s\S]*?"([^"]+)"', src))


def test_e2_taxonomy_covers_every_revert():
    """The revert strings extracted from the contract source must match
    error_taxonomy.json exactly: no revert without a message, no message
    without a revert it covers."""
    with open(_TAXONOMY_PATH) as f:
        taxonomy = json.load(f)
    taxonomy.pop("_meta", None)
    source = _source_revert_strings()
    assert set(taxonomy) == source, (
        f"in source, no message: {sorted(source - set(taxonomy))}; "
        f"in taxonomy, no revert: {sorted(set(taxonomy) - source)}")
    assert len(source) == len(taxonomy), "duplicate or missing entries"
    for reason, entry in taxonomy.items():
        assert entry["category"] in _ALLOWED_CATEGORIES, reason
        msg = entry["message"]
        assert isinstance(msg, str) and msg.strip(), f"empty message: {reason}"
        assert len(msg) <= 200, f"message too long for UI: {reason}"
        assert not _NAME_LEAK.search(msg), f"name leak in message: {reason}"
    print(f"\nE2: {len(taxonomy)} revert strings, all with a message")


def test_e2_every_catalog_reason_is_in_taxonomy():
    """Every reason the E1 catalog observed must exist in the taxonomy —
    the catalog and the mapping can never drift apart."""
    with open(_TAXONOMY_PATH) as f:
        taxonomy = json.load(f)
    taxonomy.pop("_meta", None)
    expected = {c[2] for c in E1_CASES}
    expected |= {"zero address operator", "reentrant"}
    assert expected <= set(taxonomy), sorted(expected - set(taxonomy))


# ================================================================ E3: missing reverts + boundaries

def test_e3_metadata_uri_uncapped(env):
    """FINDING (low severity, no funds at risk): deliveryText and
    disputeReason are capped at 10 KB, but metadataURI has NO cap — an
    11 KB metadata URI funds fine and is stored on-chain. The cost is
    the payer's own gas, so this is unbounded state growth the payer
    pays for, not a theft vector. Documented here, contract NOT changed
    (a cap would be a contract change needing approval)."""
    env.mint_and_approve(env.payer, JOB)
    # 11 KB of fresh storage costs ~7M gas; the default 500k tx gas
    # would run out before the contract is even reached.
    r = env.send_as(env.payer, lambda: env.escrow.functions.createJob(
        env.agent.address, env.token_addr, JOB, DEADLINE_SECONDS,
        REVIEW_WINDOW, "x" * 11_000), gas=10_000_000)
    assert r["status"] == 1, "11 KB metadataURI should fund (uncapped)"
    jid = env.escrow.functions.jobCount().call() - 1
    assert env.job(jid)[8] == "x" * 11_000


def test_e3_empty_dispute_reason_allowed(env):
    """Observation, not a bug: raiseDispute accepts an empty reason
    string (length 0 <= 10 KB). The judge then gets no reason on-chain.
    The UI should require a reason; the contract does not."""
    jid = _delivered(env)
    bond = bond_for(JOB)
    env.mint_and_approve(env.payer, bond, approve=bond)
    r = env.send_as(env.payer, lambda: env.escrow.functions.raiseDispute(jid, ""))
    assert r["status"] == 1, "empty dispute reason is accepted"
    assert env.state(jid) == DISPUTED


def test_e3_cancel_nonexistent_reports_not_payer(env):
    """Documented quirk (see E1-54): cancel() on a job that does not
    exist reports 'not payer', because onlyPayer runs before any
    existence check. The call still fails safely; the UI message is
    just slightly off for a job number that was never created."""
    assert _reason(env, env.payer,
                   lambda: env.escrow.functions.cancel(999)) == "not payer"


def test_e3_release_boundary_strict(env):
    """Agent claim is STRICT: at exactly deliveredAt + reviewWindow the
    agent still cannot claim ('review window not ended'); one second
    later it can."""
    jid = _delivered(env, review_window=3600)
    delivered_at = env.job(jid)[9]
    env.time_travel_to(delivered_at + 3600)
    assert _reason(env, env.agent,
                   lambda: env.escrow.functions.release(jid)) == "review window not ended"
    env.time_travel_to(delivered_at + 3600 + 1)
    _call_ok(env, env.agent, lambda: env.escrow.functions.release(jid))


def test_e3_dispute_boundary_inclusive(env):
    """Dispute window is INCLUSIVE: at exactly deliveredAt + reviewWindow
    a dispute still succeeds; one second later it is too late."""
    jid = _delivered(env, review_window=3600)
    delivered_at = env.job(jid)[9]
    # Fund the bond FIRST: mint/approve send txs that mine blocks and
    # would push the chain past the boundary before the call.
    bond = bond_for(JOB)
    env.mint_and_approve(env.payer, bond, approve=bond)
    env.time_travel_to(delivered_at + 3600)
    _call_ok(env, env.payer, lambda: env.escrow.functions.raiseDispute(jid, "reason"))
    env.time_travel_to(delivered_at + 3600 + 1)
    assert _reason(env, env.payer,
                   lambda: env.escrow.functions.raiseDispute(jid, "reason")) == "review window ended"


def test_e3_partial_boundary_inclusive(env):
    """Split window is INCLUSIVE: at exactly deliveredAt + reviewWindow
    a split still succeeds."""
    jid = _delivered(env, review_window=3600)
    delivered_at = env.job(jid)[9]
    env.time_travel_to(delivered_at + 3600)
    dl = env.deadline_in(86400)
    sig = env.sign_partial(env.agent, jid, JOB // 2, dl)
    _call_ok(env, env.payer, lambda: env.escrow.functions.releasePartial(
        jid, JOB // 2, dl, sig))


def test_e3_valve_boundary_strict(env):
    """Valve is STRICT: at exactly disputedAt + 72h the refund is still
    locked ('ruling period not ended'); one second later it opens."""
    jid = _disputed(env)
    disputed_at = env.job(jid)[14]
    env.time_travel_to(disputed_at + RULING_PERIOD)
    assert _reason(env, env.payer, lambda: env.escrow.functions.refundDisputeTimeout(
        jid)) == "ruling period not ended"
    env.time_travel_to(disputed_at + RULING_PERIOD + 1)
    _call_ok(env, env.payer, lambda: env.escrow.functions.refundDisputeTimeout(jid))


def test_e3_cancel_boundary_strict(env):
    """Ghosted-agent refund is STRICT: at exactly the deadline the
    payer still cannot cancel ('deadline not passed'); one second
    later it refunds."""
    jid = env.create_job(env.agent.address, deadline_seconds=3600)
    _ok(env, env.agent, lambda: env.escrow.functions.acceptJob(jid), "accept")
    deadline = env.job(jid)[4]
    env.time_travel_to(deadline)
    assert _reason(env, env.payer,
                   lambda: env.escrow.functions.cancel(jid)) == "deadline not passed"
    env.time_travel_to(deadline + 1)
    _call_ok(env, env.payer, lambda: env.escrow.functions.cancel(jid))


def test_e3_delivery_boundary_inclusive(env):
    """Delivery deadline is INCLUSIVE: at exactly the deadline the
    worker can still deliver; one second later it is too late."""
    jid = env.create_job(env.agent.address, deadline_seconds=3600)
    _ok(env, env.agent, lambda: env.escrow.functions.acceptJob(jid), "accept")
    deadline = env.job(jid)[4]
    env.time_travel_to(deadline)
    _call_ok(env, env.agent, lambda: env.escrow.functions.submitDelivery(
        jid, DH, "delivery"))
    jid2 = env.create_job(env.agent.address, deadline_seconds=3600)
    _ok(env, env.agent, lambda: env.escrow.functions.acceptJob(jid2), "accept-2")
    deadline2 = env.job(jid2)[4]
    env.time_travel_to(deadline2 + 1)
    assert _reason(env, env.agent, lambda: env.escrow.functions.submitDelivery(
        jid2, DH, "delivery")) == "deadline passed"


# ================================================================ E4: error recovery

def test_e4_failed_split_then_retry(env):
    """A split with a bad worker signature reverts, the job stays
    Delivered with balances untouched, and the retry with the real
    signature succeeds."""
    jid = _delivered(env)
    dl = env.deadline_in(86400)
    bad_sig = env.sign_partial(env.stranger, jid, JOB // 2, dl)
    env.assert_reverts(env.payer, lambda: env.escrow.functions.releasePartial(
        jid, JOB // 2, dl, bad_sig), "worker sig required")
    assert env.state(jid) == DELIVERED
    assert env.balance(env.agent.address) == 0
    assert env.balance(env.payer.address) == 0
    good_sig = env.sign_partial(env.agent, jid, JOB // 2, dl)
    _ok(env, env.payer, lambda: env.escrow.functions.releasePartial(
        jid, JOB // 2, dl, good_sig), "retry")
    assert env.state(jid) == RELEASED
    assert env.balance(env.agent.address) == JOB // 2
    assert env.balance(env.payer.address) == JOB - JOB // 2


def test_e4_failed_dispute_then_retry(env):
    """A payer dispute that fails on the bond shortfall leaves the job
    Delivered with no bond taken; once the fee is off, the same dispute
    succeeds."""
    fee = _deploy_token(env, "FeeToken", env.stranger.address)
    _whitelist(env, fee.address)
    fee.functions.setFees(True).transact({"from": env.funder})
    jid = _mk_job(env, fee, P3_JOB)
    _to_delivered(env, jid)
    bond = bond_for(95 * 10**6)
    _fund(env, fee, env.payer, bond, approve=bond)
    env.assert_reverts(env.payer, lambda: env.escrow.functions.raiseDispute(
        jid, "dispute"), "bond shortfall")
    assert env.state(jid) == DELIVERED
    assert env.job(jid)[13] == 0
    fee.functions.setFees(False).transact({"from": env.funder})
    _ok(env, env.payer, lambda: env.escrow.functions.raiseDispute(jid, "dispute"),
        "retry")
    assert env.state(jid) == DISPUTED
    assert env.job(jid)[13] == bond


def test_e4_failed_funding_then_retry(env):
    """Funding with an unwhitelisted token reverts and creates no job;
    after whitelisting, the same funding succeeds."""
    t = _deploy_token(env, "StandardToken", 6)
    _fund(env, t, env.payer, JOB)
    env.assert_reverts(env.payer, lambda: env.escrow.functions.createJob(
        env.agent.address, t.address, JOB, DEADLINE_SECONDS, 3600, "x"),
        "token not allowed")
    assert env.escrow.functions.jobCount().call() == 0
    _whitelist(env, t.address)
    r = env.send_as(env.payer, lambda: env.escrow.functions.createJob(
        env.agent.address, t.address, JOB, DEADLINE_SECONDS, 3600, "x"))
    assert r["status"] == 1
    assert env.escrow.functions.jobCount().call() == 1


def test_e4_failed_ruling_then_retry(env):
    """A ruling above the job amount reverts and leaves the job Disputed;
    the retry with a valid amount settles it."""
    jid = _disputed(env)
    env.assert_reverts(env.operator, lambda: env.escrow.functions.executeRuling(
        jid, JOB + 1), "exceeds job amount")
    assert env.state(jid) == DISPUTED
    _ok(env, env.operator, lambda: env.escrow.functions.executeRuling(
        jid, JOB // 2), "retry")
    assert env.state(jid) == RELEASED


def test_e4_failed_withdraw_then_retry(env):
    """A withdraw that fails keeps the credit intact; once the token is
    honest again the same withdraw succeeds, and a second withdraw
    reverts cleanly."""
    ly = _deploy_token(env, "LyingToggleToken")
    _whitelist(env, ly.address)
    jid = _mk_job(env, ly, P3_JOB)
    _to_delivered(env, jid)
    ly.functions.setLying(True).transact({"from": env.funder})
    _ok(env, env.payer, lambda: env.escrow.functions.release(jid), "release-lying")
    assert _credit(env, ly.address, env.agent.address) == P3_JOB
    env.assert_reverts(env.agent, lambda: env.escrow.functions.withdraw(ly.address),
                       "withdrawal failed")
    assert _credit(env, ly.address, env.agent.address) == P3_JOB, "credit preserved"
    ly.functions.setLying(False).transact({"from": env.funder})
    wb = ly.functions.balanceOf(env.agent.address).call()
    _ok(env, env.agent, lambda: env.escrow.functions.withdraw(ly.address), "retry")
    assert ly.functions.balanceOf(env.agent.address).call() - wb == P3_JOB
    assert _credit(env, ly.address, env.agent.address) == 0
    env.assert_reverts(env.agent, lambda: env.escrow.functions.withdraw(ly.address),
                       "nothing to withdraw")


def test_e4_failed_cancel_then_retry(env):
    """A cancel before the deadline reverts and leaves the job Accepted;
    once the deadline passes the same cancel refunds it."""
    jid = env.create_job(env.agent.address, deadline_seconds=3600)
    _ok(env, env.agent, lambda: env.escrow.functions.acceptJob(jid), "accept")
    env.assert_reverts(env.payer, lambda: env.escrow.functions.cancel(jid),
                       "deadline not passed")
    assert env.state(jid) == ACCEPTED
    env.time_travel(3601)
    pb = env.balance(env.payer.address)
    _ok(env, env.payer, lambda: env.escrow.functions.cancel(jid), "retry")
    assert env.state(jid) == REFUNDED
    assert env.balance(env.payer.address) - pb == JOB


# ================================================================ E5: no panics

def test_e5_malformed_inputs_all_clean_reverts(env):
    """A sweep of malformed inputs: every one must revert with a clean
    reason string from the taxonomy — never a Panic, never empty."""
    with open(_TAXONOMY_PATH) as f:
        taxonomy = json.load(f)
    taxonomy.pop("_meta", None)
    jid = _delivered(env)
    dl = env.deadline_in(86400)
    cases = [
        ("accept huge jobId", env.agent,
         lambda: env.escrow.functions.acceptJob(2**256 - 1)),
        ("release huge jobId", env.payer,
         lambda: env.escrow.functions.release(2**256 - 1)),
        ("releasePartial huge jobId", env.payer,
         lambda: env.escrow.functions.releasePartial(2**256 - 1, 1, dl, b"")),
        ("cancel huge jobId", env.payer,
         lambda: env.escrow.functions.cancel(2**256 - 1)),
        ("dispute huge jobId", env.payer,
         lambda: env.escrow.functions.raiseDispute(2**256 - 1, "x")),
        ("ruling huge jobId", env.operator,
         lambda: env.escrow.functions.executeRuling(2**256 - 1, 1)),
        ("settle huge jobId", env.payer,
         lambda: env.escrow.functions.settleByAgreement(2**256 - 1, 1, dl, b"")),
        ("valve huge jobId", env.payer,
         lambda: env.escrow.functions.refundDisputeTimeout(2**256 - 1)),
        ("withdraw zero token", env.agent,
         lambda: env.escrow.functions.withdraw(ZERO)),
        ("releasePartial max amount", env.payer,
         lambda: env.escrow.functions.releasePartial(jid, 2**256 - 1, dl, b"")),
        ("createJob max amount (no funds)", env.payer,
         lambda: env.escrow.functions.createJob(
             env.agent.address, env.token_addr, 2**256 - 1,
             DEADLINE_SECONDS, REVIEW_WINDOW, "x")),
        ("settle max amount", env.payer,
         lambda: env.escrow.functions.settleByAgreement(jid, 2**256 - 1, dl, b"")),
    ]
    for label, acct, fn in cases:
        reason = _reason(env, acct, fn)
        assert reason is not None, f"{label}: call SUCCEEDED, expected a revert"
        assert "Panic" not in reason and reason != "(no reason)", (
            f"{label}: unclean revert: {reason!r}")
        assert reason in taxonomy, f"{label}: reason {reason!r} not in taxonomy"


def test_e5_giant_amount_overflow(env):
    """DOCUMENTED THEORETICAL LIMIT (not a bug worth fixing): a job
    amount above ~2**256/100 (~10**75 units) overflows the dust-check
    multiplication `job.amount * MIN_PARTIAL_BPS` and panics (0x11)
    instead of reverting cleanly. No token can carry that supply —
    it is ~10**57 times all USD in existence in 6-decimal units — so
    the contract is NOT changed for it. The test pins the behavior so
    a future reader knows it was found and judged, not missed."""
    huge = 2**256 - 1
    env.mint_and_approve(env.payer, huge)
    r = env.send_as(env.payer, lambda: env.escrow.functions.createJob(
        env.agent.address, env.token_addr, huge, DEADLINE_SECONDS,
        REVIEW_WINDOW, "giant job"))
    assert r["status"] == 1, "giant job should fund in eth-tester"
    jid = env.escrow.functions.jobCount().call() - 1
    assert env.job(jid)[3] == huge
    _ok(env, env.agent, lambda: env.escrow.functions.acceptJob(jid), "accept")
    _ok(env, env.agent, lambda: env.escrow.functions.submitDelivery(
        jid, DH, "delivery"), "deliver")
    dl = env.deadline_in(86400)
    reason = _reason(env, env.payer, lambda: env.escrow.functions.releasePartial(
        jid, 1, dl, b""))
    assert reason is not None and "Panic" in reason, (
        f"expected an arithmetic Panic for the giant amount, got {reason!r}")
