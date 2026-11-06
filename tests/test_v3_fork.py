#!/usr/bin/env python3
"""V3 chain-fork / EIP-712 domain separator tests.

F1  Pre-fork split signed for the deploy chain validates (sanity)
F2  After a fork, a split signed for the PRE-fork chain is rejected
    (no cross-chain replay — this is the bug the fix closes)
F3  After a fork, a split signed for the NEW chain validates (the
    rebuilt separator is the correct one for the forked chain)
F4  After a fork, a settle signed for the pre-fork chain is rejected
F5  After a fork, a settle signed for the new chain validates
F6  Wrong-chain split rejected even with no fork (chain binding)

The fix: the domain separator is cached at deploy with the chain ID
it was built for; _domainSeparator() rebuilds it when block.chainid
changes (OpenZeppelin EIP712 pattern). Before the fix the separator
was a single immutable built once in the constructor, so after a fork
a pre-fork signature would still validate on the forked chain.

How the fork is simulated: eth-tester hardcodes its chain ID in the
chain class (MainnetTesterPosChain.chain_id). The test overrides the
backend chain's class attribute, which is exactly what the CHAINID
opcode reads — verified by deploying a probe contract that returns
block.chainid (it tracks the override) and by raw txs still landing
after the override. Each test gets a fresh Env/tester, and each
setup_tester_chain call defines a fresh chain class, so the override
never leaks between tests. A no-op override would fail F3 (the
new-chain signature would revert), so the test proves the override
took effect rather than assuming it.
"""
from eth_account.messages import encode_typed_data

from conftest import (
    AMOUNT, DELIVERED, DISPUTED, RELEASED, _typed_data, normalize_sig,
)

FORK_CHAIN_ID = 968  # BOT Chain testnet: a realistic fork target


def _fork(env):
    """Simulate a chain fork: the chain ID the EVM reports changes."""
    type(env.tester.backend.chain).chain_id = FORK_CHAIN_ID
    assert env.tester.backend.chain.chain_id == FORK_CHAIN_ID


def _sign_partial_chain(env, acct, job_id, amount, deadline, chain_id):
    td = _typed_data(chain_id, env.escrow_addr, "PartialRelease", [
        {"name": "jobId", "type": "uint256"},
        {"name": "amountToWorker", "type": "uint256"},
        {"name": "deadline", "type": "uint256"},
    ], {"jobId": job_id, "amountToWorker": amount, "deadline": deadline})
    raw = acct.sign_message(encode_typed_data(full_message=td)).signature
    return normalize_sig(raw)


def _sign_settle_chain(env, acct, job_id, amount, deadline, chain_id):
    td = _typed_data(chain_id, env.escrow_addr, "SettleDispute", [
        {"name": "jobId", "type": "uint256"},
        {"name": "amountToWorker", "type": "uint256"},
        {"name": "deadline", "type": "uint256"},
    ], {"jobId": job_id, "amountToWorker": amount, "deadline": deadline})
    raw = acct.sign_message(encode_typed_data(full_message=td)).signature
    return normalize_sig(raw)


# ---- F1: pre-fork sanity -------------------------------------------------
def test_F1_pre_fork_split_validates(env):
    """A split signed for the deploy chain validates before any fork."""
    jid = env.create_delivered_job()
    half = AMOUNT // 2
    deadline = env.deadline_in(86400)
    sig = _sign_partial_chain(env, env.agent, jid, half, deadline, env.chain_id)
    r = env.send_as(env.payer, lambda: env.escrow.functions.releasePartial(
        jid, half, deadline, sig))
    assert r['status'] == 1
    assert env.state(jid) == RELEASED
    assert env.balance(env.agent.address) == half


# ---- F2/F3: split across the fork ---------------------------------------
def test_F2_old_chain_split_rejected_after_fork(env):
    """THE FIX: after a fork, a split signed for the pre-fork chain no
    longer validates. Before the fix the immutable separator built at
    deploy would still accept it — a cross-chain replay."""
    jid = env.create_delivered_job()
    half = AMOUNT // 2
    deadline = env.deadline_in(86400)
    old_sig = _sign_partial_chain(env, env.agent, jid, half, deadline, env.chain_id)
    _fork(env)
    env.assert_reverts(env.payer, lambda: env.escrow.functions.releasePartial(
        jid, half, deadline, old_sig), "worker sig required")
    assert env.state(jid) == DELIVERED  # job untouched by the replay


def test_F3_new_chain_split_validates_after_fork(env):
    """After the fork, a split signed for the NEW chain ID validates:
    the rebuilt separator is byte-identical to what a fresh deployment
    on the forked chain would cache."""
    jid = env.create_delivered_job()
    half = AMOUNT // 2
    deadline = env.deadline_in(86400)
    _fork(env)
    new_sig = _sign_partial_chain(env, env.agent, jid, half, deadline, FORK_CHAIN_ID)
    r = env.send_as(env.payer, lambda: env.escrow.functions.releasePartial(
        jid, half, deadline, new_sig))
    assert r['status'] == 1
    assert env.state(jid) == RELEASED
    assert env.balance(env.agent.address) == half
    assert env.balance(env.payer.address) == AMOUNT - half


# ---- F4/F5: settle across the fork --------------------------------------
def test_F4_old_chain_settle_rejected_after_fork(env):
    """Same replay protection for the settle signature (the second
    digest site using the separator)."""
    jid = env.create_disputed_job()
    amount = AMOUNT * 60 // 100
    deadline = env.deadline_in(86400)
    old_sig = _sign_settle_chain(env, env.agent, jid, amount, deadline, env.chain_id)
    _fork(env)
    env.assert_reverts(env.payer, lambda: env.escrow.functions.settleByAgreement(
        jid, amount, deadline, old_sig), "counterparty sig required")
    assert env.state(jid) == DISPUTED  # dispute untouched by the replay


def test_F5_new_chain_settle_validates_after_fork(env):
    """A settle signed for the new chain validates after the fork."""
    jid = env.create_disputed_job()
    amount = AMOUNT * 60 // 100
    deadline = env.deadline_in(86400)
    _fork(env)
    new_sig = _sign_settle_chain(env, env.agent, jid, amount, deadline, FORK_CHAIN_ID)
    r = env.send_as(env.payer, lambda: env.escrow.functions.settleByAgreement(
        jid, amount, deadline, new_sig))
    assert r['status'] == 1
    assert env.state(jid) == RELEASED
    assert env.balance(env.agent.address) == amount


# ---- F6: chain binding without any fork ---------------------------------
def test_F6_wrong_chain_split_rejected_without_fork(env):
    """Even with no fork, a split signed for a different chain ID is
    rejected — the separator is chain-bound, not just fork-aware."""
    jid = env.create_delivered_job()
    half = AMOUNT // 2
    deadline = env.deadline_in(86400)
    sig = _sign_partial_chain(env, env.agent, jid, half, deadline, FORK_CHAIN_ID)
    env.assert_reverts(env.payer, lambda: env.escrow.functions.releasePartial(
        jid, half, deadline, sig), "worker sig required")
    assert env.state(jid) == DELIVERED
