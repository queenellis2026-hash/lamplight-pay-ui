#!/usr/bin/env python3
"""Phase 3: Fault Injection — hostile/weird tokens vs AgentEscrowV3.

Question: how does V3 behave when the ERC20 token misbehaves?
The contract accepts any whitelisted token — what if it is hostile
or broken? The bar (from V9): worst acceptable case is funds
temporarily locked, never stolen.

Adapted from the V9 Phase 3 suite (test_v9_phase3_faults.py). V9's
arbiter panel is gone; V3's dispute paths are executeRuling (single
operator key), settleByAgreement (mutual EIP-712), and the 72h refund
valve. V3's new surface in this phase: the dispute bond (20%, min $1,
max $50) — it must arrive in full, so a fee token cannot post it —
and the operator-managed whitelist (each hostile token is whitelisted
by the operator before use).

Test groups:
  T1   Fee-on-transfer token (5%): funding nets, payout fee, bond
       shortfall blocks payer disputes; agent disputes still work
  T2   Reverting token (toggle): funding reverts cleanly; payout
       credits; withdraw after heal; withdraw replay reverts
  T3   Gas-griefing token: release completes w/ gas; low-gas reverts
       retryable
  T4   Weird decimals (0 and 24): REJECTED at the whitelist — bond
       math and review tiers are 6-decimal units, so a wrong-decimal
       token can never fund a job (was: partial math exact, before
       the whitelist enforced 6 decimals)
  T5   No-return token (USDT-style): full flow + dispute + ruling
  T6   Blacklisting token: mid-job blacklist -> credit; withdraw
       after unblacklist; blacklisted payer cannot dispute (bond pull fails)
  T7   Rebasing token: up/down behavior, no theft vector; bond posts
       after a rebase-up (V3 invariant is >=, so an up-rebase does
       NOT break it — unlike V9's ==)
  T8   Pausable token mid-dispute: agent dispute + ruling credits
       while frozen; payer dispute reverts while frozen
  T9   EOA as token address: whitelisted EOA funding reverts cleanly
       ("no funds received"); unwhitelisted token reverts earlier
  T10  Lying token (returns true, moves nothing): credit path;
       false-return variant
  T11  Cross-job contamination: weird token can't touch other jobs
  T12  Fee-to-payer token: transparency (job.amount is net, on-chain)
  T13  Return-bomb token (100KB returndata): bounded gas, balance
       check pays; funding unaffected (bomb lives in transfer only)
  T14  Split with one failed leg: worker blacklisted, payer clean —
       worker leg credits, payer leg pays; withdraw after unblacklist;
       replay reverts. (A fee token can never create a credit — the
       fee is borne by the recipient — so the withdraw trap is tested
       with a blacklisting token instead.)
  T15  Ruling + valve with a broken token: all legs credit; heal and
       withdraw; replay reverts
  T16  Mutual settle with a broken token: all legs credit; heal and
       withdraw; replay reverts
"""
import pytest
import solcx
from conftest import (
    AMOUNT, BOND_MIN, BOND_MAX, CREATED, ACCEPTED, DELIVERED, DISPUTED,
    RELEASED, REFUNDED, CANCELLED, DEADLINE_SECONDS, REVIEW_WINDOW,
    RULING_PERIOD, bond_for,
)

DH = b"\x11" * 32  # dummy delivery hash
JOB = 100 * 10**6  # $100 job, 6-decimal units (tier 2, max window 72h)

try:
    solcx.install_solc("0.8.24")
except Exception:
    pass
solcx.set_solc_version("0.8.24")


# ---------------------------------------------------------------- token sources
# Adapted from the V9 Phase 3 suite. Standard hostile/weird ERC20
# doubles; nothing here knows about the escrow except the reentrancy
# case, which Phase 2 already covers and is not repeated here.

STANDARD_TOKEN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
contract StandardToken {
    string public name = "Std"; string public symbol = "STD"; uint8 public decimals;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    constructor(uint8 _decimals) { decimals = _decimals; }
    function mint(address to, uint256 amt) external { balanceOf[to] += amt; totalSupply += amt; }
    function approve(address s, uint256 amt) external returns (bool) { allowance[msg.sender][s] = amt; return true; }
    function transfer(address to, uint256 amt) external returns (bool) {
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

NOOP_TOKEN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
contract NoOpToken {
    string public name = "NoOp"; string public symbol = "NOOP"; uint8 public decimals = 6;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    function mint(address to, uint256 amt) external { balanceOf[to] += amt; }
    function approve(address s, uint256 amt) external returns (bool) { allowance[msg.sender][s] = amt; return true; }
    // transferFrom claims success but moves nothing: funding it must
    // revert "no funds received" (the escrow measures what arrived).
    function transfer(address to, uint256 amt) external returns (bool) { return true; }
    function transferFrom(address from, address to, uint256 amt) external returns (bool) { return true; }
}
"""


FEE_TOKEN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
contract FeeToken {
    string public name = "Fee"; string public symbol = "FEE"; uint8 public decimals = 6;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    address public feeCollector;
    uint256 public constant FEE_BPS = 500; // 5%
    bool public feesOn;
    constructor(address _collector) { feeCollector = _collector; }
    function mint(address to, uint256 amt) external { balanceOf[to] += amt; totalSupply += amt; }
    function approve(address s, uint256 amt) external returns (bool) { allowance[msg.sender][s] = amt; return true; }
    function setFees(bool on) external { feesOn = on; }
    function _fee(uint256 amt) internal view returns (uint256) {
        return feesOn ? (amt * FEE_BPS) / 10000 : 0;
    }
    function transfer(address to, uint256 amt) external returns (bool) {
        uint256 fee = _fee(amt);
        require(balanceOf[msg.sender] >= amt, "bal");
        balanceOf[msg.sender] -= amt;
        balanceOf[to] += amt - fee;
        if (fee > 0) balanceOf[feeCollector] += fee;
        return true;
    }
    function transferFrom(address from, address to, uint256 amt) external returns (bool) {
        require(allowance[from][msg.sender] >= amt, "allow");
        allowance[from][msg.sender] -= amt;
        uint256 fee = _fee(amt);
        require(balanceOf[from] >= amt, "bal");
        balanceOf[from] -= amt;
        balanceOf[to] += amt - fee;
        if (fee > 0) balanceOf[feeCollector] += fee;
        return true;
    }
}
"""

TOGGLE_TOKEN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
contract ToggleToken {
    string public name = "Tgl"; string public symbol = "TGL"; uint8 public decimals = 6;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    bool public broken;
    function mint(address to, uint256 amt) external { balanceOf[to] += amt; totalSupply += amt; }
    function approve(address s, uint256 amt) external returns (bool) { allowance[msg.sender][s] = amt; return true; }
    function setBroken(bool b) external { broken = b; }
    function transfer(address to, uint256 amt) external returns (bool) {
        require(!broken, "frozen");
        require(balanceOf[msg.sender] >= amt, "bal");
        balanceOf[msg.sender] -= amt; balanceOf[to] += amt; return true;
    }
    function transferFrom(address from, address to, uint256 amt) external returns (bool) {
        require(!broken, "frozen");
        require(allowance[from][msg.sender] >= amt, "allow");
        allowance[from][msg.sender] -= amt;
        require(balanceOf[from] >= amt, "bal");
        balanceOf[from] -= amt; balanceOf[to] += amt; return true;
    }
}
"""

GAS_GRIEF_TOKEN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
contract GasGriefToken {
    string public name = "Ghz"; string public symbol = "GHZ"; uint8 public decimals = 6;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public sink;
    uint256 public rounds = 20000;
    function mint(address to, uint256 amt) external { balanceOf[to] += amt; totalSupply += amt; }
    function approve(address s, uint256 amt) external returns (bool) { allowance[msg.sender][s] = amt; return true; }
    function _burn() internal {
        uint256 x = sink + 1;
        for (uint256 i = 0; i < rounds; i++) { x = x + i * 7 + 1; }
        sink = x; // storage write: optimizer cannot remove the loop
    }
    function transfer(address to, uint256 amt) external returns (bool) {
        _burn();
        require(balanceOf[msg.sender] >= amt, "bal");
        balanceOf[msg.sender] -= amt; balanceOf[to] += amt; return true;
    }
    function transferFrom(address from, address to, uint256 amt) external returns (bool) {
        _burn();
        require(allowance[from][msg.sender] >= amt, "allow");
        allowance[from][msg.sender] -= amt;
        require(balanceOf[from] >= amt, "bal");
        balanceOf[from] -= amt; balanceOf[to] += amt; return true;
    }
}
"""

NO_RETURN_TOKEN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
contract NoReturnToken {
    string public name = "NR"; string public symbol = "NR"; uint8 public decimals = 6;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    function mint(address to, uint256 amt) external { balanceOf[to] += amt; totalSupply += amt; }
    function approve(address s, uint256 amt) external { allowance[msg.sender][s] = amt; }
    function transfer(address to, uint256 amt) external {
        require(balanceOf[msg.sender] >= amt, "bal");
        balanceOf[msg.sender] -= amt; balanceOf[to] += amt;
    }
    function transferFrom(address from, address to, uint256 amt) external {
        require(allowance[from][msg.sender] >= amt, "allow");
        allowance[from][msg.sender] -= amt;
        require(balanceOf[from] >= amt, "bal");
        balanceOf[from] -= amt; balanceOf[to] += amt;
    }
}
"""

BLACKLIST_TOKEN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
contract BlacklistToken {
    string public name = "BL"; string public symbol = "BL"; uint8 public decimals = 6;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => bool) public blacklisted;
    function mint(address to, uint256 amt) external { balanceOf[to] += amt; totalSupply += amt; }
    function approve(address s, uint256 amt) external returns (bool) { allowance[msg.sender][s] = amt; return true; }
    function setBlacklisted(address a, bool b) external { blacklisted[a] = b; }
    function transfer(address to, uint256 amt) external returns (bool) {
        require(!blacklisted[msg.sender] && !blacklisted[to], "blocked");
        require(balanceOf[msg.sender] >= amt, "bal");
        balanceOf[msg.sender] -= amt; balanceOf[to] += amt; return true;
    }
    function transferFrom(address from, address to, uint256 amt) external returns (bool) {
        require(!blacklisted[from] && !blacklisted[to], "blocked");
        require(allowance[from][msg.sender] >= amt, "allow");
        allowance[from][msg.sender] -= amt;
        require(balanceOf[from] >= amt, "bal");
        balanceOf[from] -= amt; balanceOf[to] += amt; return true;
    }
}
"""

REBASE_TOKEN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
contract RebaseToken {
    string public name = "RB"; string public symbol = "RB"; uint8 public decimals = 6;
    uint256 public index = 1e18; // nominal = shares * index / 1e18
    mapping(address => uint256) public shares;
    mapping(address => mapping(address => uint256)) public allowance; // nominal
    function balanceOf(address a) external view returns (uint256) { return (shares[a] * index) / 1e18; }
    function mint(address to, uint256 amt) external { shares[to] += (amt * 1e18) / index; }
    function approve(address s, uint256 amt) external returns (bool) { allowance[msg.sender][s] = amt; return true; }
    function rebase(uint256 newIndex) external { index = newIndex; }
    function transfer(address to, uint256 amt) external returns (bool) {
        uint256 s = (amt * 1e18) / index;
        require(shares[msg.sender] >= s, "bal");
        shares[msg.sender] -= s; shares[to] += s; return true;
    }
    function transferFrom(address from, address to, uint256 amt) external returns (bool) {
        require(allowance[from][msg.sender] >= amt, "allow");
        allowance[from][msg.sender] -= amt;
        uint256 s = (amt * 1e18) / index;
        require(shares[from] >= s, "bal");
        shares[from] -= s; shares[to] += s; return true;
    }
}
"""

LYING_TOGGLE_TOKEN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
contract LyingToggleToken {
    string public name = "Ly"; string public symbol = "LY"; uint8 public decimals = 6;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    bool public lying;
    function mint(address to, uint256 amt) external { balanceOf[to] += amt; totalSupply += amt; }
    function approve(address s, uint256 amt) external returns (bool) { allowance[msg.sender][s] = amt; return true; }
    function setLying(bool b) external { lying = b; }
    function transfer(address to, uint256 amt) external returns (bool) {
        if (lying) return true; // moves nothing, claims success
        require(balanceOf[msg.sender] >= amt, "bal");
        balanceOf[msg.sender] -= amt; balanceOf[to] += amt; return true;
    }
    function transferFrom(address from, address to, uint256 amt) external returns (bool) {
        if (lying) return true;
        require(allowance[from][msg.sender] >= amt, "allow");
        allowance[from][msg.sender] -= amt;
        require(balanceOf[from] >= amt, "bal");
        balanceOf[from] -= amt; balanceOf[to] += amt; return true;
    }
}
"""

FALSE_RETURN_TOGGLE_TOKEN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
contract FalseReturnToggleToken {
    string public name = "FR"; string public symbol = "FR"; uint8 public decimals = 6;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    bool public lying;
    function mint(address to, uint256 amt) external { balanceOf[to] += amt; totalSupply += amt; }
    function approve(address s, uint256 amt) external returns (bool) { allowance[msg.sender][s] = amt; return true; }
    function setLying(bool b) external { lying = b; }
    function transfer(address to, uint256 amt) external returns (bool) {
        if (lying) return false; // moves nothing, reports failure
        require(balanceOf[msg.sender] >= amt, "bal");
        balanceOf[msg.sender] -= amt; balanceOf[to] += amt; return true;
    }
    function transferFrom(address from, address to, uint256 amt) external returns (bool) {
        if (lying) return false;
        require(allowance[from][msg.sender] >= amt, "allow");
        allowance[from][msg.sender] -= amt;
        require(balanceOf[from] >= amt, "bal");
        balanceOf[from] -= amt; balanceOf[to] += amt; return true;
    }
}
"""

RETURN_BOMB_TOKEN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
contract ReturnBombToken {
    string public name = "Bm"; string public symbol = "BM"; uint8 public decimals = 6;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    bool public bomb;
    function mint(address to, uint256 amt) external { balanceOf[to] += amt; totalSupply += amt; }
    function approve(address s, uint256 amt) external returns (bool) { allowance[msg.sender][s] = amt; return true; }
    function setBomb(bool b) external { bomb = b; }
    // NOTE: declared to return bytes (same selector as transfer(address,uint256)).
    // The escrow calls it with the bool selector; dispatch matches on selector only.
    function transfer(address to, uint256 amt) external returns (bytes memory) {
        require(balanceOf[msg.sender] >= amt, "bal");
        balanceOf[msg.sender] -= amt; balanceOf[to] += amt;
        if (bomb) {
            bytes memory b = new bytes(100000);
            return b;
        }
        return "";
    }
    function transferFrom(address from, address to, uint256 amt) external returns (bool) {
        require(allowance[from][msg.sender] >= amt, "allow");
        allowance[from][msg.sender] -= amt;
        require(balanceOf[from] >= amt, "bal");
        balanceOf[from] -= amt; balanceOf[to] += amt; return true;
    }
}
"""

_TOKEN_SOURCES = {
    "StandardToken": STANDARD_TOKEN,
    "FeeToken": FEE_TOKEN,
    "ToggleToken": TOGGLE_TOKEN,
    "GasGriefToken": GAS_GRIEF_TOKEN,
    "NoReturnToken": NO_RETURN_TOKEN,
    "BlacklistToken": BLACKLIST_TOKEN,
    "RebaseToken": REBASE_TOKEN,
    "LyingToggleToken": LYING_TOGGLE_TOKEN,
    "FalseReturnToggleToken": FALSE_RETURN_TOGGLE_TOKEN,
    "ReturnBombToken": RETURN_BOMB_TOKEN,
    "NoOpToken": NOOP_TOKEN,
}


def _compile_all():
    out = {}
    for name, src in _TOKEN_SOURCES.items():
        compiled = solcx.compile_source(
            src, output_values=["abi", "bin"], solc_version="0.8.24",
            optimize=True, optimize_runs=200,
        )
        key = [k for k in compiled if name in k][0]
        out[name] = (compiled[key]["abi"], compiled[key]["bin"])
    return out


_TOKENS = _compile_all()


# ---------------------------------------------------------------- helpers

def _deploy_token(env, name, *args):
    abi, bin = _TOKENS[name]
    c = env.w3.eth.contract(abi=abi, bytecode=bin)
    txh = c.constructor(*args).transact({"from": env.funder, "gas": 3000000})
    rcpt = env.w3.eth.wait_for_transaction_receipt(txh)
    return env.w3.eth.contract(address=rcpt.contractAddress, abi=abi)


def _whitelist(env, token_addr):
    r = env.send_as(env.operator,
                    lambda: env.escrow.functions.setTokenAllowed(token_addr, True))
    assert r["status"] == 1, "whitelist failed"
    assert env.escrow.functions.allowedTokens(token_addr).call() is True


def _fund(env, token, acct, amount, approve=None):
    """Mint `amount` to acct and approve the escrow for it."""
    token.functions.mint(acct.address, amount).transact({"from": env.funder})
    env.send_as(acct, lambda: token.functions.approve(
        env.escrow_addr, amount if approve is None else approve))


def _ok(env, acct, fn_builder, label="", gas=500000):
    r = env.send_as(acct, fn_builder, gas=gas)
    assert r["status"] == 1, f"{label}: tx returned status 0"
    return r


def _assert_invariant(env, token_addr, label=""):
    bal, unsettled, bonded, pending, holds = (
        env.escrow.functions.settlementInvariant(token_addr).call())
    assert holds, (
        f"{label}: invariant broken bal={bal} unsettled={unsettled} "
        f"bonded={bonded} pending={pending}")
    return bal, unsettled, bonded, pending


def _credit(env, token_addr, acct_addr):
    return env.escrow.functions.pendingCredit(token_addr, acct_addr).call()


def _mk_job(env, token, amount=JOB, worker=None, review_window=3600, gas=500000):
    """Create a job funded in `token`. Returns jobId. `amount` is the
    requested amount; the stored amount is what actually arrived."""
    worker = worker or env.agent.address
    _fund(env, token, env.payer, amount)
    r = env.send_as(env.payer, lambda: env.escrow.functions.createJob(
        worker, token.address, amount, DEADLINE_SECONDS,
        review_window, "fault job"), gas=gas)
    assert r["status"] == 1, "createJob failed"
    return env.escrow.functions.jobCount().call() - 1


def _to_delivered(env, jid, worker_acct=None):
    worker_acct = worker_acct or env.agent
    _ok(env, worker_acct, lambda: env.escrow.functions.acceptJob(jid), "accept")
    _ok(env, worker_acct, lambda: env.escrow.functions.submitDelivery(
        jid, DH, "fault delivery"), "deliver")


def _dispute_by_payer(env, token, jid, amount):
    """Payer dispute: fund the bond, raise it. Returns the bond paid."""
    bond = bond_for(amount)
    _fund(env, token, env.payer, bond, approve=bond)
    _ok(env, env.payer, lambda: env.escrow.functions.raiseDispute(
        jid, "fault dispute"), "raiseDispute")
    return bond


def _dispute_by_agent(env, jid, worker_acct=None):
    worker_acct = worker_acct or env.agent
    _ok(env, worker_acct, lambda: env.escrow.functions.acceptJob(jid), "accept")
    _ok(env, worker_acct, lambda: env.escrow.functions.submitDeliveryAndDispute(
        jid, DH, "fault delivery", "agent dispute"), "deliver+dispute")


def _rule(env, jid, amount_to_worker):
    _ok(env, env.operator, lambda: env.escrow.functions.executeRuling(
        jid, amount_to_worker), "executeRuling")


def _partial(env, jid, amount_to_worker):
    """Worker-signed partial split submitted by the payer."""
    dl = env.deadline_in(86400)
    sig = env.sign_partial(env.agent, jid, amount_to_worker, dl)
    _ok(env, env.payer, lambda: env.escrow.functions.releasePartial(
        jid, amount_to_worker, dl, sig), "releasePartial")


def _past_valve(env, jid):
    disputed_at = env.job(jid)[14]
    env.time_travel_to(disputed_at + RULING_PERIOD + 1)


def _fresh_acct(env):
    from eth_account import Account
    acct = Account.create()
    env.w3.eth.send_transaction({
        "from": env.funder, "to": acct.address,
        "value": env.w3.to_wei(10, "ether"), "gas": 21000,
    })
    return acct


# ================================================================ T1: fee-on-transfer

class TestFeeToken:
    def test_fee_funding_nets_and_payout(self, env):
        """5% fee token: funding stores NET received; payout fee borne by
        worker; accounting exact; invariant holds."""
        fee = _deploy_token(env, "FeeToken", env.stranger.address)
        _whitelist(env, fee.address)
        fee.functions.setFees(True).transact({"from": env.funder})

        jid = _mk_job(env, fee, JOB)
        assert env.job(jid)[3] == 95 * 10**6, "job.amount should be net received"

        _to_delivered(env, jid)
        wb = fee.functions.balanceOf(env.agent.address).call()
        cb = fee.functions.balanceOf(env.stranger.address).call()
        _ok(env, env.payer, lambda: env.escrow.functions.release(jid), "release")
        # payout of 95e6 takes 5% -> worker gets 90.25e6, collector 4.75e6
        assert fee.functions.balanceOf(env.agent.address).call() - wb == 90_250_000
        assert fee.functions.balanceOf(env.stranger.address).call() - cb == 4_750_000
        assert env.state(jid) == RELEASED
        _assert_invariant(env, fee.address, "T1")

    def test_fee_partial_split_exact(self, env):
        """Partial split on a fee token: worker + payer shares sum to net."""
        fee = _deploy_token(env, "FeeToken", env.stranger.address)
        _whitelist(env, fee.address)
        fee.functions.setFees(True).transact({"from": env.funder})
        jid = _mk_job(env, fee, JOB)
        assert env.job(jid)[3] == 95 * 10**6
        _to_delivered(env, jid)
        wb = fee.functions.balanceOf(env.agent.address).call()
        pb = fee.functions.balanceOf(env.payer.address).call()
        _partial(env, jid, 50 * 10**6)
        # worker leg: 50e6 -> fee 2.5e6 -> 47.5e6 ; payer leg: 45e6 -> fee 2.25e6 -> 42.75e6
        assert fee.functions.balanceOf(env.agent.address).call() - wb == 47_500_000
        assert fee.functions.balanceOf(env.payer.address).call() - pb == 42_750_000
        _assert_invariant(env, fee.address, "T1-partial")

    def test_fee_bond_shortfall_blocks_payer_dispute(self, env):
        """The bond must arrive in full, so a fee token cannot post it:
        payer dispute reverts, job stays Delivered, no bond taken. An
        agent dispute (no bond) still works, and the ruling legs credit
        their fee shortfalls instead of stealing."""
        fee = _deploy_token(env, "FeeToken", env.stranger.address)
        _whitelist(env, fee.address)
        fee.functions.setFees(True).transact({"from": env.funder})
        jid = _mk_job(env, fee, JOB)  # stored amount 95e6
        _to_delivered(env, jid)
        bond = bond_for(95 * 10**6)
        _fund(env, fee, env.payer, bond, approve=bond)
        env.assert_reverts(env.payer, lambda: env.escrow.functions.raiseDispute(
            jid, "payer dispute"), "bond shortfall")
        assert env.state(jid) == DELIVERED
        assert env.job(jid)[13] == 0, "no bond taken on a failed dispute"
        assert env.escrow.functions.totalBonded(fee.address).call() == 0

        # Agent dispute needs no bond: works even with fees on.
        jid2 = _mk_job(env, fee, JOB)
        _dispute_by_agent(env, jid2)
        assert env.state(jid2) == DISPUTED
        assert env.job(jid2)[13] == 0
        wb = fee.functions.balanceOf(env.agent.address).call()
        _rule(env, jid2, 95 * 10**6)  # 100% to worker
        # Worker leg 95e6: the fee (4.75e6) is borne by the worker and
        # NOT credited — _payOrCredit measures escrow outflow, and the
        # full 95e6 left the escrow. Same documented behavior as V9.
        assert fee.functions.balanceOf(env.agent.address).call() - wb == 90_250_000
        assert _credit(env, fee.address, env.agent.address) == 0
        assert env.state(jid2) == RELEASED
        _assert_invariant(env, fee.address, "T1-bond")


# ================================================================ T2: reverting token

class TestRevertingToken:
    def test_toggle_funding_reverts_and_credit_withdraw(self, env):
        """Toggle token: funding while broken reverts cleanly (no job
        created); payout while broken credits instead of reverting;
        withdraw after heal; withdraw replay reverts."""
        t = _deploy_token(env, "ToggleToken")
        _whitelist(env, t.address)
        _fund(env, t, env.payer, 10**6)

        t.functions.setBroken(True).transact({"from": env.funder})
        env.assert_reverts(env.payer, lambda: env.escrow.functions.createJob(
            env.agent.address, t.address, 100 * 10**6, DEADLINE_SECONDS,
            3600, "fault job"), "funding failed")
        assert env.escrow.functions.jobCount().call() == 0, "broken funding must not create a job"

        t.functions.setBroken(False).transact({"from": env.funder})
        jid = _mk_job(env, t, JOB)
        _to_delivered(env, jid)

        t.functions.setBroken(True).transact({"from": env.funder})
        _ok(env, env.payer, lambda: env.escrow.functions.release(jid), "release-while-broken")
        assert env.state(jid) == RELEASED
        assert _credit(env, t.address, env.agent.address) == JOB

        env.assert_reverts(env.agent, lambda: env.escrow.functions.withdraw(
            t.address), "withdrawal failed")
        assert _credit(env, t.address, env.agent.address) == JOB, "credit preserved"

        t.functions.setBroken(False).transact({"from": env.funder})
        wb = t.functions.balanceOf(env.agent.address).call()
        _ok(env, env.agent, lambda: env.escrow.functions.withdraw(t.address), "withdraw-after-heal")
        assert t.functions.balanceOf(env.agent.address).call() - wb == JOB
        assert _credit(env, t.address, env.agent.address) == 0
        # Replay: nothing left to withdraw.
        env.assert_reverts(env.agent, lambda: env.escrow.functions.withdraw(
            t.address), "nothing to withdraw")
        _assert_invariant(env, t.address, "T2")

    def test_withdraw_replay_closes_phase2_gap(self, env):
        """Phase 2's honest gap: withdraw() replay with a real failing
        token. Credit via a broken-token payout; withdraw twice — the
        second reverts and moves nothing. (withdrawTo is gone: credits
        go to the account itself.)"""
        t = _deploy_token(env, "ToggleToken")
        _whitelist(env, t.address)
        jid = _mk_job(env, t, JOB)
        _to_delivered(env, jid)
        t.functions.setBroken(True).transact({"from": env.funder})
        _ok(env, env.payer, lambda: env.escrow.functions.release(jid), "release-while-broken")
        assert _credit(env, t.address, env.agent.address) == JOB
        t.functions.setBroken(False).transact({"from": env.funder})

        ab = t.functions.balanceOf(env.agent.address).call()
        _ok(env, env.agent, lambda: env.escrow.functions.withdraw(
            t.address), "withdraw")
        assert t.functions.balanceOf(env.agent.address).call() - ab == JOB
        assert _credit(env, t.address, env.agent.address) == 0
        env.assert_reverts(env.agent, lambda: env.escrow.functions.withdraw(
            t.address), "nothing to withdraw")
        assert t.functions.balanceOf(env.agent.address).call() - ab == JOB, "replay moved nothing"
        _assert_invariant(env, t.address, "T2-replay")


# ================================================================ T3: gas griefing

class TestGasGrief:
    def test_gas_grief(self, env):
        """Gas-burning token: release completes with enough gas; low-gas
        attempt reverts WITHOUT bricking the job (retryable)."""
        g = _deploy_token(env, "GasGriefToken")
        _whitelist(env, g.address)
        # Funding also runs the grief loop (transferFrom), so create
        # needs a high gas limit too — the default 500k runs out.
        jid = _mk_job(env, g, JOB, gas=10_000_000)
        _to_delivered(env, jid)

        rcpt = _ok(env, env.payer, lambda: env.escrow.functions.release(jid),
                 "release-grief", gas=10_000_000)
        print(f"\nT3 grief release gas used: {rcpt.gasUsed}")
        assert rcpt.gasUsed > 150_000, "grief loop should burn meaningful gas"
        assert env.state(jid) == RELEASED

        jid2 = _mk_job(env, g, JOB, gas=10_000_000)
        _to_delivered(env, jid2)
        r = env.send_as(env.payer, lambda: env.escrow.functions.release(jid2), gas=100_000)
        assert r["status"] == 0, "low-gas release must fail"
        assert env.state(jid2) == DELIVERED, "job must stay Delivered, retryable"
        _ok(env, env.payer, lambda: env.escrow.functions.release(jid2),
            "retry-with-gas", gas=10_000_000)
        assert env.state(jid2) == RELEASED
        _assert_invariant(env, g.address, "T3")


# ================================================================ T4: weird decimals

class TestWeirdDecimals:
    @pytest.mark.parametrize("decimals", [0, 24])
    def test_weird_decimals_rejected_at_whitelist(self, env, decimals):
        """0- and 24-decimal tokens can no longer be whitelisted: bond
        math (20%, min $1, max $50) and the review-window tiers are all
        6-decimal units, so a wrong-decimal token would make every
        amount economically wrong. The whitelist is the enforcement
        point — such a token can never fund a job."""
        s = _deploy_token(env, "StandardToken", decimals)
        env.assert_reverts(env.operator,
                           lambda: env.escrow.functions.setTokenAllowed(
                               s.address, True),
                           "token must be 6 decimals")
        assert env.escrow.functions.allowedTokens(s.address).call() is False
        # And the job cannot be funded with it either way.
        env.assert_reverts(env.payer,
                           lambda: env.escrow.functions.createJob(
                               env.agent.address, s.address, 999, 3600, 3600, "x"),
                           "token not allowed")


# ================================================================ T5: no-return token

class TestNoReturnToken:
    def test_no_return_token(self, env):
        """USDT-style token (no return value): full flow + agent dispute
        + operator ruling work."""
        n = _deploy_token(env, "NoReturnToken")
        _whitelist(env, n.address)

        jid = _mk_job(env, n, JOB)
        _to_delivered(env, jid)
        wb = n.functions.balanceOf(env.agent.address).call()
        _ok(env, env.payer, lambda: env.escrow.functions.release(jid), "release")
        assert n.functions.balanceOf(env.agent.address).call() - wb == JOB

        jid2 = _mk_job(env, n, JOB)
        _dispute_by_agent(env, jid2)
        wb2 = n.functions.balanceOf(env.agent.address).call()
        _rule(env, jid2, JOB)
        assert n.functions.balanceOf(env.agent.address).call() - wb2 == JOB
        assert env.state(jid2) == RELEASED
        _assert_invariant(env, n.address, "T5")


# ================================================================ T6: blacklisting

class TestBlacklistToken:
    def test_blacklist_worker_credit_and_withdraw_after_unblacklist(self, env):
        """Blacklisted worker mid-job: release credits (no revert).
        Withdraw to self fails while blacklisted and the credit is
        preserved; after unblacklisting, withdraw recovers it and
        replay reverts. (withdrawTo is gone: a blacklisted account
        recovers only once it can receive again.)"""
        b = _deploy_token(env, "BlacklistToken")
        _whitelist(env, b.address)

        jid = _mk_job(env, b, JOB)
        _to_delivered(env, jid)
        b.functions.setBlacklisted(env.agent.address, True).transact({"from": env.funder})
        _ok(env, env.payer, lambda: env.escrow.functions.release(jid), "release-blacklisted-worker")
        assert env.state(jid) == RELEASED
        assert _credit(env, b.address, env.agent.address) == JOB

        env.assert_reverts(env.agent, lambda: env.escrow.functions.withdraw(
            b.address), "withdrawal failed")
        assert _credit(env, b.address, env.agent.address) == JOB
        b.functions.setBlacklisted(env.agent.address, False).transact({"from": env.funder})
        ab = b.functions.balanceOf(env.agent.address).call()
        _ok(env, env.agent, lambda: env.escrow.functions.withdraw(
            b.address), "withdraw-after-unblacklist")
        assert b.functions.balanceOf(env.agent.address).call() - ab == JOB
        assert _credit(env, b.address, env.agent.address) == 0
        env.assert_reverts(env.agent, lambda: env.escrow.functions.withdraw(
            b.address), "nothing to withdraw")
        _assert_invariant(env, b.address, "T6-worker")

    def test_blacklist_payer_refund_and_dispute_reverts(self, env):
        """Blacklisted payer: cancel past the deadline credits, recoverable
        by withdraw after unblacklisting. Blacklisted payer cannot dispute
        — the bond pull fails, so the dispute reverts and the job stays
        Delivered."""
        b = _deploy_token(env, "BlacklistToken")
        _whitelist(env, b.address)

        jid = _mk_job(env, b, JOB)
        _ok(env, env.agent, lambda: env.escrow.functions.acceptJob(jid), "accept")
        b.functions.setBlacklisted(env.payer.address, True).transact({"from": env.funder})
        job = env.job(jid)
        env.time_travel_to(job[4] + 1)  # deadline + 1
        _ok(env, env.payer, lambda: env.escrow.functions.cancel(jid),
            "refund-blacklisted-payer")
        assert env.state(jid) == REFUNDED
        assert _credit(env, b.address, env.payer.address) == JOB
        b.functions.setBlacklisted(env.payer.address, False).transact({"from": env.funder})
        pb = b.functions.balanceOf(env.payer.address).call()
        _ok(env, env.payer, lambda: env.escrow.functions.withdraw(
            b.address), "payer-withdraw")
        assert b.functions.balanceOf(env.payer.address).call() - pb == JOB

        # Payer blacklisted mid-delivery: dispute reverts (bond pull fails).
        b.functions.setBlacklisted(env.payer.address, False).transact({"from": env.funder})
        jid2 = _mk_job(env, b, JOB)
        _to_delivered(env, jid2)
        b.functions.setBlacklisted(env.payer.address, True).transact({"from": env.funder})
        bond = bond_for(JOB)
        _fund(env, b, env.payer, bond, approve=bond)
        env.assert_reverts(env.payer, lambda: env.escrow.functions.raiseDispute(
            jid2, "dispute"), "funding failed")
        assert env.state(jid2) == DELIVERED
        assert env.job(jid2)[13] == 0
        _assert_invariant(env, b.address, "T6-payer")


# ================================================================ T7: rebasing

class TestRebaseToken:
    def test_rebase_up(self, env):
        """Rebase UP: worker paid exactly job.amount; surplus stuck, not
        stealable. V3's invariant is >= (not V9's ==), so the surplus
        does NOT break it — the honest report is that it holds."""
        r = _deploy_token(env, "RebaseToken")
        _whitelist(env, r.address)

        jid = _mk_job(env, r, JOB)
        _to_delivered(env, jid)
        r.functions.rebase(2 * 10**18).transact({"from": env.funder})
        assert r.functions.balanceOf(env.escrow_addr).call() == 2 * JOB
        wb = r.functions.balanceOf(env.agent.address).call()
        _ok(env, env.payer, lambda: env.escrow.functions.release(jid), "release-rebase-up")
        assert r.functions.balanceOf(env.agent.address).call() - wb == JOB, "worker paid exactly job.amount"
        assert r.functions.balanceOf(env.escrow_addr).call() == JOB, "surplus stuck, not paid out"
        bal, u, bnd, c, holds = env.escrow.functions.settlementInvariant(r.address).call()
        assert bal == JOB and u == 0 and bnd == 0 and c == 0 and holds, \
            "V3 >= invariant holds with the surplus present"
        _assert_invariant(env, r.address, "T7-up")

    def test_rebase_down(self, env):
        """Rebase DOWN: payout reverts internally -> full credit; withdraw
        works after rebase restores."""
        r = _deploy_token(env, "RebaseToken")
        _whitelist(env, r.address)

        jid = _mk_job(env, r, JOB)
        _to_delivered(env, jid)
        r.functions.rebase(5 * 10**17).transact({"from": env.funder})
        assert r.functions.balanceOf(env.escrow_addr).call() == JOB // 2
        _ok(env, env.payer, lambda: env.escrow.functions.release(jid), "release-rebase-down")
        assert env.state(jid) == RELEASED
        assert _credit(env, r.address, env.agent.address) == JOB, "full credit, nothing lost"
        env.assert_reverts(env.agent, lambda: env.escrow.functions.withdraw(
            r.address), "withdrawal failed")
        assert _credit(env, r.address, env.agent.address) == JOB, "credit preserved"
        r.functions.rebase(10**18).transact({"from": env.funder})
        wb = r.functions.balanceOf(env.agent.address).call()
        _ok(env, env.agent, lambda: env.escrow.functions.withdraw(r.address), "withdraw-after-restore")
        assert r.functions.balanceOf(env.agent.address).call() - wb == JOB
        _assert_invariant(env, r.address, "T7-down")

    def test_rebase_up_payer_dispute_bond_posts(self, env):
        """Rebase UP before a payer dispute: the bond still posts exactly
        (balance-delta measured in nominal units)."""
        r = _deploy_token(env, "RebaseToken")
        _whitelist(env, r.address)
        # Ample shares so the bond pull cannot fail on share math.
        r.functions.mint(env.payer.address, 10**12).transact({"from": env.funder})
        jid = _mk_job(env, r, JOB)
        _to_delivered(env, jid)
        r.functions.rebase(2 * 10**18).transact({"from": env.funder})
        bond = _dispute_by_payer(env, r, jid, JOB)
        assert bond == bond_for(JOB)
        assert env.job(jid)[13] == bond
        assert env.escrow.functions.totalBonded(r.address).call() == bond
        _assert_invariant(env, r.address, "T7-bond")


# ================================================================ T8: pausable mid-dispute

class TestPausableToken:
    def test_pausable_agent_dispute_ruling_credits(self, env):
        """Token frozen mid-dispute: the operator's ruling credits (no
        revert); unfreeze -> withdraw works; replay reverts."""
        t = _deploy_token(env, "ToggleToken")
        _whitelist(env, t.address)
        jid = _mk_job(env, t, JOB)
        _dispute_by_agent(env, jid)
        t.functions.setBroken(True).transact({"from": env.funder})
        _ok(env, env.operator, lambda: env.escrow.functions.executeRuling(
            jid, JOB), "ruling-while-frozen")
        assert env.state(jid) == RELEASED
        assert _credit(env, t.address, env.agent.address) == JOB
        t.functions.setBroken(False).transact({"from": env.funder})
        wb = t.functions.balanceOf(env.agent.address).call()
        _ok(env, env.agent, lambda: env.escrow.functions.withdraw(t.address), "withdraw-after-unpause")
        assert t.functions.balanceOf(env.agent.address).call() - wb == JOB
        env.assert_reverts(env.agent, lambda: env.escrow.functions.withdraw(
            t.address), "nothing to withdraw")
        _assert_invariant(env, t.address, "T8")

    def test_pausable_payer_dispute_reverts(self, env):
        """Payer dispute while frozen: the bond pull fails, so the
        dispute reverts and the job stays Delivered. After unfreeze the
        dispute works."""
        t = _deploy_token(env, "ToggleToken")
        _whitelist(env, t.address)
        jid = _mk_job(env, t, JOB)
        _to_delivered(env, jid)
        t.functions.setBroken(True).transact({"from": env.funder})
        bond = bond_for(JOB)
        _fund(env, t, env.payer, bond, approve=bond)
        env.assert_reverts(env.payer, lambda: env.escrow.functions.raiseDispute(
            jid, "dispute"), "funding failed")
        assert env.state(jid) == DELIVERED
        t.functions.setBroken(False).transact({"from": env.funder})
        _ok(env, env.payer, lambda: env.escrow.functions.raiseDispute(
            jid, "dispute"), "dispute-after-unpause")
        assert env.state(jid) == DISPUTED
        assert env.job(jid)[13] == bond
        _assert_invariant(env, t.address, "T8-payer")


# ================================================================ T9: EOA as token

class TestEoaToken:
    def test_unwhitelisted_token_reverts(self, env):
        """A token the operator never whitelisted cannot fund a job."""
        s = _deploy_token(env, "StandardToken", 18)
        # Deliberately NOT whitelisted.
        _fund(env, s, env.payer, JOB)
        env.assert_reverts(env.payer, lambda: env.escrow.functions.createJob(
            env.agent.address, s.address, JOB, DEADLINE_SECONDS,
            3600, "fault job"), "token not allowed")
        assert env.escrow.functions.jobCount().call() == 0

    def test_eoa_as_token_reverts(self, env):
        """Using an EOA (no code) as the token: the whitelist rejects it
        outright ("token must be 6 decimals") — an EOA has no decimals()
        to read. It can never fund a job, so no state change is possible."""
        fresh = _fresh_acct(env)
        env.assert_reverts(env.operator,
                           lambda: env.escrow.functions.setTokenAllowed(
                               fresh.address, True),
                           "token must be 6 decimals")
        assert env.escrow.functions.allowedTokens(fresh.address).call() is False
        env.assert_reverts(env.payer, lambda: env.escrow.functions.createJob(
            env.agent.address, fresh.address, JOB, DEADLINE_SECONDS,
            3600, "fault job"), "token not allowed")
        assert env.escrow.functions.jobCount().call() == 0


# ================================================================ T10: lying tokens

class TestLyingTokens:
    def test_lying_token(self, env):
        """Token returns true but moves nothing: balance check catches
        the lie, full credit issued; withdraw works once honest; replay
        reverts."""
        ly = _deploy_token(env, "LyingToggleToken")
        _whitelist(env, ly.address)
        jid = _mk_job(env, ly, JOB)
        _to_delivered(env, jid)
        ly.functions.setLying(True).transact({"from": env.funder})
        _ok(env, env.payer, lambda: env.escrow.functions.release(jid), "release-lying")
        assert env.state(jid) == RELEASED
        assert _credit(env, ly.address, env.agent.address) == JOB
        assert ly.functions.balanceOf(env.agent.address).call() == 0, "nothing actually moved"
        env.assert_reverts(env.agent, lambda: env.escrow.functions.withdraw(
            ly.address), "withdrawal failed")
        assert _credit(env, ly.address, env.agent.address) == JOB, "credit preserved"
        ly.functions.setLying(False).transact({"from": env.funder})
        wb = ly.functions.balanceOf(env.agent.address).call()
        _ok(env, env.agent, lambda: env.escrow.functions.withdraw(ly.address), "withdraw")
        assert ly.functions.balanceOf(env.agent.address).call() - wb == JOB
        env.assert_reverts(env.agent, lambda: env.escrow.functions.withdraw(
            ly.address), "nothing to withdraw")
        _assert_invariant(env, ly.address, "T10")

    def test_false_return_token(self, env):
        """Token returns false and moves nothing: funding while lying
        reverts; payout while lying credits; honest again -> withdraw."""
        fr = _deploy_token(env, "FalseReturnToggleToken")
        _whitelist(env, fr.address)
        fr.functions.setLying(True).transact({"from": env.funder})
        _fund(env, fr, env.payer, JOB)
        env.assert_reverts(env.payer, lambda: env.escrow.functions.createJob(
            env.agent.address, fr.address, JOB, DEADLINE_SECONDS,
            3600, "fault job"), "funding failed")
        assert env.escrow.functions.jobCount().call() == 0

        fr.functions.setLying(False).transact({"from": env.funder})
        jid = _mk_job(env, fr, JOB)
        _to_delivered(env, jid)
        fr.functions.setLying(True).transact({"from": env.funder})
        _ok(env, env.payer, lambda: env.escrow.functions.release(jid), "release-false-return")
        assert env.state(jid) == RELEASED
        assert _credit(env, fr.address, env.agent.address) == JOB
        fr.functions.setLying(False).transact({"from": env.funder})
        wb = fr.functions.balanceOf(env.agent.address).call()
        _ok(env, env.agent, lambda: env.escrow.functions.withdraw(fr.address), "withdraw")
        assert fr.functions.balanceOf(env.agent.address).call() - wb == JOB
        _assert_invariant(env, fr.address, "T10b")


# ================================================================ T11: cross-job contamination

class TestCrossJobContamination:
    def test_cross_job_contamination(self, env):
        """A weird token's job cannot affect accounting of other tokens'
        jobs."""
        std = _deploy_token(env, "StandardToken", 6)
        fee = _deploy_token(env, "FeeToken", env.stranger.address)
        for tok in (std, fee):
            _whitelist(env, tok.address)
        fee.functions.setFees(True).transact({"from": env.funder})

        ja = _mk_job(env, std, JOB)
        jb = _mk_job(env, fee, JOB)  # net 95e6 in escrow
        _to_delivered(env, jb)
        wb = fee.functions.balanceOf(env.agent.address).call()
        _ok(env, env.payer, lambda: env.escrow.functions.release(jb), "release-fee-job")
        assert fee.functions.balanceOf(env.agent.address).call() - wb == 90_250_000

        _to_delivered(env, ja)
        wb2 = std.functions.balanceOf(env.agent.address).call()
        _ok(env, env.payer, lambda: env.escrow.functions.release(ja), "release-std-job")
        assert std.functions.balanceOf(env.agent.address).call() - wb2 == JOB, "normal job exact"

        # broken-token job credited while a normal job settles alongside
        tgl = _deploy_token(env, "ToggleToken")
        _whitelist(env, tgl.address)
        worker2 = _fresh_acct(env)
        jc = _mk_job(env, tgl, JOB)
        jd = _mk_job(env, std, JOB, worker=worker2.address)
        _to_delivered(env, jc)
        _ok(env, worker2, lambda: env.escrow.functions.acceptJob(jd), "accept-jd")
        _ok(env, worker2, lambda: env.escrow.functions.submitDelivery(
            jd, DH, "fault delivery"), "deliver-jd")
        tgl.functions.setBroken(True).transact({"from": env.funder})
        _ok(env, env.payer, lambda: env.escrow.functions.release(jc), "release-broken-credited")
        assert _credit(env, tgl.address, env.agent.address) == JOB
        w2b = std.functions.balanceOf(worker2.address).call()
        _ok(env, env.payer, lambda: env.escrow.functions.release(jd), "release-std-alongside")
        assert std.functions.balanceOf(worker2.address).call() - w2b == JOB

        for tok in (std.address, fee.address, tgl.address):
            _assert_invariant(env, tok, f"T11-{tok[:10]}")


# ================================================================ T12: fee-to-payer

class TestFeeToPayer:
    def test_fee_to_payer(self, env):
        """Malicious payer token (fees to payer): job.amount is NET
        on-chain, so the worker sees the true amount before accepting.
        Accounting exact."""
        fee = _deploy_token(env, "FeeToken", env.payer.address)  # fees flow back to the payer
        _whitelist(env, fee.address)
        fee.functions.setFees(True).transact({"from": env.funder})
        jid = _mk_job(env, fee, JOB)
        assert env.job(jid)[3] == 95 * 10**6, "on-chain amount is net of fee — transparent to worker"
        # The payer minted JOB and got the 5e6 fee back: net outlay 95e6.
        assert JOB - fee.functions.balanceOf(env.payer.address).call() == 95 * 10**6, \
            "payer net outlay 95e6, got 5e6 fee"
        _to_delivered(env, jid)
        wb = fee.functions.balanceOf(env.agent.address).call()
        _ok(env, env.payer, lambda: env.escrow.functions.release(jid), "release")
        assert fee.functions.balanceOf(env.agent.address).call() - wb == 90_250_000
        _assert_invariant(env, fee.address, "T12")


# ================================================================ T13: return bomb

class TestReturnBomb:
    def test_return_bomb_release_bounded_gas(self, env):
        """Token returning 100KB: 32-byte output cap bounds gas; balance
        check treats the moved funds as paid despite garbage returndata."""
        rb = _deploy_token(env, "ReturnBombToken")
        _whitelist(env, rb.address)
        jid = _mk_job(env, rb, JOB)
        _to_delivered(env, jid)
        rb.functions.setBomb(True).transact({"from": env.funder})
        wb = rb.functions.balanceOf(env.agent.address).call()
        rcpt = _ok(env, env.payer, lambda: env.escrow.functions.release(jid),
                 "release-bomb", gas=10_000_000)
        print(f"\nT13 return-bomb release gas used: {rcpt.gasUsed}")
        assert rcpt.gasUsed < 3_000_000, "gas must stay bounded despite 100KB returndata"
        assert rb.functions.balanceOf(env.agent.address).call() - wb == JOB, "funds moved -> paid"
        assert _credit(env, rb.address, env.agent.address) == 0, "no credit: paid"
        assert env.state(jid) == RELEASED
        _assert_invariant(env, rb.address, "T13")

    def test_return_bomb_funding_unaffected(self, env):
        """The bomb lives in `transfer`, not `transferFrom`: funding
        while the bomb is on succeeds normally and the job is created
        in full. Only payouts (transfer) ever see the bomb."""
        rb = _deploy_token(env, "ReturnBombToken")
        _whitelist(env, rb.address)
        rb.functions.setBomb(True).transact({"from": env.funder})
        jid = _mk_job(env, rb, JOB)
        assert env.job(jid)[3] == JOB
        _assert_invariant(env, rb.address, "T13-funding")


# ================================================================ T14: split with one failed leg

class TestSplitOneFailedLeg:
    def test_split_worker_leg_credits_payer_leg_pays(self, env):
        """Split where the worker leg fails and the payer leg succeeds:
        worker blacklisted, payer clean. Worker leg credits in full,
        payer leg pays out. Unblacklist -> worker withdraws the credit;
        replay reverts. (A fee token can never create a credit — the
        fee is borne by the recipient, measured on escrow outflow —
        so the withdraw trap is tested here with a blacklisting token
        instead.)"""
        b = _deploy_token(env, "BlacklistToken")
        _whitelist(env, b.address)
        jid = _mk_job(env, b, JOB)
        _to_delivered(env, jid)
        b.functions.setBlacklisted(env.agent.address, True).transact({"from": env.funder})
        pb = b.functions.balanceOf(env.payer.address).call()
        _partial(env, jid, 50 * 10**6)
        assert env.state(jid) == RELEASED
        assert _credit(env, b.address, env.agent.address) == 50 * 10**6, "worker leg credited"
        assert b.functions.balanceOf(env.payer.address).call() - pb == 50 * 10**6, "payer leg paid"
        b.functions.setBlacklisted(env.agent.address, False).transact({"from": env.funder})
        wb = b.functions.balanceOf(env.agent.address).call()
        _ok(env, env.agent, lambda: env.escrow.functions.withdraw(b.address), "withdraw")
        assert b.functions.balanceOf(env.agent.address).call() - wb == 50 * 10**6
        assert _credit(env, b.address, env.agent.address) == 0
        env.assert_reverts(env.agent, lambda: env.escrow.functions.withdraw(
            b.address), "nothing to withdraw")
        _assert_invariant(env, b.address, "T14")


# ================================================================ T15: ruling + valve, broken token

class TestRulingValveBroken:
    def test_ruling_while_broken_credits_all_legs(self, env):
        """Operator ruling while the token is frozen: worker leg, payer
        leg, AND bond leg all credit (nothing reverts, nothing lost).
        Unfreeze -> withdraw each; replay reverts."""
        t = _deploy_token(env, "ToggleToken")
        _whitelist(env, t.address)
        jid = _mk_job(env, t, JOB)
        _to_delivered(env, jid)
        bond = _dispute_by_payer(env, t, jid, JOB)
        assert bond == bond_for(JOB) == 20 * 10**6
        t.functions.setBroken(True).transact({"from": env.funder})
        _rule(env, jid, 60 * 10**6)  # 60% to worker -> bond to worker
        assert env.state(jid) == RELEASED
        assert _credit(env, t.address, env.agent.address) == 80 * 10**6, "worker leg + bond"
        assert _credit(env, t.address, env.payer.address) == 40 * 10**6, "payer leg"
        env.assert_reverts(env.agent, lambda: env.escrow.functions.withdraw(
            t.address), "withdrawal failed")
        assert _credit(env, t.address, env.agent.address) == 80 * 10**6
        t.functions.setBroken(False).transact({"from": env.funder})
        wb = t.functions.balanceOf(env.agent.address).call()
        _ok(env, env.agent, lambda: env.escrow.functions.withdraw(t.address), "worker-withdraw")
        assert t.functions.balanceOf(env.agent.address).call() - wb == 80 * 10**6
        pb = t.functions.balanceOf(env.payer.address).call()
        _ok(env, env.payer, lambda: env.escrow.functions.withdraw(t.address), "payer-withdraw")
        assert t.functions.balanceOf(env.payer.address).call() - pb == 40 * 10**6
        env.assert_reverts(env.agent, lambda: env.escrow.functions.withdraw(
            t.address), "nothing to withdraw")
        # Ruling replay reverts (job left Disputed).
        env.assert_reverts(env.operator, lambda: env.escrow.functions.executeRuling(
            jid, 60 * 10**6), "not disputed")
        _assert_invariant(env, t.address, "T15-ruling")

    def test_valve_while_broken_credits(self, env):
        """72h valve while the token is frozen: job + bond credit to the
        payer in full. Unfreeze -> withdraw; valve replay reverts."""
        t = _deploy_token(env, "ToggleToken")
        _whitelist(env, t.address)
        jid = _mk_job(env, t, JOB)
        _to_delivered(env, jid)
        bond = _dispute_by_payer(env, t, jid, JOB)
        t.functions.setBroken(True).transact({"from": env.funder})
        _past_valve(env, jid)
        _ok(env, env.stranger, lambda: env.escrow.functions.refundDisputeTimeout(jid),
            "valve-while-broken")
        assert env.state(jid) == REFUNDED
        assert _credit(env, t.address, env.payer.address) == JOB + bond
        t.functions.setBroken(False).transact({"from": env.funder})
        pb = t.functions.balanceOf(env.payer.address).call()
        _ok(env, env.payer, lambda: env.escrow.functions.withdraw(t.address), "withdraw")
        assert t.functions.balanceOf(env.payer.address).call() - pb == JOB + bond
        env.assert_reverts(env.payer, lambda: env.escrow.functions.withdraw(
            t.address), "nothing to withdraw")
        env.assert_reverts(env.stranger, lambda: env.escrow.functions.refundDisputeTimeout(
            jid), "not disputed")
        _assert_invariant(env, t.address, "T15-valve")


# ================================================================ T16: settle, broken token

class TestSettleBroken:
    def test_settle_while_broken_credits_all_legs(self, env):
        """Mutual settle while the token is frozen: worker leg, payer
        leg, and the bond (back to the payer) all credit. Unfreeze ->
        withdraw both; settle replay reverts."""
        t = _deploy_token(env, "ToggleToken")
        _whitelist(env, t.address)
        jid = _mk_job(env, t, JOB)
        _to_delivered(env, jid)
        bond = _dispute_by_payer(env, t, jid, JOB)
        t.functions.setBroken(True).transact({"from": env.funder})
        dl = env.deadline_in(86400)
        sig = env.sign_settle(env.agent, jid, 40 * 10**6, dl)
        _ok(env, env.payer, lambda: env.escrow.functions.settleByAgreement(
            jid, 40 * 10**6, dl, sig), "settle-while-broken")
        assert env.state(jid) == RELEASED
        assert _credit(env, t.address, env.agent.address) == 40 * 10**6, "worker leg"
        assert _credit(env, t.address, env.payer.address) == 60 * 10**6 + bond, \
            "payer leg + bond back"
        t.functions.setBroken(False).transact({"from": env.funder})
        wb = t.functions.balanceOf(env.agent.address).call()
        _ok(env, env.agent, lambda: env.escrow.functions.withdraw(t.address), "worker-withdraw")
        assert t.functions.balanceOf(env.agent.address).call() - wb == 40 * 10**6
        pb = t.functions.balanceOf(env.payer.address).call()
        _ok(env, env.payer, lambda: env.escrow.functions.withdraw(t.address), "payer-withdraw")
        assert t.functions.balanceOf(env.payer.address).call() - pb == 60 * 10**6 + bond
        env.assert_reverts(env.agent, lambda: env.escrow.functions.withdraw(
            t.address), "nothing to withdraw")
        # Settle replay reverts (job left Disputed).
        dl2 = env.deadline_in(86400)
        sig2 = env.sign_settle(env.agent, jid, 40 * 10**6, dl2)
        env.assert_reverts(env.payer, lambda: env.escrow.functions.settleByAgreement(
            jid, 40 * 10**6, dl2, sig2), "not disputed")
        _assert_invariant(env, t.address, "T16")
