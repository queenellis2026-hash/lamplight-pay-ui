#!/usr/bin/env python3
"""
Phase 1: Hypothesis RuleBasedStateMachine for AgentEscrowV3.

Adapted from test_v9_state_machine.py (V9, 2-of-3 arbiter panel) for V3
(AI Judge). V3 has no arbiters: disputes resolve by operator-executed
ruling, mutual settle, or the 72h refund valve. New money paths vs V9:
the 20% dispute bond (min $1, max $50), bond routing on ruling / settle /
valve, tiered review windows, operator-managed USD-only whitelist.

Runs the real V3 bytecode on local PyEVM (eth-tester) with full time
control. One module-level deployment; each Hypothesis example reverts to
a snapshot taken after setup.

Timing model (verified empirically against eth-tester): every mined tx
lands exactly 1s after the latest block. A rule therefore predicts
validity with execution time = latest block ts + 1, and reads model
timestamps (deadline, deliveredAt, disputedAt) from the receipt block
AFTER the tx mines.

Invariants (checked after every step):
  I1 fund conservation: settlementInvariant(token).holds == True
      (balance >= unsettled + bonded + pending credits)
  I2 unsettled accounting: totalUnsettled == manual scan of model
  I2b bonded accounting: totalBonded == sum of bonds on Disputed jobs
  I2c credit accounting: totalPendingCredits == sum of on-chain pull
      credits over every known account
  I3 state fidelity: on-chain (state, amount, deadline, reviewWindow,
      deliveredAt, deadlineSeconds, bondAmount, disputedAt, agent) == model
  I4 whitelist fidelity: allowedTokens(token) == model flag
  (deadline semantics are pinned by I3: deadline is 0 before accept,
  accept_ts + deadlineSeconds after)
"""

import json
import os
from collections import Counter

import pytest
import solcx
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_tester import EthereumTester, PyEVMBackend
from hypothesis import HealthCheck, settings
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule
from hypothesis import strategies as st
from web3 import Web3
from web3.providers.eth_tester import EthereumTesterProvider

from conftest import (
    ACCEPTED, BOND_MAX, BOND_MIN, CANCELLED, CREATED, DELIVERED, DISPUTED,
    MOCK_ERC20_SOURCE, REFUNDED, RELEASED, bond_for,
)

RULE_HITS = Counter()
STATES_REACHED = set()

RULING_PERIOD = 72 * 3600
MAXU = 2**256 - 1
NONTERMINAL = (CREATED, ACCEPTED, DELIVERED, DISPUTED)
TIER1_MAX_AMOUNT = 10_000_000   # $10
TIER2_MAX_AMOUNT = 100_000_000  # $100
TIER1_MAX_WINDOW = 24 * 3600
TIER2_MAX_WINDOW = 72 * 3600
TIER3_MAX_WINDOW = 7 * 86400
MIN_REVIEW_WINDOW = 3600
MAX_JOBS = 25

MAX_EXAMPLES = int(os.environ.get("V3_PROP_EXAMPLES", "25"))
STEP_COUNT = int(os.environ.get("V3_PROP_STEPS", "40"))

ZERO_ADDR = "0x0000000000000000000000000000000000000000"

solcx.set_solc_version("0.8.24")

_tester = EthereumTester(PyEVMBackend())
w3 = Web3(EthereumTesterProvider(_tester))
CHAIN_ID = w3.eth.chain_id
FUNDER = w3.eth.accounts[0]

OPERATOR = Account.create()
PAYER_A, PAYER_B = Account.create(), Account.create()
WORKER_A, WORKER_B, WORKER_C = Account.create(), Account.create(), Account.create()
STRANGER = Account.create()
LOCALS = [OPERATOR, PAYER_A, PAYER_B, WORKER_A, WORKER_B, WORKER_C, STRANGER]
PAYERS = [PAYER_A, PAYER_B]
WORKERS = [WORKER_A, WORKER_B, WORKER_C]
EVERYONE = PAYERS + WORKERS + [OPERATOR, STRANGER]
ALL_ACCOUNTS = EVERYONE + [FUNDER]


def _send_raw(acct, fn_builder, gas=500000):
    tx = fn_builder().build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "gas": gas,
        "gasPrice": w3.eth.gas_price,
        "chainId": CHAIN_ID,
    })
    signed = acct.sign_transaction(tx)
    h = w3.eth.send_raw_transaction(signed.raw_transaction)
    return w3.eth.wait_for_transaction_receipt(h)


for _a in LOCALS:
    w3.eth.send_transaction({
        "from": FUNDER, "to": _a.address,
        "value": w3.to_wei(10, "ether"), "gas": 21000,
    })

_compiled = solcx.compile_source(
    MOCK_ERC20_SOURCE, output_values=["abi", "bin"], solc_version="0.8.24")
_t_data = _compiled["<stdin>:MockToken"]
_Token = w3.eth.contract(abi=_t_data["abi"], bytecode=_t_data["bin"])
_tx = _Token.constructor().transact({"from": FUNDER, "gas": 2000000})
TOKEN_ADDR = w3.eth.wait_for_transaction_receipt(_tx).contractAddress
token = w3.eth.contract(address=TOKEN_ADDR, abi=_t_data["abi"])

_build_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "contracts", "build-AgentEscrowV3.json")
with open(_build_path) as _f:
    _build = json.load(_f)
_Escrow = w3.eth.contract(abi=_build["abi"], bytecode=_build["bytecode"])
_tx = _Escrow.constructor(OPERATOR.address).transact(
    {"from": FUNDER, "gas": 8000000})
ESCROW_ADDR = w3.eth.wait_for_transaction_receipt(_tx).contractAddress
escrow = w3.eth.contract(address=ESCROW_ADDR, abi=_build["abi"])

MINT = 10**15
for _p in PAYERS:
    token.functions.mint(_p.address, MINT).transact({"from": FUNDER})
    _r = _send_raw(_p, lambda: token.functions.approve(ESCROW_ADDR, MAXU),
                   gas=100000)
    assert _r["status"] == 1, "payer approval failed in setup"

_r = _send_raw(OPERATOR,
               lambda: escrow.functions.setTokenAllowed(TOKEN_ADDR, True))
assert _r["status"] == 1, "token whitelist failed in setup"
assert escrow.functions.allowedTokens(TOKEN_ADDR).call() is True
assert escrow.functions.operator().call() == OPERATOR.address

SNAPSHOT = w3.provider.make_request("evm_snapshot", [])["result"]


def _revert():
    w3.provider.make_request("evm_revert", [SNAPSHOT])


# ---------------------------------------------------------------- EIP-712

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_N_HALF = SECP256K1_N // 2


def _normalize_sig(sig_bytes):
    r = int.from_bytes(sig_bytes[0:32], "big")
    s = int.from_bytes(sig_bytes[32:64], "big")
    v = sig_bytes[64]
    if s > SECP256K1_N_HALF:
        s = SECP256K1_N - s
        v = 28 if v == 27 else 27
    return r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([v])


def _sign(acct, primary_type, type_fields, message):
    td = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            primary_type: type_fields,
        },
        "primaryType": primary_type,
        "domain": {
            "name": "AgentEscrowV3",
            "version": "1",
            "chainId": CHAIN_ID,
            "verifyingContract": ESCROW_ADDR,
        },
        "message": message,
    }
    raw = acct.sign_message(encode_typed_data(full_message=td)).signature
    return _normalize_sig(raw)


def _sign_partial(acct, job_id, amount, deadline):
    return _sign(acct, "PartialRelease", [
        {"name": "jobId", "type": "uint256"},
        {"name": "amountToWorker", "type": "uint256"},
        {"name": "deadline", "type": "uint256"},
    ], {"jobId": job_id, "amountToWorker": amount, "deadline": deadline})


def _sign_settle(acct, job_id, amount, deadline):
    return _sign(acct, "SettleDispute", [
        {"name": "jobId", "type": "uint256"},
        {"name": "amountToWorker", "type": "uint256"},
        {"name": "deadline", "type": "uint256"},
    ], {"jobId": job_id, "amountToWorker": amount, "deadline": deadline})


def _tier_max_window(amount):
    if amount < TIER1_MAX_AMOUNT:
        return TIER1_MAX_WINDOW
    if amount <= TIER2_MAX_AMOUNT:
        return TIER2_MAX_WINDOW
    return TIER3_MAX_WINDOW


# ---------------------------------------------------------------- machine


class V3Machine(RuleBasedStateMachine):
    def __init__(self):
        super().__init__()
        _revert()
        self.now = w3.eth.get_block("latest").timestamp
        self.model = {}  # job_id -> dict
        self.by_state = {s: [] for s in range(7)}
        self.token_allowed = True

    def teardown(self):
        _revert()

    # -- helpers ----------------------------------------------------

    def _ts(self, rcpt):
        ts = w3.eth.get_block(rcpt.blockNumber).timestamp
        self.now = max(self.now, ts)
        return ts

    def _tx(self, fn, acct, expect_revert=False):
        """Send tx; assert revert iff expected. Returns receipt or None.

        `fn` may be a zero-arg lambda returning a ContractFunction, or a
        bare ContractFunction. (Calling a ContractFunction with no args
        re-resolves the ABI and raises MismatchedABI, so bare ones are
        wrapped in a thunk here.)

        For expected reverts an eth_call runs first: it executes at the
        pending block (ts = latest + 1), exactly the timestamp the mined
        tx would land at, so call and mined outcomes agree.
        """
        # Normalize to a zero-arg thunk returning the ContractFunction.
        thunk = fn if not hasattr(fn, "abi") else (lambda: fn)
        RULE_HITS["tx_attempt"] += 1
        if expect_revert:
            try:
                thunk().call({"from": acct.address})
            except Exception as e:
                assert "revert" in str(e).lower(), \
                    f"expected revert, got non-revert error: {e}"
            else:
                raise AssertionError(
                    "expected revert in eth_call but call succeeded")
        rcpt = _send_raw(acct, thunk)
        self._ts(rcpt)
        if expect_revert:
            assert rcpt["status"] == 0, "tx expected to revert but succeeded"
            return None
        assert rcpt["status"] == 1, "tx unexpectedly reverted"
        return rcpt

    def _move(self, jid, frm, to):
        self.by_state[frm].remove(jid)
        self.by_state[to].append(jid)
        self.model[jid]["state"] = to
        STATES_REACHED.add(to)
        RULE_HITS[f"transition_{frm}_to_{to}"] += 1

    def _pick(self, state, idx):
        cands = self.by_state[state]
        if not cands:
            return None
        return cands[idx % len(cands)]

    def _bal(self, acct):
        return token.functions.balanceOf(acct.address).call()

    def _credit(self, acct):
        return escrow.functions.pendingCredit(TOKEN_ADDR, acct.address).call()

    def _snap(self, accts):
        return {a.address: (self._bal(a), self._credit(a))
                for a in accts}

    def _received(self, before, after, expected):
        # expected: {address: amount}; counts balance + pull-credit gains.
        for addr, amt in expected.items():
            got = (after[addr][0] - before[addr][0]) + \
                  (after[addr][1] - before[addr][1])
            assert got == amt, \
                f"expected {addr[:10]} to receive {amt}, got {got}"

    def _new_job(self, jid, payer, agent, amount, deadline_s, review_s):
        self.model[jid] = dict(
            payer=payer, agent=agent, amount=amount,
            deadlineSeconds=deadline_s, deadline=0, reviewWindow=review_s,
            state=CREATED, deliveredAt=0, disputedAt=0, bondAmount=0,
        )
        self.by_state[CREATED].append(jid)
        STATES_REACHED.add(CREATED)

    # -- rules ------------------------------------------------------

    @rule(data=st.data())
    def create_job(self, data):
        if len(self.model) >= MAX_JOBS:
            return
        payer = data.draw(st.sampled_from(PAYERS))
        worker = data.draw(st.sampled_from(WORKERS))
        amount = data.draw(st.one_of(
            st.integers(1, TIER1_MAX_AMOUNT - 1),
            st.integers(TIER1_MAX_AMOUNT, TIER2_MAX_AMOUNT),
            st.integers(TIER2_MAX_AMOUNT + 1, 10**9),
        ))
        deadline_s = data.draw(st.integers(3600, 7 * 86400))
        review_s = data.draw(st.integers(
            MIN_REVIEW_WINDOW, _tier_max_window(amount)))
        rcpt = self._tx(
            lambda: escrow.functions.createJob(
                worker.address, TOKEN_ADDR, amount, deadline_s, review_s,
                "ipfs://test"),
            payer, expect_revert=not self.token_allowed)
        if not self.token_allowed:
            return
        jid = escrow.functions.jobCount().call() - 1
        self._new_job(jid, payer, worker, amount, deadline_s, review_s)

    @rule(data=st.data())
    def create_open_job(self, data):
        if len(self.model) >= MAX_JOBS:
            return
        payer = data.draw(st.sampled_from(PAYERS))
        amount = data.draw(st.one_of(
            st.integers(1, TIER1_MAX_AMOUNT - 1),
            st.integers(TIER1_MAX_AMOUNT, TIER2_MAX_AMOUNT),
            st.integers(TIER2_MAX_AMOUNT + 1, 10**9),
        ))
        deadline_s = data.draw(st.integers(3600, 7 * 86400))
        review_s = data.draw(st.integers(
            MIN_REVIEW_WINDOW, _tier_max_window(amount)))
        rcpt = self._tx(
            lambda: escrow.functions.createOpenJob(
                TOKEN_ADDR, amount, deadline_s, review_s, "ipfs://test"),
            payer, expect_revert=not self.token_allowed)
        if not self.token_allowed:
            return
        jid = escrow.functions.jobCount().call() - 1
        self._new_job(jid, payer, None, amount, deadline_s, review_s)

    @rule(data=st.data())
    def create_invalid(self, data):
        # Fault-injection lite: every variant must revert, no model change.
        fault = data.draw(st.sampled_from([
            "agent_is_payer", "amount_zero", "review_zero",
            "review_too_long", "deadline_zero",
        ]))
        payer = data.draw(st.sampled_from(PAYERS))
        worker = data.draw(st.sampled_from(WORKERS))
        if fault == "agent_is_payer":
            fn = lambda: escrow.functions.createJob(
                payer.address, TOKEN_ADDR, 10**6, 3600, 3600, "x")
        elif fault == "amount_zero":
            fn = lambda: escrow.functions.createJob(
                worker.address, TOKEN_ADDR, 0, 3600, 3600, "x")
        elif fault == "review_zero":
            fn = lambda: escrow.functions.createJob(
                worker.address, TOKEN_ADDR, 10**6, 3600, 0, "x")
        elif fault == "review_too_long":
            # $5 job: tier max is 24h; 25h must revert.
            fn = lambda: escrow.functions.createJob(
                worker.address, TOKEN_ADDR, 5_000_000, 3600,
                25 * 3600, "x")
        else:  # deadline_zero
            fn = lambda: escrow.functions.createJob(
                worker.address, TOKEN_ADDR, 10**6, 0, 3600, "x")
        self._tx(fn, payer, expect_revert=True)

    @rule(idx=st.integers(0, 64), by=st.sampled_from(EVERYONE))
    def accept(self, idx, by):
        jid = self._pick(CREATED, idx)
        if jid is None:
            return
        m = self.model[jid]
        if m["agent"] is None:  # open job
            valid = by != m["payer"]
        else:
            valid = by == m["agent"]
        rcpt = self._tx(
            escrow.functions.acceptJob(jid), by, expect_revert=not valid)
        if valid:
            if m["agent"] is None:
                m["agent"] = by  # acceptor becomes agent
            # deadline is set from the mined block ts (self.now updated).
            m["deadline"] = self.now + m["deadlineSeconds"]
            self._move(jid, CREATED, ACCEPTED)

    @rule(idx=st.integers(0, 64), by=st.sampled_from(EVERYONE),
          dh=st.binary(min_size=32, max_size=32))
    def deliver(self, idx, by, dh):
        if dh == b"\x00" * 32:
            return
        jid = self._pick(ACCEPTED, idx)
        if jid is None:
            return
        m = self.model[jid]
        et = self.now + 1  # execution lands 1s after latest block
        valid = by == m["agent"] and et <= m["deadline"]
        rcpt = self._tx(
            escrow.functions.submitDelivery(jid, dh, "delivery text"),
            by, expect_revert=not valid)
        if valid:
            m["deliveredAt"] = self.now
            self._move(jid, ACCEPTED, DELIVERED)

    @rule(idx=st.integers(0, 64), by=st.sampled_from(EVERYONE),
          dh=st.binary(min_size=32, max_size=32))
    def deliver_and_dispute(self, idx, by, dh):
        if dh == b"\x00" * 32:
            return
        jid = self._pick(ACCEPTED, idx)
        if jid is None:
            return
        m = self.model[jid]
        et = self.now + 1
        valid = by == m["agent"] and et <= m["deadline"]
        rcpt = self._tx(
            escrow.functions.submitDeliveryAndDispute(
                jid, dh, "delivery text", "agent dispute reason"),
            by, expect_revert=not valid)
        if valid:
            # Agent-raised dispute: no bond.
            m["deliveredAt"] = self.now
            m["disputedAt"] = self.now
            m["bondAmount"] = 0
            self._move(jid, ACCEPTED, DISPUTED)

    @rule(idx=st.integers(0, 64), by=st.sampled_from(EVERYONE))
    def release(self, idx, by):
        jid = self._pick(DELIVERED, idx)
        if jid is None:
            return
        m = self.model[jid]
        et = self.now + 1
        if by == m["payer"]:
            valid = True
        elif by == m["agent"]:
            valid = et > m["deliveredAt"] + m["reviewWindow"]
        else:
            valid = False
        before = self._snap([m["agent"], m["payer"]])
        rcpt = self._tx(
            escrow.functions.release(jid), by, expect_revert=not valid)
        if valid:
            after = self._snap([m["agent"], m["payer"]])
            self._received(before, after, {m["agent"].address: m["amount"]})
            self._move(jid, DELIVERED, RELEASED)

    @rule(idx=st.integers(0, 64),
          pct=st.one_of(st.integers(0, 100),
                        st.sampled_from([0, 1, 50, 99, 100])),
          bad_sig=st.booleans())
    def release_partial(self, idx, pct, bad_sig):
        jid = self._pick(DELIVERED, idx)
        if jid is None:
            return
        m = self.model[jid]
        to_worker = m["amount"] * pct // 100
        et = self.now + 1
        in_window = et <= m["deliveredAt"] + m["reviewWindow"]
        dust_ok = to_worker > 0 and (
            to_worker == m["amount"]
            or to_worker >= m["amount"] * 100 // 10000)
        valid = in_window and dust_ok and not bad_sig
        signer = STRANGER if bad_sig else m["agent"]
        sig = _sign_partial(signer, jid, to_worker,
                            self.now + 365 * 86400)
        before = self._snap([m["agent"], m["payer"]])
        rcpt = self._tx(
            lambda: escrow.functions.releasePartial(
                jid, to_worker, self.now + 365 * 86400, sig),
            m["payer"], expect_revert=not valid)
        if valid:
            after = self._snap([m["agent"], m["payer"]])
            self._received(before, after, {
                m["agent"].address: to_worker,
                m["payer"].address: m["amount"] - to_worker,
            })
            self._move(jid, DELIVERED, RELEASED)

    @rule(idx=st.integers(0, 64), by=st.sampled_from(EVERYONE))
    def dispute(self, idx, by):
        jid = self._pick(DELIVERED, idx)
        if jid is None:
            return
        m = self.model[jid]
        et = self.now + 1
        valid = (by == m["payer"] or by == m["agent"]) and \
            et <= m["deliveredAt"] + m["reviewWindow"]
        bond = bond_for(m["amount"]) if by == m["payer"] else 0
        payer_bal_before = self._bal(m["payer"]) if valid else None
        rcpt = self._tx(
            lambda: escrow.functions.raiseDispute(jid, "dispute reason"),
            by, expect_revert=not valid)
        if valid:
            if by == m["payer"]:
                # Bond pulled from the payer in the same tx.
                assert self._bal(m["payer"]) == payer_bal_before - bond, \
                    "bond pull mismatch"
                m["bondAmount"] = bond
            else:
                m["bondAmount"] = 0
            m["disputedAt"] = self.now
            self._move(jid, DELIVERED, DISPUTED)

    @rule(idx=st.integers(0, 64), by=st.sampled_from(EVERYONE),
          pct=st.one_of(st.integers(0, 100),
                        st.sampled_from([0, 1, 50, 99, 100])))
    def execute_ruling(self, idx, by, pct):
        jid = self._pick(DISPUTED, idx)
        if jid is None:
            return
        m = self.model[jid]
        to_worker = m["amount"] * pct // 100
        et = self.now + 1  # execution lands 1s after latest block
        valid = by == OPERATOR and et <= m["disputedAt"] + RULING_PERIOD
        bond_to_agent = to_worker >= m["amount"] - to_worker
        before = self._snap([m["agent"], m["payer"]])
        rcpt = self._tx(
            lambda: escrow.functions.executeRuling(jid, to_worker),
            by, expect_revert=not valid)
        if valid:
            after = self._snap([m["agent"], m["payer"]])
            self._received(before, after, {
                m["agent"].address:
                    to_worker + (m["bondAmount"] if bond_to_agent else 0),
                m["payer"].address:
                    (m["amount"] - to_worker) +
                    (0 if bond_to_agent else m["bondAmount"]),
            })
            self._move(jid, DISPUTED,
                       RELEASED if to_worker > 0 else REFUNDED)
            m["bondAmount"] = 0
            # Single-use: a second ruling must revert.
            self._tx(
                lambda: escrow.functions.executeRuling(jid, to_worker),
                OPERATOR, expect_revert=True)

    @rule(idx=st.integers(0, 64), caller=st.sampled_from(EVERYONE),
          pct=st.one_of(st.integers(0, 100),
                        st.sampled_from([0, 1, 50, 99, 100])),
          bad_sig=st.booleans())
    def settle_by_agreement(self, idx, caller, pct, bad_sig):
        jid = self._pick(DISPUTED, idx)
        if jid is None:
            return
        m = self.model[jid]
        to_worker = m["amount"] * pct // 100
        is_party = caller == m["payer"] or caller == m["agent"]
        counterparty = (m["agent"] if caller == m["payer"]
                        else m["payer"] if caller == m["agent"] else None)
        valid = is_party and not bad_sig
        # Non-party callers revert on "not a party" regardless of the sig;
        # sign as a stranger so _sign_settle always gets a real account.
        signer = counterparty if (counterparty is not None and not bad_sig) \
            else STRANGER
        sig = _sign_settle(signer, jid, to_worker,
                           self.now + 365 * 86400)
        before = self._snap([m["agent"], m["payer"]])
        rcpt = self._tx(
            lambda: escrow.functions.settleByAgreement(
                jid, to_worker, self.now + 365 * 86400, sig),
            caller, expect_revert=not valid)
        if valid:
            after = self._snap([m["agent"], m["payer"]])
            # Bond always returns to the payer on mutual settle.
            self._received(before, after, {
                m["agent"].address: to_worker,
                m["payer"].address:
                    (m["amount"] - to_worker) + m["bondAmount"],
            })
            self._move(jid, DISPUTED,
                       RELEASED if to_worker > 0 else REFUNDED)
            m["bondAmount"] = 0
            # Single-use: a second settle must revert.
            sig2 = _sign_settle(m["payer"], jid, to_worker,
                                self.now + 365 * 86400)
            self._tx(
                lambda: escrow.functions.settleByAgreement(
                    jid, to_worker, self.now + 365 * 86400, sig2),
                m["agent"], expect_revert=True)

    @rule(idx=st.integers(0, 64), by=st.sampled_from(EVERYONE))
    def refund_timeout(self, idx, by):
        jid = self._pick(DISPUTED, idx)
        if jid is None:
            return
        m = self.model[jid]
        et = self.now + 1
        valid = et > m["disputedAt"] + RULING_PERIOD
        before = self._snap([m["payer"]])
        rcpt = self._tx(
            escrow.functions.refundDisputeTimeout(jid),
            by, expect_revert=not valid)
        if valid:
            after = self._snap([m["payer"]])
            self._received(before, after, {
                m["payer"].address: m["amount"] + m["bondAmount"],
            })
            self._move(jid, DISPUTED, REFUNDED)
            m["bondAmount"] = 0
            # Single-use: a second valve call must revert.
            self._tx(escrow.functions.refundDisputeTimeout(jid),
                     by, expect_revert=True)

    @rule(idx=st.integers(0, 64))
    def refund_after_deadline(self, idx):
        # Ghosted-agent exit, folded into cancel(): Accepted + past
        # deadline refunds via cancel, same as the old refundAfterDeadline.
        jid = self._pick(ACCEPTED, idx)
        if jid is None:
            return
        m = self.model[jid]
        et = self.now + 1
        valid = et > m["deadline"]
        before = self._snap([m["payer"]])
        rcpt = self._tx(
            escrow.functions.cancel(jid),
            m["payer"], expect_revert=not valid)
        if valid:
            after = self._snap([m["payer"]])
            self._received(before, after, {m["payer"].address: m["amount"]})
            self._move(jid, ACCEPTED, REFUNDED)

    @rule(idx=st.integers(0, 64))
    def cancel(self, idx):
        jid = self._pick(CREATED, idx)
        if jid is None:
            return
        m = self.model[jid]
        before = self._snap([m["payer"]])
        rcpt = self._tx(escrow.functions.cancel(jid), m["payer"])
        after = self._snap([m["payer"]])
        self._received(before, after, {m["payer"].address: m["amount"]})
        self._move(jid, CREATED, CANCELLED)

    @rule(acct=st.sampled_from(EVERYONE))
    def withdraw(self, acct):
        credit = escrow.functions.pendingCredit(
            TOKEN_ADDR, acct.address).call()
        before = self._snap([acct])
        rcpt = self._tx(
            lambda: escrow.functions.withdraw(TOKEN_ADDR),
            acct, expect_revert=(credit == 0))
        if credit > 0:
            after = self._snap([acct])
            self._received(before, after, {acct.address: credit})

    @rule(by=st.sampled_from([OPERATOR, STRANGER, PAYER_A]),
          flag=st.integers(0, 9))
    def set_token_allowed(self, by, flag):
        # Delist is rare (flag == 0); re-list is the common case, so the
        # machine recovers instead of starving creates for a whole example.
        allowed = flag != 0
        valid = by == OPERATOR
        rcpt = self._tx(
            lambda: escrow.functions.setTokenAllowed(TOKEN_ADDR, allowed),
            by, expect_revert=not valid)
        if valid:
            self.token_allowed = allowed

    # -- workflow rules: drive jobs to deep states atomically ------------
    # The atomic rules above rarely chain create->accept->deliver by
    # chance; these workflows guarantee deep-state coverage for dispute /
    # ruling / settle / valve testing. Random interleaving still comes
    # from the atomic rules.

    @rule(data=st.data())
    def workflow_delivered(self, data):
        if len(self.model) >= MAX_JOBS:
            return
        payer = data.draw(st.sampled_from(PAYERS))
        worker = data.draw(st.sampled_from(WORKERS))
        amount = data.draw(st.one_of(
            st.integers(1, TIER1_MAX_AMOUNT - 1),
            st.integers(TIER1_MAX_AMOUNT, TIER2_MAX_AMOUNT),
            st.integers(TIER2_MAX_AMOUNT + 1, 10**9),
        ))
        deadline_s = data.draw(st.integers(3600, 7 * 86400))
        review_s = data.draw(st.integers(
            MIN_REVIEW_WINDOW, _tier_max_window(amount)))
        dh = data.draw(st.binary(min_size=32, max_size=32))
        if dh == b"\x00" * 32:
            return
        use_open = data.draw(st.booleans())
        if use_open:
            rcpt = self._tx(
                lambda: escrow.functions.createOpenJob(
                    TOKEN_ADDR, amount, deadline_s, review_s, "ipfs://test"),
                payer, expect_revert=not self.token_allowed)
            agent = worker
        else:
            rcpt = self._tx(
                lambda: escrow.functions.createJob(
                    worker.address, TOKEN_ADDR, amount, deadline_s,
                    review_s, "ipfs://test"),
                payer, expect_revert=not self.token_allowed)
            agent = worker
        if not self.token_allowed:
            return
        jid = escrow.functions.jobCount().call() - 1
        self._new_job(jid, payer, None if use_open else worker,
                      amount, deadline_s, review_s)
        m = self.model[jid]
        self._tx(escrow.functions.acceptJob(jid), agent)
        m["agent"] = agent
        m["deadline"] = self.now + m["deadlineSeconds"]
        self._move(jid, CREATED, ACCEPTED)
        if self.now + 1 > m["deadline"]:
            return  # deadline edge: leave Accepted for refund testing
        self._tx(escrow.functions.submitDelivery(jid, dh, "delivery text"),
                 agent)
        m["deliveredAt"] = self.now
        self._move(jid, ACCEPTED, DELIVERED)

    @rule(data=st.data())
    def workflow_disputed(self, data):
        if len(self.model) >= MAX_JOBS:
            return
        payer = data.draw(st.sampled_from(PAYERS))
        worker = data.draw(st.sampled_from(WORKERS))
        amount = data.draw(st.one_of(
            st.integers(1, TIER1_MAX_AMOUNT - 1),
            st.integers(TIER1_MAX_AMOUNT, TIER2_MAX_AMOUNT),
            st.integers(TIER2_MAX_AMOUNT + 1, 10**9),
        ))
        deadline_s = data.draw(st.integers(3600, 7 * 86400))
        review_s = data.draw(st.integers(
            MIN_REVIEW_WINDOW, _tier_max_window(amount)))
        dh = data.draw(st.binary(min_size=32, max_size=32))
        if dh == b"\x00" * 32:
            return
        rcpt = self._tx(
            lambda: escrow.functions.createJob(
                worker.address, TOKEN_ADDR, amount, deadline_s, review_s,
                "ipfs://test"),
            payer, expect_revert=not self.token_allowed)
        if not self.token_allowed:
            return
        jid = escrow.functions.jobCount().call() - 1
        self._new_job(jid, payer, worker, amount, deadline_s, review_s)
        m = self.model[jid]
        self._tx(escrow.functions.acceptJob(jid), worker)
        m["deadline"] = self.now + m["deadlineSeconds"]
        self._move(jid, CREATED, ACCEPTED)
        if self.now + 1 > m["deadline"]:
            return
        self._tx(escrow.functions.submitDelivery(jid, dh, "delivery text"),
                 worker)
        m["deliveredAt"] = self.now
        self._move(jid, ACCEPTED, DELIVERED)
        # Dispute immediately: review_s >= 3600 keeps it in-window.
        payer_bal_before = self._bal(payer)
        bond = bond_for(amount)
        self._tx(lambda: escrow.functions.raiseDispute(jid, "reason"), payer)
        assert self._bal(payer) == payer_bal_before - bond, "bond pull"
        m["disputedAt"] = self.now
        m["bondAmount"] = bond
        self._move(jid, DELIVERED, DISPUTED)

    @rule(data=st.data())
    def workflow_refunded_via_valve(self, data):
        # Deterministic Refunded coverage: the atomic refund paths
        # (ruling 0%, settle 0%, valve, refund-after-deadline) are all
        # low-probability per step, and one full run missed state 5
        # entirely. This workflow guarantees the valve path is exercised:
        # create -> accept -> deliver -> dispute (payer, bond) -> +73h
        # -> refundDisputeTimeout, called by a stranger to prove anyone
        # may call it.
        if len(self.model) >= MAX_JOBS:
            return
        payer = data.draw(st.sampled_from(PAYERS))
        worker = data.draw(st.sampled_from(WORKERS))
        amount = data.draw(st.one_of(
            st.integers(1, TIER1_MAX_AMOUNT - 1),
            st.integers(TIER1_MAX_AMOUNT, TIER2_MAX_AMOUNT),
            st.integers(TIER2_MAX_AMOUNT + 1, 10**9),
        ))
        deadline_s = data.draw(st.integers(3600, 7 * 86400))
        review_s = data.draw(st.integers(
            MIN_REVIEW_WINDOW, _tier_max_window(amount)))
        dh = data.draw(st.binary(min_size=32, max_size=32))
        if dh == b"\x00" * 32:
            return
        rcpt = self._tx(
            lambda: escrow.functions.createJob(
                worker.address, TOKEN_ADDR, amount, deadline_s, review_s,
                "ipfs://test"),
            payer, expect_revert=not self.token_allowed)
        if not self.token_allowed:
            return
        jid = escrow.functions.jobCount().call() - 1
        self._new_job(jid, payer, worker, amount, deadline_s, review_s)
        m = self.model[jid]
        self._tx(escrow.functions.acceptJob(jid), worker)
        m["deadline"] = self.now + m["deadlineSeconds"]
        self._move(jid, CREATED, ACCEPTED)
        if self.now + 1 > m["deadline"]:
            return
        self._tx(escrow.functions.submitDelivery(jid, dh, "delivery text"),
                 worker)
        m["deliveredAt"] = self.now
        self._move(jid, ACCEPTED, DELIVERED)
        payer_bal_before = self._bal(payer)
        bond = bond_for(amount)
        self._tx(lambda: escrow.functions.raiseDispute(jid, "reason"), payer)
        assert self._bal(payer) == payer_bal_before - bond, "bond pull"
        m["disputedAt"] = self.now
        m["bondAmount"] = bond
        self._move(jid, DELIVERED, DISPUTED)
        # Advance 73h past the dispute, then anyone may call the valve.
        latest = w3.eth.get_block("latest").timestamp
        pending = w3.eth.get_block("pending").timestamp
        base = max(self.now, latest, pending)
        _tester.time_travel(base + 73 * 3600)
        w3.provider.make_request("evm_mine", [])
        self.now = w3.eth.get_block("latest").timestamp
        before = self._snap([payer])
        self._tx(escrow.functions.refundDisputeTimeout(jid), STRANGER)
        after = self._snap([payer])
        self._received(before, after,
                       {payer.address: amount + bond})
        self._move(jid, DISPUTED, REFUNDED)
        m["bondAmount"] = 0

    @rule(delta_s=st.integers(1, 80 * 3600))
    def advance_time(self, delta_s):
        # Anchor to the max of every known clock: eth-tester validates
        # time_travel against the PENDING block, which can run ahead of
        # self.now after reverts/shrinks. Never travel backwards.
        latest = w3.eth.get_block("latest").timestamp
        pending = w3.eth.get_block("pending").timestamp
        base = max(self.now, latest, pending)
        _tester.time_travel(base + delta_s)
        w3.provider.make_request("evm_mine", [])
        self.now = w3.eth.get_block("latest").timestamp
        assert self.now >= base + 1, f"time did not advance: {self.now} < {base}"

    # -- invariants -------------------------------------------------

    @invariant()
    def i1_fund_conservation(self):
        _, _, _, _, holds = escrow.functions.settlementInvariant(
            TOKEN_ADDR).call()
        assert holds, "I1 BROKEN: settlement invariant does not hold"

    @invariant()
    def i2_unsettled_matches_scan(self):
        expect = sum(
            m["amount"] for m in self.model.values()
            if m["state"] in NONTERMINAL)
        got = escrow.functions.totalUnsettled(TOKEN_ADDR).call()
        assert got == expect, f"I2 BROKEN: onchain={got} scan={expect}"

    @invariant()
    def i2b_bonded_matches_scan(self):
        expect = sum(
            m["bondAmount"] for m in self.model.values()
            if m["state"] == DISPUTED)
        got = escrow.functions.totalBonded(TOKEN_ADDR).call()
        assert got == expect, f"I2b BROKEN: onchain={got} scan={expect}"

    @invariant()
    def i2c_credits_match_scan(self):
        addrs = [x.address for x in EVERYONE] + [FUNDER]
        expect = sum(
            escrow.functions.pendingCredit(TOKEN_ADDR, a).call()
            for a in addrs)
        got = escrow.functions.totalPendingCredits(TOKEN_ADDR).call()
        assert got == expect, f"I2c BROKEN: onchain={got} scan={expect}"

    @invariant()
    def i3_state_fidelity(self):
        for jid, m in self.model.items():
            job = escrow.functions.getJob(jid).call()
            # tuple: payer, agent, token, amount, deadline, reviewWindow,
            #        state, deliveryHash, metadataURI, deliveredAt,
            #        deadlineSeconds, deliveryText, disputeReason,
            #        bondAmount, disputedAt
            assert job[6] == m["state"], \
                f"I3 job {jid}: state {job[6]} != {m['state']}"
            assert job[3] == m["amount"], f"I3 job {jid}: amount drift"
            assert job[4] == m["deadline"], \
                f"I3 job {jid}: deadline {job[4]} != {m['deadline']}"
            assert job[5] == m["reviewWindow"], \
                f"I3 job {jid}: reviewWindow drift"
            assert job[9] == m["deliveredAt"], \
                f"I3 job {jid}: deliveredAt drift"
            assert job[10] == m["deadlineSeconds"], \
                f"I3 job {jid}: deadlineSeconds drift"
            assert job[13] == m["bondAmount"], \
                f"I3 job {jid}: bondAmount {job[13]} != {m['bondAmount']}"
            assert job[14] == m["disputedAt"], \
                f"I3 job {jid}: disputedAt drift"
            exp_agent = m["agent"].address if m["agent"] else ZERO_ADDR
            assert job[1].lower() == exp_agent.lower(), \
                f"I3 job {jid}: agent drift"
            assert job[0].lower() == m["payer"].address.lower(), \
                f"I3 job {jid}: payer drift"

    @invariant()
    def i4_whitelist_fidelity(self):
        got = escrow.functions.allowedTokens(TOKEN_ADDR).call()
        assert got == self.token_allowed, \
            f"I4 BROKEN: onchain allowed={got} model={self.token_allowed}"


TestV3 = V3Machine.TestCase
TestV3.settings = settings(
    max_examples=MAX_EXAMPLES,
    stateful_step_count=STEP_COUNT,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)


if __name__ == "__main__":
    import unittest

    unittest.main()


def test_v3_prop_phase1_coverage():
    # Runs after the state machine; asserts every state was reached and
    # reports rule hits.
    print("\nRULE_HITS:", dict(RULE_HITS))
    print("STATES_REACHED:", sorted(STATES_REACHED))
    missing = set(range(7)) - STATES_REACHED
    assert not missing, f"states never reached: {sorted(missing)}"
