"""
Phase 4: Reconciliation & State Reconstruction — AgentEscrowV3.

Question: can off-chain systems (UI, indexers, dispute watchers) accurately
reconstruct contract state from on-chain data? Do the contract's accounting
views match reality?

Adapted from the V9 Phase 4 suite (`test_v9_phase4_recon.py`) for V3:
no arbiter panel, no votes, no rotation, no governance. V3 adds a dispute
bond, operator-executed rulings, mutual settlement, a 72h timeout valve,
tiered review windows, and an operator-managed whitelist — and the size
cuts deleted `claimWindows` / `jobWindows`, so the watcher recipe here is
events + `getJob`, not events + window views.

Test groups:
  R1  Event completeness: every state change emits the right event with
      all fields needed for off-chain reconstruction
  R2  View function accuracy: totalUnsettled / totalBonded /
      totalPendingCredits / pendingCredit / settlementInvariant / getJob
      match ground truth after a mixed scenario (incl. a forced credit)
  R3  Off-chain reconstruction: pure-Python model built ONLY from events
      (+ receipt block timestamps) matches on-chain state after every
      step of random operation sequences
  R4  Accounting edge cases: odd partials, dispute splits, valve
      accounting, credit tracking — do the views stay exact?
  R5  Dispute watcher compatibility: can a watcher detect DisputeRaised
      and recover job details + deadlines from on-chain data alone,
      with zero off-chain storage?

FINDING (documented, not a bug fix — see test_r1_event_fields_gap):
JobCreated does not emit `deadlineSeconds` or `reviewWindow`, and
DisputeRaised does not carry the dispute reason text. A pure-event
indexer therefore cannot compute claim deadlines or read the reason
from the log; it must call `getJob`. State, amounts, bond, and credits
are fully event-sourced; timing parameters are view-sourced. The
contract was NOT changed for this: the watcher recipe (events +
`getJob`) still needs zero off-chain storage, and the size direction
for this contract is smaller, not bigger.
"""

import random

import pytest
import solcx
from eth_account import Account

from conftest import (
    CREATED, ACCEPTED, DELIVERED, DISPUTED, RELEASED, REFUNDED, CANCELLED,
    AMOUNT, REVIEW_WINDOW, DEADLINE_SECONDS, RULING_PERIOD, bond_for,
)

try:
    solcx.install_solc("0.8.24")
except Exception:
    pass
solcx.set_solc_version("0.8.24")

ZERO_HASH = b"\x00" * 32
ZERO_ADDR = "0x0000000000000000000000000000000000000000"

# All 15 events V3 emits.
EVENT_NAMES = [
    "JobCreated", "JobAccepted", "DeliverySubmitted", "JobReleased",
    "JobRefunded", "JobCancelled", "DisputeRaised", "BondPosted",
    "RulingExecuted", "SettledByAgreement", "DisputeTimeoutRefunded",
    "JobPartiallyReleased", "Credited", "Withdrawn", "TokenWhitelisted",
]


def _events(env, receipt):
    """Decode all V3 events from a receipt into (name, args, block_ts),
    in true log order (logIndex). Block timestamps come from the block,
    not the event args — no V3 event carries a timestamp."""
    out = []
    block_ts = env.w3.eth.get_block(receipt["blockNumber"])["timestamp"]
    for name in EVENT_NAMES:
        try:
            ev = getattr(env.escrow.events, name)()
            for log in ev.process_receipt(receipt):
                out.append((log["logIndex"], name, dict(log["args"]), block_ts))
        except Exception:
            pass
    out.sort(key=lambda t: t[0])
    return [(name, args, ts) for _, name, args, ts in out]


def _apply_all(env, model, receipt):
    """Feed one receipt's events into the model, in log order."""
    for name, args, ts in _events(env, receipt):
        model.apply(name, args, ts)


class ChainModel:
    """Pure-Python reconstruction of escrow state from events ONLY
    (+ receipt block timestamps, which are chain data).

    Tracks everything the events carry: job state/amount/parties,
    deliveredAt, disputedAt, bond, credits, whitelist, unsettled and
    bonded totals. Deliberately does NOT track deadline, reviewWindow,
    deadlineSeconds, or disputeReason — no event carries them (see the
    finding in the module docstring). Those fields are view-sourced
    via getJob, and the comparison function skips them.
    """

    def __init__(self):
        self.jobs = {}        # jobId -> dict
        self.unsettled = {}   # token -> amount
        self.bonded = {}      # token -> amount
        self.credits = {}     # (token, account) -> amount
        self.whitelist = {}   # token -> bool

    def apply(self, name, a, ts):
        jid = a.get("jobId")
        if name == "JobCreated":
            self.jobs[jid] = {
                "payer": a["payer"].lower(), "agent": a["agent"].lower(),
                "token": a["token"].lower(), "amount": a["amount"],
                "state": CREATED, "deliveredAt": 0, "disputedAt": 0,
                "bondAmount": 0, "raisedBy": None,
                "metadataURI": a["metadataURI"],
                "deliveryHash": ZERO_HASH, "deliveryText": "",
                "_settled": False,
            }
            t = a["token"].lower()
            self.unsettled[t] = self.unsettled.get(t, 0) + a["amount"]
        elif name == "JobAccepted":
            j = self.jobs[jid]
            j["agent"] = a["agent"].lower()
            j["state"] = ACCEPTED
        elif name == "DeliverySubmitted":
            j = self.jobs[jid]
            j["state"] = DELIVERED
            j["deliveryHash"] = bytes(a["deliveryHash"])
            j["deliveryText"] = a["deliveryText"]
            j["deliveredAt"] = ts
        elif name == "DisputeRaised":
            j = self.jobs[jid]
            j["state"] = DISPUTED
            j["raisedBy"] = a["by"].lower()
            j["disputedAt"] = ts
        elif name == "BondPosted":
            j = self.jobs[jid]
            j["bondAmount"] = a["bondAmount"]
            t = j["token"]
            self.bonded[t] = self.bonded.get(t, 0) + a["bondAmount"]
        elif name == "JobReleased":
            self.jobs[jid]["state"] = RELEASED
            self._settle(jid)
        elif name == "JobRefunded":
            self.jobs[jid]["state"] = REFUNDED
            self._settle(jid)
        elif name == "JobCancelled":
            self.jobs[jid]["state"] = CANCELLED
            self._settle(jid)
        elif name == "JobPartiallyReleased":
            self.jobs[jid]["state"] = RELEASED
            self._settle(jid)
        elif name == "RulingExecuted":
            j = self.jobs[jid]
            j["state"] = REFUNDED if a["amountToWorker"] == 0 else RELEASED
            self._pay_bond(jid)
            self._settle(jid)
        elif name == "SettledByAgreement":
            j = self.jobs[jid]
            j["state"] = REFUNDED if a["amountToWorker"] == 0 else RELEASED
            self._pay_bond(jid)
            self._settle(jid)
        elif name == "DisputeTimeoutRefunded":
            j = self.jobs[jid]
            j["state"] = REFUNDED
            self._pay_bond(jid)
            self._settle(jid)
        elif name == "Credited":
            k = (a["token"].lower(), a["account"].lower())
            self.credits[k] = self.credits.get(k, 0) + a["amount"]
        elif name == "Withdrawn":
            k = (a["token"].lower(), a["account"].lower())
            self.credits[k] = self.credits.get(k, 0) - a["amount"]
        elif name == "TokenWhitelisted":
            self.whitelist[a["token"].lower()] = a["allowed"]

    def _settle(self, jid):
        """Idempotent: several events can fire for one settlement
        (e.g. valve emits JobRefunded + DisputeTimeoutRefunded in one
        tx). The job's amount leaves unsettled exactly once."""
        j = self.jobs[jid]
        if j.get("_settled"):
            return
        j["_settled"] = True
        t = j["token"]
        self.unsettled[t] = self.unsettled.get(t, 0) - j["amount"]

    def _pay_bond(self, jid):
        """Bond leaves bonded exactly once, on the ruling/settle/valve
        event. (JobRefunded alone does not move the bond — it can fire
        in the same tx before the path event, so bond payout waits for
        the path event.)"""
        j = self.jobs[jid]
        bond = j.get("bondAmount", 0)
        if bond:
            t = j["token"]
            self.bonded[t] = self.bonded.get(t, 0) - bond
            j["bondAmount"] = 0


def _check_model(env, model, token_addr, label=""):
    """Compare the events-only model against the chain, exactly.
    Fields no event carries (deadline, reviewWindow, deadlineSeconds,
    disputeReason) are skipped here and covered by the gap test."""
    t = token_addr.lower()
    n = env.escrow.functions.jobCount().call()
    assert len(model.jobs) == n, \
        f"{label}: model has {len(model.jobs)} jobs, chain has {n}"
    for jid in range(n):
        chain = env.job(jid)
        m = model.jobs[jid]
        assert chain[0].lower() == m["payer"], f"{label}: job {jid} payer"
        assert chain[1].lower() == m["agent"], f"{label}: job {jid} agent"
        assert chain[2].lower() == m["token"], f"{label}: job {jid} token"
        assert chain[3] == m["amount"], f"{label}: job {jid} amount"
        assert chain[6] == m["state"], \
            f"{label}: job {jid} state chain={chain[6]} model={m['state']}"
        assert bytes(chain[7]) == bytes(m["deliveryHash"]), \
            f"{label}: job {jid} deliveryHash"
        assert chain[8] == m["metadataURI"], f"{label}: job {jid} metadataURI"
        assert chain[9] == m["deliveredAt"], \
            f"{label}: job {jid} deliveredAt chain={chain[9]} model={m['deliveredAt']}"
        assert chain[11] == m["deliveryText"], \
            f"{label}: job {jid} deliveryText"
        assert chain[13] == m["bondAmount"], \
            f"{label}: job {jid} bondAmount chain={chain[13]} model={m['bondAmount']}"
        assert chain[14] == m["disputedAt"], \
            f"{label}: job {jid} disputedAt chain={chain[14]} model={m['disputedAt']}"

    assert env.escrow.functions.totalUnsettled(token_addr).call() == \
        model.unsettled.get(t, 0), f"{label}: totalUnsettled"
    assert env.escrow.functions.totalBonded(token_addr).call() == \
        model.bonded.get(t, 0), f"{label}: totalBonded"
    model_credit_total = sum(
        v for (tt, _), v in model.credits.items() if tt == t)
    assert env.escrow.functions.totalPendingCredits(token_addr).call() == \
        model_credit_total, f"{label}: totalPendingCredits"
    for (tt, acct), amt in model.credits.items():
        if tt != t:
            continue
        assert env.escrow.functions.pendingCredit(token_addr, acct).call() == amt, \
            f"{label}: pendingCredit {acct}"
    assert env.escrow.functions.allowedTokens(token_addr).call() == \
        model.whitelist.get(t, True), f"{label}: whitelist"

    bal, usum, bsum, csum, holds = env.escrow.functions.settlementInvariant(
        token_addr).call()
    assert holds is True, f"{label}: settlementInvariant does not hold"
    assert usum == model.unsettled.get(t, 0), f"{label}: invariant unsettled"
    assert bsum == model.bonded.get(t, 0), f"{label}: invariant bonded"
    assert csum == model_credit_total, f"{label}: invariant credits"

# ============================================================ R1: event completeness

def _tx_ok(env, fn_builder, acct, gas=500000):
    r = env.send_as(acct, fn_builder, gas=gas)
    assert r["status"] == 1, "tx unexpectedly reverted"
    return r


def _names(evs):
    return [n for n, _, _ in evs]


def _find(evs, name):
    return [a for n, a, _ in evs if n == name]


TOGGLE_TOKEN_SOURCE = """
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


def _deploy_toggle(env):
    compiled = solcx.compile_source(
        TOGGLE_TOKEN_SOURCE, output_values=["abi", "bin"], solc_version="0.8.24")
    data = compiled["<stdin>:ToggleToken"]
    Token = env.w3.eth.contract(abi=data["abi"], bytecode=data["bin"])
    tx = Token.constructor().transact({"from": env.funder, "gas": 2000000})
    addr = env.w3.eth.wait_for_transaction_receipt(tx).contractAddress
    return env.w3.eth.contract(address=addr, abi=data["abi"])


def _fund_token(env, token, acct, amount):
    token.functions.mint(acct.address, amount).transact({"from": env.funder})
    tx = token.functions.approve(env.escrow_addr, amount).build_transaction({
        "from": acct.address,
        "nonce": env.w3.eth.get_transaction_count(acct.address),
        "gas": 100000, "gasPrice": env.w3.eth.gas_price, "chainId": env.chain_id,
    })
    env.w3.eth.send_raw_transaction(acct.sign_transaction(tx).raw_transaction)


def _create_with_token(env, token_addr, payer, agent_addr, amount,
                       review_window=3600, deadline_seconds=3600):
    r = _tx_ok(env, lambda: env.escrow.functions.createJob(
        agent_addr, token_addr, amount, deadline_seconds,
        review_window, "toggle job"), payer)
    return env.escrow.functions.jobCount().call() - 1


class TestR1Events:
    def test_r1_create_accept_deliver_events(self, env):
        model = ChainModel()
        # Named job.
        env.mint_and_approve(env.payer, AMOUNT)
        r = _tx_ok(env, lambda: env.escrow.functions.createJob(
            env.agent.address, env.token_addr, AMOUNT, DEADLINE_SECONDS,
            REVIEW_WINDOW, "job-zero"), env.payer)
        evs = _events(env, r)
        _apply_all(env, model, r)
        created = _find(evs, "JobCreated")
        assert len(created) == 1, f"expected 1 JobCreated, got {_names(evs)}"
        a = created[0]
        assert a["jobId"] == 0
        assert a["payer"].lower() == env.payer.address.lower()
        assert a["agent"].lower() == env.agent.address.lower()
        assert a["token"].lower() == env.token_addr.lower()
        assert a["amount"] == AMOUNT
        assert a["deadline"] == 0, "deadline must be 0 until accept"
        assert a["metadataURI"] == "job-zero"

        # Open job.
        env.mint_and_approve(env.payer, AMOUNT)
        r = _tx_ok(env, lambda: env.escrow.functions.createOpenJob(
            env.token_addr, AMOUNT, DEADLINE_SECONDS, REVIEW_WINDOW,
            "open-job"), env.payer)
        evs = _events(env, r)
        _apply_all(env, model, r)
        created = _find(evs, "JobCreated")
        assert len(created) == 1
        assert created[0]["agent"].lower() == ZERO_ADDR
        assert created[0]["jobId"] == 1

        # Accept named + open claim.
        r = _tx_ok(env, lambda: env.escrow.functions.acceptJob(0), env.agent)
        evs = _events(env, r)
        _apply_all(env, model, r)
        acc = _find(evs, "JobAccepted")
        assert len(acc) == 1
        assert acc[0]["jobId"] == 0
        assert acc[0]["agent"].lower() == env.agent.address.lower()
        r = _tx_ok(env, lambda: env.escrow.functions.acceptJob(1), env.stranger)
        evs = _events(env, r)
        _apply_all(env, model, r)
        acc = _find(evs, "JobAccepted")
        assert len(acc) == 1
        assert acc[0]["agent"].lower() == env.stranger.address.lower()

        # Deliver both.
        dh = env.w3.keccak(text="d0")
        r = _tx_ok(env, lambda: env.escrow.functions.submitDelivery(
            0, dh, "delivered zero"), env.agent)
        evs = _events(env, r)
        _apply_all(env, model, r)
        assert any(n == "DeliverySubmitted" and a["jobId"] == 0
                   and bytes(a["deliveryHash"]) == bytes(dh)
                   and a["deliveryText"] == "delivered zero"
                   for n, a, _ in evs)
        r = _tx_ok(env, lambda: env.escrow.functions.submitDelivery(
            1, dh, "delivered one"), env.stranger)
        evs = _events(env, r)
        _apply_all(env, model, r)
        assert any(n == "DeliverySubmitted" for n, _, _ in evs)
        _check_model(env, model, env.token_addr, "r1-create-deliver")

    def test_r1_dispute_bond_events(self, env):
        # Payer dispute: BondPosted + DisputeRaised.
        bond = bond_for(AMOUNT)
        env.mint_and_approve(env.payer, AMOUNT)
        r = _tx_ok(env, lambda: env.escrow.functions.createJob(
            env.agent.address, env.token_addr, AMOUNT, DEADLINE_SECONDS,
            REVIEW_WINDOW, "bond-job"), env.payer)
        jid2 = env.escrow.functions.jobCount().call() - 1
        _tx_ok(env, lambda: env.escrow.functions.acceptJob(jid2), env.agent)
        dh = env.w3.keccak(text="db")
        _tx_ok(env, lambda: env.escrow.functions.submitDelivery(
            jid2, dh, "delivery"), env.agent)
        env.mint_and_approve(env.payer, bond, approve=bond)
        r = _tx_ok(env, lambda: env.escrow.functions.raiseDispute(
            jid2, "work was wrong"), env.payer)
        evs = _events(env, r)
        posted = _find(evs, "BondPosted")
        assert len(posted) == 1
        assert posted[0]["jobId"] == jid2
        assert posted[0]["payer"].lower() == env.payer.address.lower()
        assert posted[0]["bondAmount"] == bond
        raised = _find(evs, "DisputeRaised")
        assert len(raised) == 1
        assert raised[0]["jobId"] == jid2
        assert raised[0]["by"].lower() == env.payer.address.lower()
        # BondPosted precedes DisputeRaised in log order.
        assert _names(evs).index("BondPosted") < _names(evs).index("DisputeRaised")

        # Agent dispute via atomic deliver+dispute: both delivery and
        # dispute events, NO bond.
        jid3 = env.create_job(env.agent.address)
        _tx_ok(env, lambda: env.escrow.functions.acceptJob(jid3), env.agent)
        r = _tx_ok(env, lambda: env.escrow.functions.submitDeliveryAndDispute(
            jid3, dh, "delivery", "agent dispute"), env.agent)
        evs = _events(env, r)
        assert _names(evs) == ["DeliverySubmitted", "DisputeRaised"]
        assert _find(evs, "BondPosted") == []

    def test_r1_ruling_events(self, env):
        # 100% to worker: RulingExecuted only, no JobRefunded.
        jid = env.create_disputed_job(by="payer")
        r = _tx_ok(env, lambda: env.escrow.functions.executeRuling(
            jid, AMOUNT), env.operator)
        evs = _events(env, r)
        assert _names(evs) == ["RulingExecuted"]
        a = _find(evs, "RulingExecuted")[0]
        assert a["amountToWorker"] == AMOUNT
        assert a["amountToPayer"] == 0
        assert a["bondTo"].lower() == env.agent.address.lower()
        assert env.state(jid) == RELEASED

        # 60% to worker: bond follows the ruling to the worker.
        jid = env.create_disputed_job(by="payer")
        amt = AMOUNT * 60 // 100
        r = _tx_ok(env, lambda: env.escrow.functions.executeRuling(
            jid, amt), env.operator)
        evs = _events(env, r)
        assert _names(evs) == ["RulingExecuted"]
        a = _find(evs, "RulingExecuted")[0]
        assert a["amountToWorker"] == amt
        assert a["amountToPayer"] == AMOUNT - amt
        assert a["bondTo"].lower() == env.agent.address.lower()
        assert env.state(jid) == RELEASED

        # 0% to worker: RulingExecuted + JobRefunded, bond to payer.
        jid = env.create_disputed_job(by="payer")
        r = _tx_ok(env, lambda: env.escrow.functions.executeRuling(
            jid, 0), env.operator)
        evs = _events(env, r)
        assert _names(evs) == ["JobRefunded", "RulingExecuted"]
        ref = _find(evs, "JobRefunded")[0]
        assert ref["jobId"] == jid
        assert ref["amount"] == AMOUNT
        assert _find(evs, "RulingExecuted")[0]["bondTo"].lower() == \
            env.payer.address.lower()
        assert env.state(jid) == REFUNDED

    def test_r1_settle_events(self, env):
        # 100% settle: SettledByAgreement only.
        jid = env.create_disputed_job(by="payer")
        dl = env.deadline_in(86400)
        sig = env.sign_settle(env.agent, jid, AMOUNT, deadline=dl)
        r = _tx_ok(env, lambda: env.escrow.functions.settleByAgreement(
            jid, AMOUNT, dl, sig), env.payer)
        evs = _events(env, r)
        assert _names(evs) == ["SettledByAgreement"]
        a = _find(evs, "SettledByAgreement")[0]
        assert a["amountToWorker"] == AMOUNT
        assert a["amountToPayer"] == 0
        assert env.state(jid) == RELEASED

        # 0% settle: SettledByAgreement + JobRefunded.
        jid = env.create_disputed_job(by="payer")
        dl = env.deadline_in(86400)
        sig = env.sign_settle(env.agent, jid, 0, deadline=dl)
        r = _tx_ok(env, lambda: env.escrow.functions.settleByAgreement(
            jid, 0, dl, sig), env.payer)
        evs = _events(env, r)
        assert _names(evs) == ["JobRefunded", "SettledByAgreement"]
        assert env.state(jid) == REFUNDED

    def test_r1_valve_events(self, env):
        jid = env.create_disputed_job(by="payer")
        bond = bond_for(AMOUNT)
        env.time_travel(RULING_PERIOD + 60)
        r = _tx_ok(env, lambda: env.escrow.functions.refundDisputeTimeout(
            jid), env.stranger)
        evs = _events(env, r)
        assert _names(evs) == ["JobRefunded", "DisputeTimeoutRefunded"]
        a = _find(evs, "DisputeTimeoutRefunded")[0]
        assert a["jobId"] == jid
        assert a["payer"].lower() == env.payer.address.lower()
        assert a["amount"] == AMOUNT
        assert a["bond"] == bond
        assert env.state(jid) == REFUNDED

    def test_r1_cancel_events(self, env):
        # Created -> JobCancelled.
        jid = env.create_job(env.agent.address)
        r = _tx_ok(env, lambda: env.escrow.functions.cancel(jid), env.payer)
        evs = _events(env, r)
        assert _names(evs) == ["JobCancelled"]
        assert _find(evs, "JobCancelled")[0]["jobId"] == jid
        assert env.state(jid) == CANCELLED

        # Accepted past deadline -> JobRefunded (ghosted-agent exit).
        jid = env.create_job(env.agent.address, deadline_seconds=3600)
        _tx_ok(env, lambda: env.escrow.functions.acceptJob(jid), env.agent)
        env.time_travel(3601)
        r = _tx_ok(env, lambda: env.escrow.functions.cancel(jid), env.payer)
        evs = _events(env, r)
        assert _names(evs) == ["JobRefunded"]
        ref = _find(evs, "JobRefunded")[0]
        assert ref["jobId"] == jid
        assert ref["amount"] == AMOUNT
        assert env.state(jid) == REFUNDED

    def test_r1_partial_and_release_events(self, env):
        jid = env.create_delivered_job(review_window=3600)
        dl = env.deadline_in(86400)
        sig = env.sign_partial(env.agent, jid, 400_000_000, deadline=dl)
        r = _tx_ok(env, lambda: env.escrow.functions.releasePartial(
            jid, 400_000_000, dl, sig), env.payer)
        evs = _events(env, r)
        pr = _find(evs, "JobPartiallyReleased")
        assert len(pr) == 1
        assert pr[0]["jobId"] == jid
        assert pr[0]["amountToAgent"] == 400_000_000
        assert pr[0]["amountToPayer"] == AMOUNT - 400_000_000
        assert env.state(jid) == RELEASED

        jid = env.create_delivered_job(review_window=3600)
        r = _tx_ok(env, lambda: env.escrow.functions.release(jid), env.payer)
        evs = _events(env, r)
        rel = _find(evs, "JobReleased")
        assert len(rel) == 1
        assert rel[0]["jobId"] == jid
        assert rel[0]["amount"] == AMOUNT
        assert rel[0]["agent"].lower() == env.agent.address.lower()
        assert env.state(jid) == RELEASED

    def test_r1_whitelist_and_withdraw_events(self, env):
        # ToggleToken: fund while healthy, break it, release -> credit.
        token = _deploy_toggle(env)
        _tx_ok(env, lambda: env.escrow.functions.setTokenAllowed(
            token.address, True), env.operator)
        _fund_token(env, token, env.payer, 100_000_000)
        jid = _create_with_token(env, token.address, env.payer,
                                 env.agent.address, 100_000_000)
        _tx_ok(env, lambda: env.escrow.functions.acceptJob(jid), env.agent)
        dh = env.w3.keccak(text="tw")
        _tx_ok(env, lambda: env.escrow.functions.submitDelivery(
            jid, dh, "toggle delivery"), env.agent)
        token.functions.setBroken(True).transact({"from": env.funder})
        r = _tx_ok(env, lambda: env.escrow.functions.release(jid), env.payer)
        evs = _events(env, r)
        assert _names(evs) == ["Credited", "JobReleased"]
        cr = _find(evs, "Credited")[0]
        assert cr["token"].lower() == token.address.lower()
        assert cr["account"].lower() == env.agent.address.lower()
        assert cr["amount"] == 100_000_000
        assert env.escrow.functions.pendingCredit(
            token.address, env.agent.address).call() == 100_000_000

        # Heal, withdraw -> Withdrawn, credit zeroed.
        token.functions.setBroken(False).transact({"from": env.funder})
        r = _tx_ok(env, lambda: env.escrow.functions.withdraw(
            token.address), env.agent)
        evs = _events(env, r)
        wd = _find(evs, "Withdrawn")
        assert len(wd) == 1
        assert wd[0]["account"].lower() == env.agent.address.lower()
        assert wd[0]["to"].lower() == env.agent.address.lower()
        assert wd[0]["amount"] == 100_000_000
        assert env.escrow.functions.pendingCredit(
            token.address, env.agent.address).call() == 0

        # Whitelist toggle emits TokenWhitelisted.
        r = _tx_ok(env, lambda: env.escrow.functions.setTokenAllowed(
            token.address, False), env.operator)
        evs = _events(env, r)
        tw = _find(evs, "TokenWhitelisted")
        assert len(tw) == 1
        assert tw[0]["token"].lower() == token.address.lower()
        assert tw[0]["allowed"] is False

    def test_r1_event_fields_gap(self, env):
        """FINDING: JobCreated omits deadlineSeconds and reviewWindow,
        and DisputeRaised omits the reason text. A pure-event indexer
        cannot compute claim deadlines or read the reason from the log.
        The watcher recipe is events + getJob (still zero off-chain
        storage — getJob is chain data). The contract was NOT changed
        for this: the size direction is smaller, not bigger."""
        jid = env.create_delivered_job(review_window=3600)
        # Re-create one job and inspect the raw JobCreated args.
        env.mint_and_approve(env.payer, AMOUNT)
        r = _tx_ok(env, lambda: env.escrow.functions.createJob(
            env.agent.address, env.token_addr, AMOUNT, 3600, 3600,
            "gap-job"), env.payer)
        created = _find(_events(env, r), "JobCreated")[0]
        assert set(created.keys()) == {
            "jobId", "payer", "agent", "token", "amount", "deadline",
            "metadataURI",
        }, f"JobCreated args changed: {sorted(created.keys())}"
        assert "deadlineSeconds" not in created
        assert "reviewWindow" not in created

        bond = bond_for(AMOUNT)
        env.mint_and_approve(env.payer, bond, approve=bond)
        r = _tx_ok(env, lambda: env.escrow.functions.raiseDispute(
            jid, "the reason text"), env.payer)
        raised = _find(_events(env, r), "DisputeRaised")[0]
        assert set(raised.keys()) == {"jobId", "by"}, \
            f"DisputeRaised args changed: {sorted(raised.keys())}"
        assert "reason" not in raised

        # But getJob carries everything the watcher needs.
        job = env.job(jid)
        assert job[10] == DEADLINE_SECONDS  # deadlineSeconds (24h default)
        assert job[5] == 3600  # reviewWindow
        assert job[12] == "the reason text"  # disputeReason
        # Claim deadline is derivable: deliveredAt + reviewWindow.
        assert job[9] > 0  # deliveredAt
        assert job[9] + job[5] > env.now()

# ============================================================ R2: view accuracy

class TestR2Views:
    def test_r2_views_match_ground_truth(self, env):
        """Mixed scenario: views vs hand-computed ground truth and the
        events-only model, at every step."""
        model = ChainModel()
        token = env.token_addr

        def do(fn_builder, acct):
            r = _tx_ok(env, fn_builder, acct)
            _apply_all(env, model, r)
            _check_model(env, model, token, "r2")
            return r

        # 5 named jobs + 1 open job, mixed amounts.
        amounts = [100_000_000, 250_000_000, 50_000_000, 300_000_000, 5_000_000]
        for i, amt in enumerate(amounts):
            payer = env.payer if i % 2 == 0 else env.agent
            worker = env.agent if i % 2 == 0 else env.stranger
            # Note: payer/agent roles rotate; stranger acts as worker here.
            env.mint_and_approve(payer, amt)
            do(lambda p=payer, w=worker, a=amt, j=i: env.escrow.functions.createJob(
                w.address, token, a, 3600, 3600, f"v{j}"), payer)
        env.mint_and_approve(env.payer, 120_000_000)
        do(lambda: env.escrow.functions.createOpenJob(
            token, 120_000_000, 3600, 3600, "v-open"), env.payer)

        assert env.escrow.functions.jobCount().call() == 6

        # Accept 0,1,5; deliver 0,1; dispute 1 (agent 2nd party);
        # release 0; cancel 4 (never accepted).
        do(lambda: env.escrow.functions.acceptJob(0), env.agent)
        do(lambda: env.escrow.functions.acceptJob(1), env.stranger)
        do(lambda: env.escrow.functions.acceptJob(5), env.stranger)
        dh = env.w3.keccak(text="r2")
        do(lambda: env.escrow.functions.submitDelivery(
            0, dh, "d0"), env.agent)
        do(lambda: env.escrow.functions.submitDelivery(
            1, dh, "d1"), env.stranger)
        # Job 1 payer is env.agent (i=1 odd) — dispute by the payer.
        bond1 = bond_for(amounts[1])
        env.mint_and_approve(env.agent, bond1, approve=bond1)
        do(lambda: env.escrow.functions.raiseDispute(1, "bad"), env.agent)
        do(lambda: env.escrow.functions.release(0), env.payer)
        do(lambda: env.escrow.functions.cancel(4), env.payer)

        # totalUnsettled: job 1 (disputed, 250M), job 2 (created, 50M),
        # job 3 (created, 300M), job 5 (accepted, 120M) = 720M.
        # Job 0 released, job 4 cancelled -> excluded.
        unsettled = env.escrow.functions.totalUnsettled(token).call()
        assert unsettled == 250_000_000 + 50_000_000 + 300_000_000 + 120_000_000, \
            f"got {unsettled}"
        # Bonded: only job 1's bond.
        assert env.escrow.functions.totalBonded(token).call() == bond1
        # Manual getJob scan agrees.
        manual = 0
        for jid in range(6):
            job = env.job(jid)
            if job[6] in (CREATED, ACCEPTED, DELIVERED, DISPUTED):
                manual += job[3]
        assert manual == unsettled, f"view {unsettled} vs scan {manual}"
        # Invariant holds; no credits yet (plain token, no failures).
        _, usum, bsum, csum, holds = env.escrow.functions.settlementInvariant(
            token).call()
        assert holds is True
        assert usum == unsettled and bsum == bond1 and csum == 0

    def test_r2_credit_views_with_failing_token(self, env):
        """pendingCredit / totalPendingCredits stay exact when a payout
        fails and credits, then withdraws."""
        token = _deploy_toggle(env)
        _tx_ok(env, lambda: env.escrow.functions.setTokenAllowed(
            token.address, True), env.operator)
        _fund_token(env, token, env.payer, 100_000_000)
        jid = _create_with_token(env, token.address, env.payer,
                                 env.agent.address, 100_000_000)
        _tx_ok(env, lambda: env.escrow.functions.acceptJob(jid), env.agent)
        dh = env.w3.keccak(text="cv")
        _tx_ok(env, lambda: env.escrow.functions.submitDelivery(
            jid, dh, "credit job"), env.agent)
        assert env.escrow.functions.totalPendingCredits(token.address).call() == 0
        assert env.escrow.functions.pendingCredit(
            token.address, env.agent.address).call() == 0

        token.functions.setBroken(True).transact({"from": env.funder})
        _tx_ok(env, lambda: env.escrow.functions.release(jid), env.payer)
        assert env.escrow.functions.pendingCredit(
            token.address, env.agent.address).call() == 100_000_000
        assert env.escrow.functions.totalPendingCredits(token.address).call() == \
            100_000_000
        _, _, _, csum, holds = env.escrow.functions.settlementInvariant(
            token.address).call()
        assert holds is True
        assert csum == 100_000_000

        token.functions.setBroken(False).transact({"from": env.funder})
        _tx_ok(env, lambda: env.escrow.functions.withdraw(
            token.address), env.agent)
        assert env.escrow.functions.pendingCredit(
            token.address, env.agent.address).call() == 0
        assert env.escrow.functions.totalPendingCredits(token.address).call() == 0
        _, _, _, csum, holds = env.escrow.functions.settlementInvariant(
            token.address).call()
        assert holds is True and csum == 0


# ============================================================ R3: off-chain reconstruction

class TestR3Model:
    def test_r3_rich_scenario_matches_chain(self, env):
        """Scripted rich scenario: the events-only model must match
        on-chain getJob for every job, and the accounting views."""
        model = ChainModel()
        token = env.token_addr

        def do(fn_builder, acct):
            r = _tx_ok(env, fn_builder, acct)
            _apply_all(env, model, r)
            _check_model(env, model, token, "r3-rich")
            return r

        # 4 named + 2 open.
        env.mint_and_approve(env.payer, 100_000_000)
        do(lambda: env.escrow.functions.createJob(
            env.agent.address, token, 100_000_000, 3600, 3600, "s0"), env.payer)
        env.mint_and_approve(env.agent, 200_000_000)
        do(lambda: env.escrow.functions.createJob(
            env.stranger.address, token, 200_000_000, 7200, 3600, "s1"), env.agent)
        env.mint_and_approve(env.payer, 150_000_000)
        do(lambda: env.escrow.functions.createOpenJob(
            token, 150_000_000, 3600, 3600, "o2"), env.payer)
        env.mint_and_approve(env.agent, 50_000_000)
        do(lambda: env.escrow.functions.createOpenJob(
            token, 50_000_000, 3600, 3600, "o3"), env.agent)
        env.mint_and_approve(env.payer, 80_000_000)
        do(lambda: env.escrow.functions.createJob(
            env.agent.address, token, 80_000_000, 3600, 3600, "s4"), env.payer)
        env.mint_and_approve(env.agent, 40_000_000)
        do(lambda: env.escrow.functions.createJob(
            env.stranger.address, token, 40_000_000, 3600, 3600, "s5"), env.agent)

        # Accepts (open claims by third parties).
        do(lambda: env.escrow.functions.acceptJob(0), env.agent)
        do(lambda: env.escrow.functions.acceptJob(1), env.stranger)
        do(lambda: env.escrow.functions.acceptJob(2), env.stranger)
        do(lambda: env.escrow.functions.acceptJob(3), env.stranger)
        do(lambda: env.escrow.functions.acceptJob(4), env.agent)

        # Deliveries.
        dh = env.w3.keccak(text="r3")
        for jid, worker in [(0, env.agent), (1, env.stranger),
                            (2, env.stranger), (3, env.stranger),
                            (4, env.agent)]:
            do(lambda j=jid, w=worker: env.escrow.functions.submitDelivery(
                j, dh, f"delivered {j}"), worker)

        # Dispute job 1 (payer = env.agent), rule 60% to worker.
        bond1 = bond_for(200_000_000)
        env.mint_and_approve(env.agent, bond1, approve=bond1)
        do(lambda: env.escrow.functions.raiseDispute(1, "bad work"), env.agent)
        do(lambda: env.escrow.functions.executeRuling(
            1, 120_000_000), env.operator)

        # Release job 0, partial-release job 4 (50%).
        do(lambda: env.escrow.functions.release(0), env.payer)
        dl = env.deadline_in(86400)
        sig = env.sign_partial(env.agent, 4, 40_000_000, deadline=dl)
        do(lambda: env.escrow.functions.releasePartial(
            4, 40_000_000, dl, sig), env.payer)

        # Dispute job 2 (agent-raised, no bond), settle 100% by agreement.
        do(lambda: env.escrow.functions.raiseDispute(2, "agent dispute"),
           env.stranger)
        dl = env.deadline_in(86400)
        sig = env.sign_settle(env.payer, 2, 150_000_000, deadline=dl)
        do(lambda: env.escrow.functions.settleByAgreement(
            2, 150_000_000, dl, sig), env.stranger)

        # Dispute job 3 (payer = env.agent), valve timeout.
        bond3 = bond_for(50_000_000)
        env.mint_and_approve(env.agent, bond3, approve=bond3)
        do(lambda: env.escrow.functions.raiseDispute(3, "late"), env.agent)
        env.time_travel(RULING_PERIOD + 60)
        do(lambda: env.escrow.functions.refundDisputeTimeout(3), env.stranger)

        # Cancel job 5 (never accepted).
        do(lambda: env.escrow.functions.cancel(5), env.agent)

        # Final: every job terminal, unsettled and bonded both zero.
        assert env.escrow.functions.totalUnsettled(token).call() == 0
        assert env.escrow.functions.totalBonded(token).call() == 0
        _check_model(env, model, token, "r3-rich-final")

    def test_r3_random_sequences_match_chain(self):
        """Seeded random operation sequences: after every successful tx
        the events-only model must match the chain exactly. Each seed
        runs on a fresh chain (fresh Env)."""
        for seed in (11, 23, 47):
            self._run_random_seed(seed)

    def _run_random_seed(self, seed):
        from conftest import Env
        env = Env()
        rng = random.Random(seed)
        model = ChainModel()
        token = env.token_addr
        base = 0  # fresh chain: job ids start at 0

        payers = [env.payer, env.agent]
        workers = [env.agent, env.stranger]
        amounts = [5_000_000, 50_000_000, 200_000_000]
        jobs = {}  # jid -> {"payer": acct, "agent": acct, "amount": int}

        def do(fn_builder, acct):
            r = env.send_as(acct, fn_builder)
            if r["status"] != 1:
                return None
            _apply_all(env, model, r)
            _check_model(env, model, token, f"r3-seed{seed}")
            return r

        def new_job():
            payer = rng.choice(payers)
            agent = rng.choice(workers)
            amount = rng.choice(amounts)
            open_job = rng.random() < 0.3
            env.mint_and_approve(payer, amount)
            if open_job:
                r = do(lambda: env.escrow.functions.createOpenJob(
                    token, amount, 3600, 3600, "rand"), payer)
            else:
                r = do(lambda: env.escrow.functions.createJob(
                    agent.address, token, amount, 3600, 3600, "rand"), payer)
            if r is None:
                return
            jid = env.escrow.functions.jobCount().call() - 1
            jobs[jid] = {"payer": payer,
                         "agent": None if open_job else agent,
                         "amount": amount}

        def by_state(state):
            return [j for j in jobs
                    if env.state(j) == state and j >= base]

        for step in range(60):
            roll = rng.random()
            created = by_state(CREATED)
            accepted = by_state(ACCEPTED)
            delivered = by_state(DELIVERED)
            disputed = by_state(DISPUTED)
            if roll < 0.18 or not jobs:
                new_job()
            elif roll < 0.30 and created:
                jid = rng.choice(created)
                agent = jobs[jid]["agent"]
                if agent is None:
                    agent = rng.choice(
                        [a for a in workers + [env.stranger]
                         if a.address != jobs[jid]["payer"].address])
                    jobs[jid]["agent"] = agent
                do(lambda j=jid, a=agent: env.escrow.functions.acceptJob(j), agent)
            elif roll < 0.40 and accepted:
                jid = rng.choice(accepted)
                dh = env.w3.keccak(text=f"r3-{seed}-{step}")
                do(lambda j=jid: env.escrow.functions.submitDelivery(
                    j, dh, "random delivery"), jobs[jid]["agent"])
            elif roll < 0.45 and accepted:
                jid = rng.choice(accepted)
                dh = env.w3.keccak(text=f"r3d-{seed}-{step}")
                do(lambda j=jid: env.escrow.functions.submitDeliveryAndDispute(
                    j, dh, "random delivery", "random dispute"),
                    jobs[jid]["agent"])
            elif roll < 0.52 and delivered:
                jid = rng.choice(delivered)
                do(lambda j=jid: env.escrow.functions.release(j),
                   jobs[jid]["payer"])
            elif roll < 0.58 and delivered:
                jid = rng.choice(delivered)
                amt = jobs[jid]["amount"]
                pct = rng.choice([1, 25, 50, 100])
                split = max(amt * pct // 100, 1)
                dl = env.deadline_in(86400)
                sig = env.sign_partial(jobs[jid]["agent"], jid, split,
                                       deadline=dl)
                do(lambda j=jid, s=split, d=dl, sg=sig:
                   env.escrow.functions.releasePartial(j, s, d, sg),
                   jobs[jid]["payer"])
            elif roll < 0.66 and delivered:
                jid = rng.choice(delivered)
                by_payer = rng.random() < 0.5
                by = jobs[jid]["payer"] if by_payer else jobs[jid]["agent"]
                if by_payer:
                    env.mint_and_approve(by, bond_for(jobs[jid]["amount"]),
                                         approve=bond_for(jobs[jid]["amount"]))
                do(lambda j=jid, b=by: env.escrow.functions.raiseDispute(
                    j, "random reason"), by)
            elif roll < 0.74 and disputed:
                jid = rng.choice(disputed)
                pct = rng.choice([0, 25, 50, 60, 100])
                amt = jobs[jid]["amount"] * pct // 100
                do(lambda j=jid, a=amt: env.escrow.functions.executeRuling(
                    j, a), env.operator)
            elif roll < 0.80 and disputed:
                jid = rng.choice(disputed)
                pct = rng.choice([0, 25, 50, 100])
                amt = jobs[jid]["amount"] * pct // 100
                caller = rng.choice([jobs[jid]["payer"], jobs[jid]["agent"]])
                other = jobs[jid]["agent"] if caller == jobs[jid]["payer"] \
                    else jobs[jid]["payer"]
                dl = env.deadline_in(86400)
                sig = env.sign_settle(other, jid, amt, deadline=dl)
                do(lambda j=jid, a=amt, d=dl, s=sig:
                   env.escrow.functions.settleByAgreement(j, a, d, s), caller)
            elif roll < 0.84 and disputed:
                jid = rng.choice(disputed)
                do(lambda j=jid: env.escrow.functions.refundDisputeTimeout(j),
                   env.stranger)
            elif roll < 0.90:
                pool = created + accepted
                if pool:
                    jid = rng.choice(pool)
                    do(lambda j=jid: env.escrow.functions.cancel(j),
                       jobs[jid]["payer"])
            elif roll < 0.95:
                acct = rng.choice([env.payer, env.agent, env.stranger])
                do(lambda a=acct: env.escrow.functions.withdraw(token), acct)
            else:
                env.time_travel(rng.choice([3600, 24 * 3600, 80 * 3600]))
                _check_model(env, model, token, f"r3-seed{seed}-time")

        _check_model(env, model, token, f"r3-seed{seed}-final")


# ============================================================ R4: accounting edges

class TestR4Edges:
    def test_r4_odd_partial_exact(self, env):
        """999-unit job, 333/666 split: sums exactly, unsettled -> 0."""
        jid = env.create_delivered_job(review_window=3600, amount=999)
        dl = env.deadline_in(86400)
        sig = env.sign_partial(env.agent, jid, 333, deadline=dl)
        w0 = env.balance(env.agent.address)
        p0 = env.balance(env.payer.address)
        r = _tx_ok(env, lambda: env.escrow.functions.releasePartial(
            jid, 333, dl, sig), env.payer)
        evs = _events(env, r)
        pr = _find(evs, "JobPartiallyReleased")[0]
        assert pr["amountToAgent"] == 333
        assert pr["amountToPayer"] == 666
        assert env.balance(env.agent.address) - w0 == 333
        assert env.balance(env.payer.address) - p0 == 666
        assert env.escrow.functions.totalUnsettled(env.token_addr).call() == 0
        _, _, _, _, holds = env.escrow.functions.settlementInvariant(
            env.token_addr).call()
        assert holds is True

    def test_r4_dispute_split_accounting(self, env):
        """Ruling 70/30 on a $100 job: worker 70, payer 30, bond to
        worker (>= 50%). All legs exact, books zeroed."""
        jid = env.create_disputed_job(by="payer", amount=100_000_000,
                                      review_window=3600)
        bond = bond_for(100_000_000)
        w0 = env.balance(env.agent.address)
        p0 = env.balance(env.payer.address)
        r = _tx_ok(env, lambda: env.escrow.functions.executeRuling(
            jid, 70_000_000), env.operator)
        assert env.balance(env.agent.address) - w0 == 70_000_000 + bond
        assert env.balance(env.payer.address) - p0 == 30_000_000
        assert env.escrow.functions.totalUnsettled(env.token_addr).call() == 0
        assert env.escrow.functions.totalBonded(env.token_addr).call() == 0
        _, _, _, _, holds = env.escrow.functions.settlementInvariant(
            env.token_addr).call()
        assert holds is True

    def test_r4_valve_accounting(self, env):
        """Valve: job + bond refund to payer in full, books zeroed."""
        jid = env.create_disputed_job(by="payer", amount=100_000_000,
                                      review_window=3600)
        bond = bond_for(100_000_000)
        p0 = env.balance(env.payer.address)
        env.time_travel(RULING_PERIOD + 60)
        _tx_ok(env, lambda: env.escrow.functions.refundDisputeTimeout(jid),
               env.stranger)
        assert env.balance(env.payer.address) - p0 == 100_000_000 + bond
        assert env.escrow.functions.totalUnsettled(env.token_addr).call() == 0
        assert env.escrow.functions.totalBonded(env.token_addr).call() == 0
        _, _, _, _, holds = env.escrow.functions.settlementInvariant(
            env.token_addr).call()
        assert holds is True

    def test_r4_credit_tracking(self, env):
        """Credit issued on failed payout, tracked in views, withdrawn
        once, replay reverts — views exact at every step."""
        token = _deploy_toggle(env)
        _tx_ok(env, lambda: env.escrow.functions.setTokenAllowed(
            token.address, True), env.operator)
        _fund_token(env, token, env.payer, 100_000_000)
        jid = _create_with_token(env, token.address, env.payer,
                                 env.agent.address, 100_000_000)
        _tx_ok(env, lambda: env.escrow.functions.acceptJob(jid), env.agent)
        dh = env.w3.keccak(text="r4c")
        _tx_ok(env, lambda: env.escrow.functions.submitDelivery(
            jid, dh, "credit job"), env.agent)
        token.functions.setBroken(True).transact({"from": env.funder})
        _tx_ok(env, lambda: env.escrow.functions.release(jid), env.payer)
        assert env.escrow.functions.totalPendingCredits(token.address).call() \
            == 100_000_000
        assert env.escrow.functions.pendingCredit(
            token.address, env.agent.address).call() == 100_000_000
        _, usum, _, csum, holds = env.escrow.functions.settlementInvariant(
            token.address).call()
        assert holds is True and usum == 0 and csum == 100_000_000

        token.functions.setBroken(False).transact({"from": env.funder})
        w0 = token.functions.balanceOf(env.agent.address).call()
        _tx_ok(env, lambda: env.escrow.functions.withdraw(token.address),
               env.agent)
        assert token.functions.balanceOf(env.agent.address).call() - w0 \
            == 100_000_000
        assert env.escrow.functions.totalPendingCredits(token.address).call() == 0
        # Withdraw replay reverts (credit zeroed before transfer).
        env.assert_reverts(env.agent, lambda: env.escrow.functions.withdraw(
            token.address), "nothing to withdraw")


# ============================================================ R5: dispute watcher

class TestR5Watcher:
    def test_r5_watcher_from_chain_only(self, env):
        """Simulate the dispute watcher: from DisputeRaised logs alone +
        on-chain views, recover everything needed to act — no off-chain
        DB required."""
        jid = env.create_delivered_job(review_window=3600)
        r = _tx_ok(env, lambda: env.escrow.functions.raiseDispute(
            jid, "watch me"), env.agent)

        # 1. Detect: filter logs for DisputeRaised.
        logs = env.escrow.events.DisputeRaised().process_receipt(r)
        assert len(logs) == 1
        job_id = logs[0]["args"]["jobId"]
        raiser = logs[0]["args"]["by"]
        assert job_id == jid
        assert raiser.lower() == env.agent.address.lower()
        block_ts = env.w3.eth.get_block(r["blockNumber"])["timestamp"]

        # 2. Enrich purely on-chain: getJob (no off-chain DB).
        job = env.job(job_id)
        payer, agent, token, amount = job[0], job[1], job[2], job[3]
        assert payer.lower() == env.payer.address.lower()
        assert agent.lower() == env.agent.address.lower()
        assert amount == AMOUNT
        assert job[12] == "watch me"  # disputeReason, from getJob
        assert job[14] == block_ts  # disputedAt matches the log's block

        # 3. Ruling deadline is derivable from the log + the public
        #    constant: disputedAt + 72h. No view call needed for this.
        ruling_period = env.escrow.functions.RULING_PERIOD().call()
        assert ruling_period == 72 * 3600
        rule_by = job[14] + ruling_period
        assert rule_by > env.now()

        payload = {
            "jobId": job_id,
            "raiser": raiser,
            "payer": payer,
            "agent": agent,
            "amount": amount,
            "token": token,
            "metadataURI": job[8],
            "disputeReason": job[12],
            "ruleBy": rule_by,
        }
        assert payload["amount"] == AMOUNT
        assert payload["metadataURI"] == "test job"
        assert payload["disputeReason"] == "watch me"

        # 4. Already-resolved disputes detectable: second watcher run
        #    sees state != DISPUTED and skips (no double-ping).
        _tx_ok(env, lambda: env.escrow.functions.executeRuling(
            job_id, AMOUNT), env.operator)
        assert env.state(job_id) == RELEASED  # watcher would skip

    def test_r5_watcher_scan_pattern(self, env):
        """Watcher startup scan: iterate jobCount, find currently-disputed
        jobs via getJob — no event-log dependency for the backlog."""
        _ = env.create_delivered_job(review_window=3600)  # job 0
        jid1 = env.create_job(env.agent.address)  # job 1, created only
        env.mint_and_approve(env.payer, bond_for(AMOUNT),
                             approve=bond_for(AMOUNT))
        _tx_ok(env, lambda: env.escrow.functions.raiseDispute(
            0, "scan me"), env.payer)

        disputed = []
        for j in range(env.escrow.functions.jobCount().call()):
            if env.state(j) == DISPUTED:
                disputed.append(j)
        assert disputed == [0]

    def test_r5_watcher_claim_deadline_needs_getjob(self, env):
        """The agent-claim deadline (deliveredAt + reviewWindow) is NOT
        derivable from events alone — reviewWindow is not in any event
        (see the R1 gap test). The watcher gets it from getJob; this
        test locks in that recipe and its arithmetic."""
        jid = env.create_delivered_job(review_window=3600)
        job = env.job(jid)
        delivered_at, review_window = job[9], job[5]
        assert delivered_at > 0 and review_window == 3600
        agent_claim_at = delivered_at + review_window
        # Before the window ends the agent cannot claim; after it, it can.
        env.assert_call_reverts(
            env.agent, lambda: env.escrow.functions.release(jid),
            "review window not ended")
        env.time_travel_to(agent_claim_at + 1)
        r = _tx_ok(env, lambda: env.escrow.functions.release(jid), env.agent)
        assert _find(_events(env, r), "JobReleased")
        assert env.state(jid) == RELEASED
