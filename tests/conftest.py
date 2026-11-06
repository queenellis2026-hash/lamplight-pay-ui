#!/usr/bin/env python3
"""Shared eth-tester harness for AgentEscrowV3 tests.

Every test gets a fresh deployment (function-scoped ``env`` fixture):
a MockToken, the V3 escrow with a single operator, and the token
whitelisted via setTokenAllowed. Helpers cover EIP-712 signing
(PartialRelease / SettleDispute, domain AgentEscrowV3), sending signed
txs as local accounts, revert assertions, time travel, and the
create -> accept -> deliver job lifecycle. Dispute helpers post the
20% bond (min $1, max $50) on payer-raised disputes.
"""
import json
import os

import pytest
import solcx
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_tester import EthereumTester, PyEVMBackend
from web3 import Web3
from web3.providers.eth_tester import EthereumTesterProvider

MOCK_ERC20_SOURCE = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
contract MockToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint8 public decimals = 6; // USD-stablecoin units, like USDC/USDT
    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "insufficient");
        require(allowance[from][msg.sender] >= amount, "no allowance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
'''

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_N_HALF = SECP256K1_N // 2

# Job amounts: 1000 USDC-style units (6 decimals)
AMOUNT = 1000 * 10**6
REVIEW_WINDOW = 48 * 3600
DEADLINE_SECONDS = 24 * 3600
RULING_PERIOD = 72 * 3600

# Bond: 20% of job amount, min $1, max $50 (6-decimal units)
BOND_BPS = 2000
BOND_MIN = 1_000_000
BOND_MAX = 50_000_000

# Review-window tiers (job amount in USD, 6-decimal units)
TIER1_MAX_AMOUNT = 10_000_000    # $10
TIER2_MAX_AMOUNT = 100_000_000   # $100

# Job State enum indices
CREATED, ACCEPTED, DELIVERED, DISPUTED, RELEASED, REFUNDED, CANCELLED = range(7)


def bond_for(amount):
    """Mirror of the contract's _bondAmount: 20%, min $1, max $50."""
    bond = amount * BOND_BPS // 10000
    if bond < BOND_MIN:
        bond = BOND_MIN
    if bond > BOND_MAX:
        bond = BOND_MAX
    return bond


def normalize_sig(sig_bytes):
    """Convert to low-s form (EIP-2) so the contract's malleability check passes."""
    r = int.from_bytes(sig_bytes[0:32], 'big')
    s = int.from_bytes(sig_bytes[32:64], 'big')
    v = sig_bytes[64]
    if s > SECP256K1_N_HALF:
        s = SECP256K1_N - s
        v = 28 if v == 27 else 27
    return r.to_bytes(32, 'big') + s.to_bytes(32, 'big') + bytes([v])


def _typed_data(chain_id, contract_addr, primary_type, type_fields, message):
    return {
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
            "chainId": chain_id,
            "verifyingContract": contract_addr,
        },
        "message": message,
    }


class Env:
    def __init__(self):
        solcx.set_solc_version('0.8.24')
        self.tester = EthereumTester(PyEVMBackend())
        self.w3 = Web3(EthereumTesterProvider(self.tester))
        self.chain_id = self.w3.eth.chain_id
        self.funder = self.w3.eth.accounts[0]

        self.operator = Account.create()
        self.payer = Account.create()
        self.agent = Account.create()
        self.stranger = Account.create()
        for acct in [self.operator, self.payer, self.agent, self.stranger]:
            self.w3.eth.send_transaction({
                'from': self.funder, 'to': acct.address,
                'value': self.w3.to_wei(10, 'ether'), 'gas': 21000,
            })

        # Deploy mock token
        compiled = solcx.compile_source(
            MOCK_ERC20_SOURCE, output_values=['abi', 'bin'], solc_version='0.8.24')
        t_data = compiled['<stdin>:MockToken']
        Token = self.w3.eth.contract(abi=t_data['abi'], bytecode=t_data['bin'])
        tx = Token.constructor().transact({'from': self.funder, 'gas': 2000000})
        self.token_addr = self.w3.eth.wait_for_transaction_receipt(tx).contractAddress
        self.token = self.w3.eth.contract(address=self.token_addr, abi=t_data['abi'])

        # Deploy escrow (operator set in constructor)
        build_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            '..', 'contracts', 'build-AgentEscrowV3.json')
        with open(build_path) as f:
            build = json.load(f)
        Escrow = self.w3.eth.contract(abi=build['abi'], bytecode=build['bytecode'])
        tx = Escrow.constructor(
            self.operator.address
        ).transact({'from': self.funder, 'gas': 8000000})
        self.escrow_addr = self.w3.eth.wait_for_transaction_receipt(tx).contractAddress
        self.escrow = self.w3.eth.contract(address=self.escrow_addr, abi=build['abi'])

        # Whitelist the token via the operator
        r = self.send_as(self.operator, lambda: self.escrow.functions.setTokenAllowed(
            self.token_addr, True))
        assert r['status'] == 1, "token whitelist failed in setup"
        assert self.escrow.functions.allowedTokens(self.token_addr).call() is True

    # ---- chain helpers -------------------------------------------------
    def now(self):
        return self.w3.eth.get_block('latest')['timestamp']

    def deadline_in(self, seconds=86400):
        return self.now() + seconds

    def time_travel(self, seconds):
        """Advance chain time by `seconds` from the latest block."""
        self.tester.time_travel(self.now() + seconds)
        self.tester.mine_block()

    def time_travel_to(self, timestamp):
        self.tester.time_travel(timestamp)
        self.tester.mine_block()

    # ---- signing -------------------------------------------------------
    def _sign(self, acct, primary_type, type_fields, message):
        td = _typed_data(self.chain_id, self.escrow_addr,
                         primary_type, type_fields, message)
        raw = acct.sign_message(encode_typed_data(full_message=td)).signature
        return normalize_sig(raw)

    def sign_partial(self, acct, job_id, amount, deadline=None):
        if deadline is None:
            deadline = self.deadline_in(86400)
        return self._sign(acct, "PartialRelease", [
            {"name": "jobId", "type": "uint256"},
            {"name": "amountToWorker", "type": "uint256"},
            {"name": "deadline", "type": "uint256"},
        ], {"jobId": job_id, "amountToWorker": amount, "deadline": deadline})

    def sign_settle(self, acct, job_id, amount, deadline=None):
        if deadline is None:
            deadline = self.deadline_in(86400)
        return self._sign(acct, "SettleDispute", [
            {"name": "jobId", "type": "uint256"},
            {"name": "amountToWorker", "type": "uint256"},
            {"name": "deadline", "type": "uint256"},
        ], {"jobId": job_id, "amountToWorker": amount, "deadline": deadline})

    # ---- tx helpers ----------------------------------------------------
    def send_as(self, acct, fn_builder, gas=500000):
        """Build, sign, and send a tx as acct. Returns the receipt."""
        tx = fn_builder().build_transaction({
            'from': acct.address,
            'nonce': self.w3.eth.get_transaction_count(acct.address),
            'gas': gas, 'gasPrice': self.w3.eth.gas_price, 'chainId': self.chain_id,
        })
        signed = acct.sign_transaction(tx)
        h = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        return self.w3.eth.wait_for_transaction_receipt(h)

    def assert_call_reverts(self, acct, fn_builder, substr=None):
        """Assert the eth_call reverts, WITHOUT sending an on-chain tx.
        Use at exact time boundaries: a confirming tx mines one second
        later, which can flip a strict `>` time gate and succeed."""
        from_addr = acct.address if hasattr(acct, 'address') else acct
        try:
            fn_builder().call({'from': from_addr})
        except Exception as e:
            err = str(e)
            if substr is not None:
                assert substr in err, (
                    f"expected revert containing {substr!r}, got: {err[:200]}")
            return
        raise AssertionError(
            f"expected revert{' containing ' + repr(substr) if substr else ''} but call succeeded")

    def assert_reverts(self, acct, fn_builder, substr=None):
        """Assert the call reverts (checking the reason via eth_call) and
        that a real tx also fails (status 0). `acct` may be a LocalAccount
        or a plain address string (e.g. the eth-tester funder)."""
        from_addr = acct.address if hasattr(acct, 'address') else acct
        try:
            fn_builder().call({'from': from_addr})
        except Exception as e:
            err = str(e)
            if substr is not None:
                assert substr in err, (
                    f"expected revert containing {substr!r}, got: {err[:200]}")
            # Confirm on-chain too
            if hasattr(acct, 'address'):
                receipt = self.send_as(acct, fn_builder)
            else:
                tx = fn_builder().transact({'from': from_addr, 'gas': 500000})
                receipt = self.w3.eth.wait_for_transaction_receipt(tx)
            assert receipt['status'] == 0, "tx succeeded but eth_call reverted"
            return receipt
        raise AssertionError(
            f"expected revert{' containing ' + repr(substr) if substr else ''} but call succeeded")

    # ---- job lifecycle -------------------------------------------------
    def mint_and_approve(self, acct, amount, approve=None):
        if approve is None:
            approve = amount
        self.token.functions.mint(acct.address, amount).transact({'from': self.funder})
        tx = self.token.functions.approve(self.escrow_addr, approve).build_transaction({
            'from': acct.address,
            'nonce': self.w3.eth.get_transaction_count(acct.address),
            'gas': 100000, 'gasPrice': self.w3.eth.gas_price, 'chainId': self.chain_id,
        })
        self.w3.eth.send_raw_transaction(acct.sign_transaction(tx).raw_transaction)

    def create_job(self, agent_addr=None, amount=AMOUNT,
                   review_window=REVIEW_WINDOW, deadline_seconds=DEADLINE_SECONDS,
                   payer=None):
        """Create a job (named agent, or open if agent_addr is None). Returns jobId."""
        payer = payer or self.payer
        self.mint_and_approve(payer, amount)
        if agent_addr is None:
            r = self.send_as(payer, lambda: self.escrow.functions.createOpenJob(
                self.token_addr, amount, deadline_seconds, review_window, "test job"))
        else:
            r = self.send_as(payer, lambda: self.escrow.functions.createJob(
                agent_addr, self.token_addr, amount, deadline_seconds,
                review_window, "test job"))
        assert r['status'] == 1, "createJob failed"
        return self.escrow.functions.jobCount().call() - 1

    def create_delivered_job(self, review_window=REVIEW_WINDOW, amount=AMOUNT):
        """Create -> accept -> deliver. Returns jobId."""
        job_id = self.create_job(self.agent.address, amount=amount,
                                 review_window=review_window)
        r = self.send_as(self.agent, lambda: self.escrow.functions.acceptJob(job_id))
        assert r['status'] == 1, "acceptJob failed"
        dh = self.w3.keccak(text=f"delivery-{job_id}")
        r = self.send_as(self.agent, lambda: self.escrow.functions.submitDelivery(
            job_id, dh, f"delivery text for job {job_id}"))
        assert r['status'] == 1, "submitDelivery failed"
        return job_id

    def create_disputed_job(self, review_window=REVIEW_WINDOW, amount=AMOUNT,
                            by="payer"):
        """Create -> accept -> deliver -> raiseDispute. Returns jobId.
        Payer-raised disputes post the 20% bond (min $1, max $50), so the
        payer is funded for amount + bond. Agent-raised disputes
        (submitDeliveryAndDispute) post no bond."""
        if by == "payer":
            bond = bond_for(amount)
            job_id = self.create_delivered_job(review_window=review_window, amount=amount)
            # Top up the payer's approval for the bond (create consumed `amount`)
            self.mint_and_approve(self.payer, bond, approve=bond)
            r = self.send_as(self.payer, lambda: self.escrow.functions.raiseDispute(
                job_id, "dispute reason"))
            assert r['status'] == 1, "raiseDispute failed"
            return job_id
        job_id = self.create_job(self.agent.address, amount=amount,
                                 review_window=review_window)
        r = self.send_as(self.agent, lambda: self.escrow.functions.acceptJob(job_id))
        assert r['status'] == 1, "acceptJob failed"
        dh = self.w3.keccak(text=f"delivery-{job_id}")
        r = self.send_as(self.agent, lambda: self.escrow.functions.submitDeliveryAndDispute(
            job_id, dh, f"delivery text for job {job_id}", "agent dispute reason"))
        assert r['status'] == 1, "submitDeliveryAndDispute failed"
        return job_id

    def job(self, job_id):
        """Full Job struct tuple: (payer, agent, token, amount, deadline,
        reviewWindow, state, deliveryHash, metadataURI, deliveredAt,
        deadlineSeconds, deliveryText, disputeReason, bondAmount, disputedAt)."""
        return self.escrow.functions.getJob(job_id).call()

    def state(self, job_id):
        return self.job(job_id)[6]

    def balance(self, acct_address):
        return self.token.functions.balanceOf(acct_address).call()


@pytest.fixture
def env():
    return Env()
