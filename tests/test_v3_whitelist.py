#!/usr/bin/env python3
"""V3 operator-managed token whitelist tests.

W1  Operator can whitelist a token; non-operator cannot
W2  Non-whitelisted token cannot fund a job ("token not allowed")
W3  Operator can delist; a delisted token cannot fund a job
W4  Zero-address token reverts ("zero address")
W5  TokenWhitelisted event emitted
W6  The operator address is set in the constructor (readable on-chain)
W7  18-decimal token cannot be whitelisted ("token must be 6 decimals")
W8  0-decimal token cannot be whitelisted ("token must be 6 decimals")
W9  Token without decimals() (and a plain EOA) cannot be whitelisted
W10 Delisting needs no decimals check — removing a token always works
"""
import solcx
from eth_account import Account
from web3 import Web3

from conftest import MOCK_ERC20_SOURCE

_DECIMAL_TOKEN_SOURCE = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
contract DecimalToken {
    mapping(address => uint256) public balanceOf;
    uint8 public decimals;
    constructor(uint8 _decimals) { decimals = _decimals; }
    function mint(address to, uint256 amt) external { balanceOf[to] += amt; }
}
'''

_NO_DECIMALS_TOKEN_SOURCE = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
contract NoDecimalsToken {
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 amt) external { balanceOf[to] += amt; }
}
'''


def _deploy(env, source, contract_name, *args):
    compiled = solcx.compile_source(
        source, output_values=['abi', 'bin'], solc_version='0.8.24')
    data = compiled[f'<stdin>:{contract_name}']
    c = env.w3.eth.contract(abi=data['abi'], bytecode=data['bin'])
    tx = c.constructor(*args).transact({'from': env.funder, 'gas': 2000000})
    addr = env.w3.eth.wait_for_transaction_receipt(tx).contractAddress
    return env.w3.eth.contract(address=addr, abi=data['abi'])


def test_W1_operator_whitelists_non_operator_reverts(env):
    assert env.escrow.functions.operator().call() == env.operator.address
    token = _deploy(env, MOCK_ERC20_SOURCE, "MockToken")
    token_addr = token.address
    assert env.escrow.functions.allowedTokens(token_addr).call() is False
    r = env.send_as(env.operator, lambda: env.escrow.functions.setTokenAllowed(token_addr, True))
    assert r['status'] == 1
    assert env.escrow.functions.allowedTokens(token_addr).call() is True
    # Non-operator (even the funder) cannot change the list
    other = _deploy(env, MOCK_ERC20_SOURCE, "MockToken").address
    env.assert_reverts(env.payer,
                       lambda: env.escrow.functions.setTokenAllowed(other, True),
                       "not operator")
    env.assert_reverts(env.stranger,
                       lambda: env.escrow.functions.setTokenAllowed(other, True),
                       "not operator")


def test_W2_non_whitelisted_token_cannot_fund(env):
    token_addr = Account.create().address
    env.assert_reverts(env.payer, lambda: env.escrow.functions.createJob(
        env.agent.address, token_addr, 1000, 86400, 3600, "nope"),
        "token not allowed")


def test_W3_operator_delists(env):
    assert env.escrow.functions.allowedTokens(env.token_addr).call() is True
    r = env.send_as(env.operator, lambda: env.escrow.functions.setTokenAllowed(env.token_addr, False))
    assert r['status'] == 1
    assert env.escrow.functions.allowedTokens(env.token_addr).call() is False
    env.assert_reverts(env.payer, lambda: env.escrow.functions.createJob(
        env.agent.address, env.token_addr, 1000, 86400, 3600, "delisted"),
        "token not allowed")


def test_W4_zero_address_reverts(env):
    env.assert_reverts(env.operator,
                       lambda: env.escrow.functions.setTokenAllowed(
                           "0x0000000000000000000000000000000000000000", True),
                       "zero address")


def test_W5_whitelist_event(env):
    token = _deploy(env, MOCK_ERC20_SOURCE, "MockToken")
    token_addr = token.address
    r = env.send_as(env.operator, lambda: env.escrow.functions.setTokenAllowed(token_addr, True))
    assert r['status'] == 1
    ev = env.escrow.events.TokenWhitelisted().process_receipt(r)
    assert len(ev) == 1
    assert ev[0]['args']['token'] == token_addr
    assert ev[0]['args']['allowed'] is True


def test_W7_whitelist_18_decimals_reverts(env):
    token = _deploy(env, _DECIMAL_TOKEN_SOURCE, "DecimalToken", 18)
    env.assert_reverts(env.operator,
                       lambda: env.escrow.functions.setTokenAllowed(
                           token.address, True),
                       "token must be 6 decimals")
    assert env.escrow.functions.allowedTokens(token.address).call() is False


def test_W8_whitelist_0_decimals_reverts(env):
    token = _deploy(env, _DECIMAL_TOKEN_SOURCE, "DecimalToken", 0)
    env.assert_reverts(env.operator,
                       lambda: env.escrow.functions.setTokenAllowed(
                           token.address, True),
                       "token must be 6 decimals")
    assert env.escrow.functions.allowedTokens(token.address).call() is False


def test_W9_whitelist_no_decimals_reverts(env):
    token = _deploy(env, _NO_DECIMALS_TOKEN_SOURCE, "NoDecimalsToken")
    env.assert_reverts(env.operator,
                       lambda: env.escrow.functions.setTokenAllowed(
                           token.address, True),
                       "token must be 6 decimals")
    assert env.escrow.functions.allowedTokens(token.address).call() is False
    # A plain EOA has no decimals() either — same clean revert.
    eoa = Account.create().address
    env.assert_reverts(env.operator,
                       lambda: env.escrow.functions.setTokenAllowed(eoa, True),
                       "token must be 6 decimals")
    assert env.escrow.functions.allowedTokens(eoa).call() is False


def test_W10_delist_needs_no_decimals_check(env):
    # Delisting skips the decimals check: removing a token is always safe,
    # even one that could never be listed.
    token = _deploy(env, _DECIMAL_TOKEN_SOURCE, "DecimalToken", 18)
    r = env.send_as(env.operator, lambda: env.escrow.functions.setTokenAllowed(
        token.address, False))
    assert r['status'] == 1
    assert env.escrow.functions.allowedTokens(token.address).call() is False


def test_W6_operator_is_constructor_set(env):
    assert env.escrow.functions.operator().call() == env.operator.address
    assert env.escrow.functions.operator().call() != env.payer.address
    assert env.escrow.functions.operator().call() != env.agent.address
