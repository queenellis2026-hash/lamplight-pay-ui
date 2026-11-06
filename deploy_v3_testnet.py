#!/usr/bin/env python3
"""Deploy Lamplight Pay 3.0 (AgentEscrowV3) to BOT Chain Testnet (chain ID 968).

V3 vs V16: the 2-of-3 arbiter panel is gone. Disputes go to an AI Judge;
the single operator key executes rulings and manages the token whitelist.
The constructor takes ONE operator address. There is no rotation: if the
operator key is lost, disputes fall back to the 72h refund valve.

Usage:
  DEPLOYER_KEY=<key> OPERATOR=0x... \\
      ~/workspace/botchain-port/venv/bin/python deploy_v3_testnet.py

  Or pass the operator as an argument:
  DEPLOYER_KEY=<key> ~/workspace/botchain-port/venv/bin/python \\
      deploy_v3_testnet.py 0xOperatorAddress

The deployer key is read from DEPLOYER_KEY env only — never printed,
never saved, never written to disk.

Safety: refuses to run on any chain other than 968. BOT mainnet (677)
is refused outright, before any transaction is built or sent.

This script DEPLOYS ONLY. It does not whitelist any token and does not
create any job. After it prints the deployed address, follow the NEXT
STEPS block it prints: whitelist MockUSDC via the operator, then run a
first live job end-to-end on test funds. Those are separate operator
actions, not part of this transaction.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from web3 import Web3  # noqa: E402

EXPECTED_CHAIN_ID = 968  # BOT Chain Testnet (bohr). Mainnet is 677 — refused.
MAINNET_CHAIN_ID = 677
RPC = "https://rpc.bohr.life"
EXPLORER = "https://scan.bohr.life"
MOCK_USDC = "0x5D8508FB91f6f7CF5B8934115AD2b873E44D5372"  # testnet, 6 decimals

SOLC_VERSION = "0.8.24"
OPTIMIZER_RUNS = 200

GAS_HEADROOM = 1.25
MIN_GAS_LIMIT = 5_000_000


def deploy_gas_limit(estimate: int, floor: int = MIN_GAS_LIMIT) -> int:
    return max(math.ceil(estimate * GAS_HEADROOM), floor)


def check_chain_id(chain_id: int) -> None:
    """Refuse anything that is not BOT Chain Testnet (968).

    Mainnet (677) is refused explicitly, before any transaction is built
    or sent. Any other chain is refused too — this script is testnet-only.
    """
    if chain_id == MAINNET_CHAIN_ID:
        raise SystemExit(
            f"REFUSED: chain id is {chain_id} (BOT Chain Mainnet) — "
            "this script deploys to testnet only. Aborting before any "
            "transaction was built or sent."
        )
    if chain_id != EXPECTED_CHAIN_ID:
        raise SystemExit(
            f"REFUSED: chain id is {chain_id}, expected {EXPECTED_CHAIN_ID} "
            "(BOT Chain Testnet). Aborting."
        )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Deploy AgentEscrowV3 to BOT Chain Testnet (968). "
        "Mainnet (677) is refused."
    )
    p.add_argument(
        "operator",
        nargs="?",
        default=None,
        help="Operator address (the single key that executes AI Judge "
        "rulings and manages the token whitelist). "
        "Or set OPERATOR env. Required.",
    )
    return p.parse_args(argv)


def main() -> None:
    args = parse_args()
    operator = args.operator or os.environ.get("OPERATOR", "")
    if not operator:
        raise SystemExit(
            "Operator address required.\n"
            "Usage: DEPLOYER_KEY=<key> OPERATOR=0x... python deploy_v3_testnet.py\n"
            "  or: DEPLOYER_KEY=<key> python deploy_v3_testnet.py 0xOperatorAddress"
        )
    if not Web3.is_address(operator):
        raise SystemExit(f"invalid operator address: {operator}")
    operator = Web3.to_checksum_address(operator)

    key = os.environ.get("DEPLOYER_KEY")
    if not key:
        raise SystemExit("DEPLOYER_KEY is not set.")

    w3 = Web3(Web3.HTTPProvider(RPC, request_kwargs={"timeout": 30}))
    if not w3.is_connected():
        raise SystemExit(f"cannot reach RPC at {RPC}")
    check_chain_id(w3.eth.chain_id)
    chain_id = w3.eth.chain_id

    acct = w3.eth.account.from_key(key)
    print(f"deployer: {acct.address} | chain: {chain_id} | "
          f"balance: {w3.eth.get_balance(acct.address) / 10**18:.6f} tBOT")
    if w3.eth.get_balance(acct.address) == 0:
        raise SystemExit("deployer has 0 balance — fund it first (faucet).")

    print(f"operator: {operator}")
    print("WARNING: the operator is a single immutable key with no rotation. "
          "If it is lost, disputes fall back to the 72h refund valve.")

    artifact = json.loads((ROOT / "contracts" / "build-AgentEscrowV3.json").read_text())
    meta = artifact.get("metadata", {})
    print(f"artifact: AgentEscrowV3, solc {meta.get('solc')}, "
          f"optimizer runs {meta.get('optimizer', {}).get('runs')}")
    contract = w3.eth.contract(abi=artifact["abi"], bytecode=artifact["bytecode"])

    nonce = w3.eth.get_transaction_count(acct.address, "pending")
    estimate = contract.constructor(operator).estimate_gas({"from": acct.address})
    gas = deploy_gas_limit(estimate)
    tx = contract.constructor(operator).build_transaction({
        "from": acct.address, "nonce": nonce,
        "gas": gas, "gasPrice": w3.eth.gas_price, "chainId": chain_id,
    })
    print(f"AgentEscrowV3: estimate {estimate} gas -> limit {gas}, nonce {tx['nonce']}")
    signed = acct.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
    if receipt.status != 1:
        raise SystemExit(f"deploy FAILED (tx {tx_hash.hex()}, status 0) — not recorded.")
    addr = receipt.contractAddress
    print(f"AgentEscrowV3: {addr} (tx {tx_hash.hex()})")
    print(f"  explorer: {EXPLORER}/address/{addr}")

    # Verify the operator on-chain
    deployed = w3.eth.contract(address=addr, abi=artifact["abi"])
    onchain_operator = deployed.functions.operator().call()
    assert onchain_operator.lower() == operator.lower(), \
        f"operator mismatch! onchain={onchain_operator}"
    print("operator verified on-chain.")

    out = ROOT / "botchain-v3-deployment.json"
    out.write_text(json.dumps({
        "network": "BOT Chain Testnet",
        "chain_id": chain_id,
        "rpc": RPC,
        "deployer": acct.address,
        "AgentEscrowV3": addr,
        "operator": operator,
        "tx": tx_hash.hex(),
        "solc": meta.get("solc"),
        "optimizer_runs": meta.get("optimizer", {}).get("runs"),
        "notes": "AI Judge disputes; single operator executes rulings + manages "
        "USD-only whitelist; 20% dispute bond (min $1, max $50); 72h ruling "
        "deadline + refund valve; tiered review windows; mutual settle; "
        "worker-signed partials with 1% dust floor; atomic deliver+dispute",
    }, indent=2))
    print(f"deployment record: {out}")

    print()
    print("Source verification (run after deploy, same settings as the build):")
    print(f"  solc {SOLC_VERSION}, optimizer enabled, runs {OPTIMIZER_RUNS}")
    print(f"  Verify at: {EXPLORER}/address/{addr} -> Contract -> Verify & Publish")
    print("  Source file: contracts/AgentEscrowV3.sol (exact file from this tree)")
    print()
    print("NEXT STEPS — separate operator actions, NOT done by this script:")
    print("  1. Whitelist MockUSDC (operator only):")
    print(f"     cast send {addr} 'setTokenAllowed(address,bool)' "
          f"{MOCK_USDC} true --private-key $OPERATOR_KEY --rpc-url {RPC}")
    print("     (or the equivalent web3 call from the operator key; "
          "confirm TokenWhitelisted on the explorer)")
    print("  2. First live job end-to-end on test funds:")
    print("     a. Mint/obtain test MockUSDC, approve the escrow.")
    print("     b. Create a job (small amount), accept it, deliver it,")
    print("        release it — confirm each step on the explorer.")
    print("     c. Create a second job, deliver it, dispute it, confirm the")
    print("        bond posts, then settle it by agreement or let the valve")
    print("        refund it — confirm the bond follows the outcome.")
    print("  3. Update the UI contract address (index.html CONFIG) and")
    print("     have the UI reviewed before any push.")


if __name__ == "__main__":
    main()
