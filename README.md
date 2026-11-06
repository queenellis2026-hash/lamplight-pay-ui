# Lamplight Pay — Escrow for Agent Work

A payer funds a job in a USD stablecoin; the worker accepts, delivers,
and the payer releases. If they disagree, either side can raise a
dispute inside the review window. The payer posts a 20% dispute bond
(min $1, max $50). An AI Judge rules; a single operator executes the
ruling on-chain. The ruling is final — no appeal. If no ruling executes
within 72 hours of the dispute, the job amount and the bond refund to
the payer in full. The two parties may also settle a dispute themselves
by mutual signature at any time.

## Deployed

BOT Chain Testnet (chain 968), contract `AgentEscrowV3`:

- Address: `0x5f1078cD6Dd394478664cc86A3F45e5C7d50cF3c`
- Explorer: https://scan.bohr.life/address/0x5f1078cD6Dd394478664cc86A3F45e5C7d50cF3c
- Source verified on the explorer (solc 0.8.24, optimizer 200 runs).

## Contents

- `contracts/AgentEscrowV3.sol` — the contract.
- `contracts/build-AgentEscrowV3.json` — compiled ABI + creation bytecode,
  with compiler metadata (contract, solc version, optimizer settings).
- `tests/` — unit tests and five property-testing phases (state machine,
  idempotency and replay, fault injection, reconciliation, error
  taxonomy), plus `error_taxonomy.json`, which maps every on-chain
  revert string to exactly one plain-language message for the UI,
  and `test_monitor.py` for the monitor.
- `index.html` — the UI, a single self-contained HTML file, pointed at
  the deployed testnet contract.
- `monitor/` — the dispute/ruling/valve monitor. Watches the deployed
  contract and sends Telegram alerts (new dispute, ruling executed,
  valve refund, settlement-invariant breach). See `monitor/README.md`.
- `deploy_v3_testnet.py` — deploys to testnet 968 only; refuses mainnet
  677 outright. Deployer key from the `DEPLOYER_KEY` environment
  variable only; operator address as an argument.
- `THREAT_MODEL.md` — what the contract must do, what it must never do,
  who can change what, and how an attacker could profit from breaking
  each piece.
- `requirements.txt` — pinned test dependencies. `setup.sh` — creates
  `.venv`, installs them, downloads solc 0.8.24, runs the suite.

## Compile

solc 0.8.24, optimizer on, 200 runs. Creation bytecode is 15,992 bytes,
runtime 15,559 bytes (EIP-170 limit 24,576).

```python
import solcx
compiled = solcx.compile_files(
    ["contracts/AgentEscrowV3.sol"],
    output_values=["abi", "bin", "bin-runtime"],
    solc_version="0.8.24", optimize=True, optimize_runs=200,
)
```

Or run `python build.py`, which writes `contracts/build-AgentEscrowV3.json`.

## Run the tests

```bash
./setup.sh            # creates .venv, installs pinned deps, runs the suite
# — or by hand —
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -c "import solcx; solcx.install_solc('0.8.24')"
.venv/bin/python -m pytest tests/ -q
```

Python 3.12. The full suite is 323 tests (304 contract + 19 monitor)
and takes ~13 minutes; the Hypothesis state machine is most of it.

## The rules

- **Disputes:** any and all go to the AI Judge. No thresholds, no exceptions.
  Users are told "by AI Judge" and nothing more.
- **Bond:** 20% of the job amount, min $1, max $50. Follows the ruling:
  worker >= 50% -> bond to worker; < 50% -> bond to payer. On mutual
  settle the bond returns to the payer. On the 72h valve the bond refunds
  to the payer with the job amount. Only the payer posts a bond, when the
  payer raises the dispute. An agent-raised dispute posts no bond.
- **Ruling:** executed by the operator (`executeRuling`). Operator-only,
  single-use, any split 0-100%. **Hard deadline:** the ruling must execute
  within 72 hours of the dispute (inclusive — at exactly disputedAt + 72h
  it still succeeds). After that, only the 72h refund valve can settle
  the job; a late ruling reverts "ruling period ended".
- **Timeout valve:** 72 hours from the dispute. Anyone may call
  `refundDisputeTimeout`; job amount + bond refund to the payer in full.
- **Review window:** min 1h for all. Max by job size: under $10 -> 24h,
  $10-$100 -> 72h, over $100 -> 7 days.
- **Tokens:** USD stablecoins only (USDC, USDT). Operator-managed whitelist.
  **Listing requires 6 decimals** — bond math and review tiers are all
  6-decimal units. A token with other decimals, or no `decimals()`, cannot
  be listed ("token must be 6 decimals"). Delisting needs no check.
- **Splits:** worker-signed (`releasePartial`), 1% dust rejection, signature
  expiry. No per-job nonce: replay protection is the Delivered -> Released
  state transition.
- **Chain fork:** the EIP-712 domain separator is cached with the chain ID
  it was built for and rebuilt if the chain ID changes, so a signature from
  one fork cannot replay on another.
- **Operator:** single key, set once in the constructor, no rotation. If
  the key is lost, disputes fall back to the 72h refund valve — that is
  the safety net.
- **Ruling publication:** the ruled amount is emitted on-chain
  (`RulingExecuted`). The judge's reasoning is published off-chain.
