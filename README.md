# Lamplight Pay — BOT Chain UI

Pay-on-delivery UI for agent escrow on BOT Chain. A payer locks payment for a job; the worker gets paid when the delivery is accepted. Money is held, not sent.

This satisfies **criterion 4** of the BOT Chain Ecosystem Support checklist: a product UI with wallet connection that is fully usable, not just deployed contracts.

## Live contracts (BOT Chain testnet, chain 968)

- **AgentEscrow:** `0xB78F507C8e46CB63ec7D6a76B11cfDE3F9066719` — [view on explorer](https://scan.bohr.life/address/0xB78F507C8e46CB63ec7D6a76B11cfDE3F9066719)
- **MockUSDC (test token):** `0x5D8508FB91f6f7CF5B8934115AD2b873E44D5372` — [view on explorer](https://scan.bohr.life/address/0x5D8508FB91f6f7CF5B8934115AD2b873E44D5372)

## Run locally

No build step. Any static server works:

```bash
cd ~/workspace/botchain-pay-ui
python3 -m http.server 8080
# open http://localhost:8080
```

## Try the full flow (testnet)

1. Open the page, click **Connect wallet** (MetaMask). The app auto-adds/switches to BOT Chain Testnet (chain 968).
2. Click **Get free tBOT (gas)** → faucet at https://faucet.botchain.ai/en/basic — paste your address, complete the check, claim 10 tBOT.
3. Click **Get free test dollars** → mints 100 mUSDC to your wallet (one click, on-chain).
4. **Create a job:** enter the worker's address, a payment amount, a deadline in hours, and what needs doing. Click **Step 1 — Allow the payment**, then **Step 2 — Create the job**.
5. As the **worker** (connect a second wallet, or use the worker address): **Accept job** → do the work → **Mark as delivered** (enter what you delivered; it gets sealed on-chain as a hash).
6. As the **payer**: **Release payment** — the worker gets the tokens.
7. If the deadline passes with no delivery, the payer gets **Reclaim money**.

The job list shows every job with its status: Open → Accepted → Delivered → Paid (or Refunded / Cancelled). Filter "Mine" to see only jobs where you're the payer or the worker.

## Deploy / host

It's a single static file (`index.html`) plus this README. Host it anywhere static files go (GitHub Pages, IPFS, a web server). No secrets, no backend, no build.

## Going to mainnet

One-line change at the top of `index.html`:

```js
const CONFIG = {
  CHAIN_ID: 677,            // was 968
  CHAIN_ID_HEX: '0x2A5',    // 677 in hex
  CHAIN_NAME: 'BOT Chain',
  RPC_URL: 'https://rpc.botchain.ai',
  EXPLORER: 'https://scan.botchain.ai',
  ...
};
```

Plus the mainnet contract addresses for `ESCROW_ADDRESS` / `TOKEN_ADDRESS` once deployed.

## Tech

- Vanilla JS + [ethers.js v6](https://docs.ethers.org/v6/) via CDN — no build step, no framework.
- Wallet: any injected EIP-1193 wallet (MetaMask, etc.). Auto network add/switch via `wallet_addEthereumChain` / `wallet_switchEthereumChain`.
- Delivery proof: the worker's delivery text is hashed with keccak256 (`lamplight-pay:` prefix) and stored as `bytes32` on-chain; the plain text stays off-chain between the two parties.
