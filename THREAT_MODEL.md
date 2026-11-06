# Lamplight Pay — Threat Model (AgentEscrowV3)

**Date:** November 6, 2026
**Status:** Pre-deployment. Read with the design doc and the terms. No names, no history.

---

## 1. What the contract must do

- Hold a payer's funds for one job until the job settles, and pay exactly the job amount out — no more, no less — split between worker and payer.
- Let the payer release (or the worker claim) after the review window with no third party involved.
- Let either party dispute inside the review window, and resolve every dispute exactly once: by AI Judge ruling, by mutual agreement, or by the 72-hour refund valve.
- Make the settlement invariant hold at all times: contract balance >= unsettled job amounts + outstanding bonds + pending credits.
- Never lose funds to a failed token transfer — failed payouts become pull credits the recipient can withdraw.

## 2. What the contract must never do

- Never pay out more than the job amount plus the bond for a job.
- Never pay the same job twice through any combination of exit paths (release, partial, ruling, settle, valve, cancel, refund).
- Never let the operator move happy-path funds. The operator touches disputed jobs only.
- Never let a signature authorize a different job, amount, chain, or contract than the signer intended.
- Never lock funds forever: every non-terminal state has an exit (cancel, claim, ruling, settle, valve).
- Never accept a token that breaks the 6-decimal dollar math.
- Never let a dispute settle without the bond going to exactly one party (worker or payer), in full.

## 3. Who can change what

### The operator (single immutable address, set in the constructor)

**Can:**
- Execute an AI Judge ruling on a Disputed job (`executeRuling`): choose any `amountToWorker` from 0 to the full job amount, only while the job is Disputed and only within 72 hours of the dispute. The bond follows the ruling (worker gets it at >= 50%).
- Whitelist / delist tokens (`setTokenAllowed`). Listing requires the token to report exactly 6 decimals. Delisting does not affect jobs already funded in that token.

**Cannot:**
- Move happy-path funds. There is no operator function for release, claim, cancel, or refund. Only the payer releases, only the worker claims, only the payer cancels.
- Settle a job that is not Disputed. `executeRuling` reverts unless the state is Disputed.
- Rule after the deadline. `executeRuling` reverts after `disputedAt + 72h`; after that only the refund valve can settle the job.
- Change the bond (20%, min $1, max $50), the review-window tiers, the 72-hour period, the dust rule, or any other parameter. All are constants.
- Change the operator address. There is no rotation. If the key is lost, disputes fall back to the 72-hour refund valve.
- Take a cut. No fee exists anywhere in the contract. The bond goes to the worker or the payer, never to the operator.

### The payer

**Can:** fund jobs, accept nothing (the payer never accepts), release in full after the review window, submit a worker-signed partial split, dispute (posting the 20% bond), settle by agreement, cancel a Created job, cancel an Accepted job past its deadline.

**Cannot:** release before the review window ends, dispute outside the review window, cancel a Delivered/Disputed job, accept their own open job, be the worker on their own job.

### The worker

**Can:** accept a job (named or open), deliver (or deliver-and-dispute atomically), claim after the review window, sign a partial split, dispute (no bond), settle by agreement.

**Cannot:** deliver after the deadline, dispute outside the review window, release their own job, cancel.

### Anyone

**Can:** call the 72-hour refund valve on a Disputed job past its deadline. No one else's permission is needed, and the refund goes to the payer in full — the caller gets nothing for calling it.

---

## 4. Trust boundaries

| Boundary | What is trusted | What is checked on-chain |
|---|---|---|
| Operator key | The operator executes the ruling the AI Judge actually gave, and whitelists only real 6-decimal USD stablecoins. | Nothing. The contract cannot verify a ruling's provenance. The ruling is published off-chain so execution can be checked against it after the fact. |
| AI Judge (off-chain) | The judge rules on the evidence presented, fairly and once. | Nothing. The contract receives only the final split numbers. Judgment is final, no appeal. |
| Token contracts | The token is a real ERC-20 with 6 decimals that behaves like one. | Decimals checked at listing. Funding and bond collection measure the balance delta (what actually arrived), so fee-on-transfer tokens cannot inflate the recorded amount. Payouts are attempted with returndata-capped calls; a failed payout becomes a pull credit, never a revert that blocks settlement. |
| UI / indexer | The UI shows the right job, the right deadlines, and the right token. | Nothing. All state is readable from the contract (`getJob`, `settlementInvariant`); the UI is a convenience, not a trust root. Dispute deadlines are computed from `getJob`, not from event logs. |
| Block timestamps | Miners/validators cannot move time by more than seconds. | All time boundaries are hours to days (1h minimum review window; 24h/72h/7d tiers; 72h ruling period). A seconds-scale manipulation cannot cross any boundary that matters. |
| Signatures (EIP-712) | The signer saw the job, amount, and deadline they signed. | Domain separator is chain-bound (rebuilt if the chain ID changes, so a signature cannot replay across a fork); `s` must be non-malleable; the signer must be the expected party; the deadline must not have passed; single-use enforced by the state transition (a second use reverts because the job left its state). |

---

## 5. How an attacker could profit, feature by feature

### Ruling execution
- **Compromised operator key.** The attacker executes fraudulent rulings on every currently Disputed job, paying the worker 0 (full refund to a payer the attacker controls) or 100% (to a worker the attacker controls). Worst case is bounded by the value of jobs Disputed at the time — happy-path funds are untouched. Mitigation: none on-chain; key custody is the control. The 72-hour deadline limits how long a stolen key stays useful for any one dispute, but not the damage across disputes.
- **Operator inaction.** The operator simply never rules. Profit: none directly — the valve refunds the payer in full after 72h. The worker loses (delivered work, no pay). Mitigation: the valve. Residual risk is worker-side, not theft.
- **Late ruling race.** Closed: the ruling has a hard deadline (`disputedAt + 72h`, inclusive). After it, only the valve can settle. No race between a late ruling and the valve.

### Bond
- **Payer disputes frivolously.** Costs the payer 20% (min $1, max $50) if the judge sides with the worker — the bond follows the ruling, so a losing dispute pays the worker extra. Deterrent is the bond itself.
- **Payer avoids the bond.** The payer cannot dispute without posting the bond in the same transaction (balance-delta checked; a shortfall reverts). Fee-on-transfer tokens cannot fake the bond: the bond must arrive in full or `raiseDispute` reverts.
- **Bond exceeds a sub-$1 job.** The $1 floor applies even to jobs under $1, so the bond can exceed the job amount. Accepted as a deterrent (nobody pays $1 to dispute fifty cents), but it is asymmetric against tiny jobs.
- **Bond theft.** The bond can only go to the worker or the payer, decided by the ruling split (>= 50% to worker) or returned to the payer on settle/valve. No path pays the bond to the operator or a third party.

### Whitelist
- **Wrong-decimal token listed.** Closed at listing: `setTokenAllowed` requires the token to report exactly 6 decimals (never-reverting decimals read; a token that cannot report decimals is rejected). An 18-decimal token cannot be listed, so the bond and tier math cannot be silently wrong.
- **Malicious token listed.** A token that reverts, blacklists, pauses, rebases, or charges fees cannot steal funds: funding records only what arrived; payouts that fail become pull credits; settlement accounting is by recorded amounts, not by trusting the token. Worst case is funds temporarily locked as credit, never stolen (proven by fault-injection testing across 13 hostile-token classes).
- **Delisting mid-job.** Delisting does not affect jobs already funded in that token; they settle normally.

### Signatures (splits and mutual settle)
- **Replay across jobs.** The struct hash binds `jobId`, `amountToWorker`, and `deadline` — a signature for one job cannot settle another.
- **Replay across chains.** The domain separator is chain-bound and rebuilt if the chain ID changes. A signature from one fork is rejected on the other.
- **Malleable signatures.** `s` above the secp256k1 half-order is rejected; `v` must be valid; the recovered signer must be the expected party.
- **Expired signatures.** Both split and settle signatures carry a deadline; use after it reverts.
- **Double use.** Single-use is enforced by the state transition, not by a nonce: after a split the job is Released; after a settle the job leaves Disputed. A second use reverts on state.
- **Front-running the agent's dispute.** The atomic deliver-and-dispute path lets the worker deliver and dispute in one transaction, so the payer cannot see the delivery in the mempool and release first.

### The 72-hour valve
- **Caller profit.** None — the valve refunds the payer in full. The caller pays gas and receives nothing.
- **Valve griefing.** Calling the valve early reverts (strict `>` past the deadline). Calling it on time settles the job once; a second call reverts on state.
- **Valve vs ruling.** No race: the ruling deadline and the valve opening are the same instant, with the ruling allowed at exactly the deadline and the valve strictly after it.

### Mutual settle
- **One party forging the other's consent.** The counterparty's EIP-712 signature is required, over the exact job, amount, and deadline. Without it the call reverts.
- **Settle then re-settle.** Single-use by state: the job leaves Disputed on settle.
- **Bond on settle.** The bond returns to the payer in full regardless of the agreed split — the bond backs a ruling, and with no ruling there is nothing to back. Both parties see this in the terms.

### Cancel paths
- **Payer cancels to escape a dispute.** Cannot: cancel only works on Created jobs (immediate refund) and Accepted jobs past their deadline (ghosted-worker refund). A Delivered or Disputed job cannot be cancelled.
- **Cancelling a nonexistent job.** Reverts on the payer check (`onlyPayer` runs before any existence check, so the message is "not payer" — slightly off, but it fails safely).
- **Double cancel.** The state transition makes the second call revert.

### Fee / rebase / pausable tokens (job already funded)
- **Fee-on-transfer.** The payer's funding is recorded as what arrived; a payer dispute requires the bond to arrive in full or it reverts. A worker on a fee token still gets paid what the escrow sends; the payout fee is borne by the recipient, measured by escrow outflow.
- **Rebase up.** Surplus stays in the contract; the `>=` settlement invariant holds with surplus present.
- **Rebase down.** The shortfall is honestly recorded as a credit against the recipient; the invariant reports the deficit rather than hiding it.
- **Pausable / blacklisting.** Payouts that fail become pull credits; the recipient withdraws when the token unpauses or unblacklists. Funds are delayed, not lost. A blacklisted account cannot redirect its credit to a clean address (no `withdrawTo`).

### Open jobs
- **Anyone accepts.** By design: an open job can be accepted by any wallet except the payer. The payer cannot reject a specific acceptor after posting open. Mitigation: post a named job when the worker matters.
- **Payer accepts their own job.** Reverts. The payer cannot be the worker on their own job.

---

## 6. Accepted risks (known, not fixed)

- **Single operator, no rotation.** The operator key is the central trust point for disputed jobs. Compromise or loss has the consequences in section 5. The 72-hour valve is the safety net for loss/inaction, not for misuse. An operator key management / rotation plan is a mainnet decision, not a contract feature in this version.
- **AI Judge is opaque and off-chain.** No on-chain evidence package, no challenge period, no appeal. The contract cannot verify what the judge was shown or decided. Users are told only "by AI Judge." The ruling is published off-chain so execution can be checked after the fact.
- **Bond asymmetry.** Only payer disputes post a bond. Agent disputes (including the atomic deliver-and-dispute) post none. An agent can force a dispute for free; the cost is operator time and up to 72 hours of delay, not funds. The agent gains nothing financially from forcing a dispute — the judge decides on evidence.
- **Review window in no event.** `JobCreated` carries `deadlineSeconds` but not `reviewWindow`, and no other event carries it. A watcher cannot compute the agent-claim deadline (`deliveredAt + reviewWindow`) from the event log alone; it must call `getJob`. Every state change is event-sourced; this is a missing parameter, not a missing event.
- **Metadata URI uncapped.** Delivery and dispute text are capped at 10 KB, but `metadataURI` has no length cap. It is payer-funded gas, so the cost falls on the payer, not the protocol.
- **Empty dispute reason accepted.** The contract accepts a dispute with an empty reason string. The judge would receive no reason on-chain. The UI should require one; the contract does not.
- **Cancel on a nonexistent job says "not payer".** The payer check runs before any existence check. It fails safely; the message is just slightly off.
- **Timestamp dependence.** All time logic uses `block.timestamp`. Miner manipulation of seconds cannot cross any hour/day boundary in this contract (verified by boundary tests).
- **Gas: struct unpacked, text on-chain.** The 15-field Job struct is not packed for storage, and delivery/dispute text is stored on-chain (up to 10 KB each). Deliberate: the judge reads text from state without trusting an indexer, and gas on this chain is near zero. Both are held for a mainnet gas pass, not fixed here.
- **No pause switch.** There is no circuit breaker. The 72-hour valve is the safety mechanism for disputes; happy-path funds need no switch because no admin function can touch them.

---

## 7. What the tests proved (and what they did not)

- **Proved:** fund conservation across random operation sequences (state machine); no double-spend through any pair of exit paths; reentrancy battery with zero breaches; 13 hostile-token classes worst-case locked-never-stolen; pure-events reconstruction matches the chain exactly; all 49 revert strings map to plain-language messages with no panic paths; cross-chain signature replay fails.
- **Not proved by tests:** that the operator executes the ruling the judge gave (off-chain, unverifiable on-chain); that the AI Judge rules fairly (off-chain); that the operator's key is safe (custody, not code); that a listed token stays honest (behavior is handled, trust is not).
