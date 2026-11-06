// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title AgentEscrowV3 — escrowed settlement for agent work, judged by an AI Judge.
/// @notice A payer funds a job in a USD stablecoin; the worker accepts,
///   delivers, and the payer releases. If they disagree, either side can
///   raise a dispute inside the review window. The payer posts a 20%
///   dispute bond (min $1, max $50). An AI Judge rules; a single operator
///   executes the ruling on-chain. The ruling is final — no appeal. If no
///   ruling executes within 72 hours of the dispute, the job amount and
///   the bond refund to the payer in full. The two parties may also settle
///   a dispute themselves by mutual signature at any time.
/// @notice V3 vs V16: the 2-of-3 arbiter panel is GONE — no arbiters,
///   votes, rotation, or governance. Disputes resolve by AI Judge ruling
///   (operator executes), mutual settle, or the 72h refund valve.
///   Review windows are capped by job size. The token whitelist is
///   operator-managed, USD stablecoins only. Full history: CHANGELOG.md.
/// @dev Review-window lifecycle:
///   - submitDelivery records deliveredAt. The payer may release at any
///     time while the job is Delivered; the payer may also release a
///     PARTIAL amount via releasePartial(), but ONLY during the review
///     window, ONLY with the worker's EIP-712 signature agreeing to the
///     exact split, and NEVER dust (below 1% of the job amount reverts).
///   - A dispute may only be raised INSIDE the review window; after it,
///     raiseDispute reverts. The worker may also deliver AND dispute
///     atomically via submitDeliveryAndDispute(), so the payer gets no
///     front-running window.
///   - If the payer stays silent past the window and no dispute was raised,
///     the AGENT may call release() and claim the funds. The payer cannot
///     front-run this with releasePartial — it reverts after the window,
///     and without the worker's signature it reverts inside the window too.
///   - A disputed job resolves one of three ways: the operator executes
///     the AI Judge's ruling (executeRuling), the two parties settle by
///     mutual signature (settleByAgreement), or — if no ruling executes
///     within 72 hours of the dispute — anyone may call
///     refundDisputeTimeout(), which refunds job amount + bond to the
///     payer in full. No path lets funds lock forever.
/// @dev V3 keeps V16's deadline-on-accept model: the deadline clock
///   starts on ACCEPT, not creation. The payer sets "you have X hours once
///   you start" — open jobs sitting on the board don't tick until accepted.
/// @dev Funding measures what actually arrived: createJob compares the
///   escrow's token balance before and after transferFrom and stores the
///   received amount, so fee-on-transfer / rebasing tokens cannot make the
///   escrow insolvent by recording more than it holds. The dispute bond
///   is measured the same way and must arrive in full.
/// @dev Payouts assume a token moves the full amount or nothing:
///   the balance check in _payOrCredit credits only the shortfall between
///   the escrow's balance before and after a payout leg.
/// @dev All token moves use SafeERC20-style low-level calls that accept an
///   empty return value, so USDT-style tokens (no bool return) work.
/// @dev Payouts are PULL on failure. (See V9 NatSpec for the full
///   _payOrCredit / withdraw design.)
/// @dev Unsupported token classes (unchanged from V9): rebasing tokens,
///   sender-side fee tokens, partial-transfer tokens. The whitelist
///   (allowedTokens) is the enforcement point: only USD stablecoins
///   should be approved.
/// @dev The settlement invariant is balance >= unsettled + bonded +
///   pending credits. A surplus (donations, rounding) is harmless; only
///   a deficit matters.
/// @dev Minimal reentrancy guard included; no external dependencies.
interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function decimals() external view returns (uint8);
}

contract AgentEscrowV3 {
    enum State { Created, Accepted, Delivered, Disputed, Released, Refunded, Cancelled }

    struct Job {
        address payer;
        address agent; // address(0) until an open job is accepted
        address token;
        uint256 amount;
        uint256 deadline; // 0 until accepted; set to acceptTime + deadlineSeconds in acceptJob
        uint256 reviewWindow; // seconds after delivery during which payer may dispute
        State state;
        bytes32 deliveryHash;
        string metadataURI; // off-chain job spec / quote id
        uint256 deliveredAt; // timestamp of submitDelivery; 0 until delivered
        uint256 deadlineSeconds; // work window: set at creation, clock starts on accept
        string deliveryText; // worker's delivery description, stored on-chain
        string disputeReason; // stated reason when disputing
        uint256 bondAmount; // dispute bond posted by the payer; 0 if the agent disputed
        uint256 disputedAt; // timestamp the dispute was raised; 0 until disputed
    }

    /// @dev The operator: the single key that executes the AI Judge's
    ///   rulings (executeRuling) and manages the token whitelist
    ///   (setTokenAllowed). Set once in the constructor; there is no
    ///   rotation in this version. If the operator key is lost, disputes
    ///   fall back to the 72h refund valve — that is the safety net.
    ///   Known limitation; see README.md.
    address public immutable operator;

    /// @dev Ruling period after a dispute is raised: if the operator has
    ///   not executed a ruling within it, anyone may call
    ///   refundDisputeTimeout() and the job amount + bond refund to the
    ///   payer in full. 72 hours — disputes resolve in hours, this covers
    ///   a long weekend.
    uint256 public constant RULING_PERIOD = 72 hours;

    /// @dev Review-window tiers, by job amount (USD, 6-decimal token
    ///   units). A small job must not lock funds for a week.
    ///   Under $10 -> max 24h; $10-$100 -> max 72h; over $100 -> max 7 days.
    uint256 public constant TIER1_MAX_AMOUNT = 10_000_000; // $10
    uint256 public constant TIER2_MAX_AMOUNT = 100_000_000; // $100
    uint256 public constant TIER1_MAX_WINDOW = 24 hours;
    uint256 public constant TIER2_MAX_WINDOW = 72 hours;
    uint256 public constant TIER3_MAX_WINDOW = 7 days;

    /// @dev Lower bound on the review window: a 0 window would make
    ///   disputes unraisabe (only the delivery block itself would be
    ///   in-window).
    uint256 public constant MIN_REVIEW_WINDOW = 1 hours;

    /// @dev Upper bound on deliveryText length: 10 KB caps the gas cost of
    ///   storing the worker's delivery description on-chain.
    uint256 public constant MAX_DELIVERY_TEXT = 10240;

    /// @dev Dispute bond: 20% of the job amount, min $1, max $50.
    ///   Token amounts are 6-decimal (USDC/USDT). The bond follows the
    ///   ruling: the judge awards the worker >= 50% -> bond to worker;
    ///   < 50% -> bond to payer. On mutual settle the bond returns to
    ///   the payer (no ruling to back). On the 72h valve the bond refunds
    ///   to the payer with the job amount.
    uint256 public constant BOND_BPS = 2000; // 20%
    uint256 public constant BOND_MIN = 1_000_000; // $1
    uint256 public constant BOND_MAX = 50_000_000; // $50

    /// @dev Token whitelist: only approved tokens can fund jobs. Managed
    ///   by the operator via setTokenAllowed. USD stablecoins only.
    mapping(address => bool) public allowedTokens;

    uint256 public jobCount;
    /// @dev Private, not public: the auto-generated getter for a 15-field
    ///   struct does not compile under legacy codegen (stack too deep).
    ///   Read jobs through getJob().
    mapping(uint256 => Job) private jobs;

    /// @dev Pull balances: token => account => amount credited when a
    ///   payout leg failed (see _payOrCredit).
    mapping(address => mapping(address => uint256)) public pendingWithdrawals;

    /// @dev Total of all pending credits per token.
    mapping(address => uint256) public totalPendingCredits;

    /// @dev Total of all unsettled job amounts per token.
    mapping(address => uint256) public totalUnsettled;

    /// @dev Total of all outstanding dispute bonds per token. The bond
    ///   is held by the contract from raiseDispute until the dispute
    ///   settles, so it must be counted in the settlement invariant.
    mapping(address => uint256) public totalBonded;

    /// @dev Upper bound on disputeReason length: 10 KB, same as delivery text.
    uint256 public constant MAX_DISPUTE_REASON = 10240;

    /// @dev Minimum partial release, in basis points of the job amount
    ///   (100 = 1%). A partial below this reverts unless it is the full
    ///   amount. Kills 1-wei dust games.
    uint256 public constant MIN_PARTIAL_BPS = 100;

    /// @dev EIP-712 domain separator, cached at deploy time together
    ///   with the chain ID it was built for. If the chain forks and
    ///   the chain ID changes, _domainSeparator() rebuilds it for the
    ///   new chain ID instead of reusing the old one — otherwise a
    ///   signature from one fork would replay on the other.
    uint256 private immutable _CACHED_CHAIN_ID;
    bytes32 private immutable _CACHED_DOMAIN_SEPARATOR;
    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 private constant PARTIAL_RELEASE_TYPEHASH = keccak256(
        "PartialRelease(uint256 jobId,uint256 amountToWorker,uint256 deadline)"
    );
    bytes32 private constant SETTLE_DISPUTE_TYPEHASH = keccak256(
        "SettleDispute(uint256 jobId,uint256 amountToWorker,uint256 deadline)"
    );
    /// @dev EIP-2: max s value for non-malleable signatures (secp256k1 n/2).
    uint256 private constant MAX_SIG_S = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    event JobCreated(uint256 indexed jobId, address indexed payer, address indexed agent, address token, uint256 amount, uint256 deadline, string metadataURI);
    event JobAccepted(uint256 indexed jobId, address indexed agent);
    event DeliverySubmitted(uint256 indexed jobId, bytes32 deliveryHash, string deliveryText);
    event JobReleased(uint256 indexed jobId, address indexed agent, uint256 amount);
    event JobRefunded(uint256 indexed jobId, address indexed payer, uint256 amount);
    event JobCancelled(uint256 indexed jobId);
    event DisputeRaised(uint256 indexed jobId, address indexed by);
    event BondPosted(uint256 indexed jobId, address indexed payer, uint256 bondAmount);
    event RulingExecuted(uint256 indexed jobId, uint256 amountToWorker, uint256 amountToPayer, address bondTo);
    event SettledByAgreement(uint256 indexed jobId, uint256 amountToWorker, uint256 amountToPayer);
    event DisputeTimeoutRefunded(uint256 indexed jobId, address indexed payer, uint256 amount, uint256 bond);
    event JobPartiallyReleased(uint256 indexed jobId, address indexed agent, uint256 amountToAgent, uint256 amountToPayer);
    event Credited(address indexed token, address indexed account, uint256 amount);
    event Withdrawn(address indexed token, address indexed account, address to, uint256 amount);
    event TokenWhitelisted(address indexed token, bool allowed);

    /// @dev Set the operator. Must be a non-zero address. No rotation.
    constructor(address _operator) {
        require(_operator != address(0), "zero address operator");
        operator = _operator;
        _CACHED_CHAIN_ID = block.chainid;
        _CACHED_DOMAIN_SEPARATOR = _buildDomainSeparator(block.chainid);
    }

    /// @dev Build the EIP-712 domain separator for a given chain ID.
    ///   Single construction site: the constructor and _domainSeparator
    ///   both use it, so the rebuilt separator is byte-identical to the
    ///   cached one when the chain ID has not changed.
    function _buildDomainSeparator(uint256 chainId) internal view returns (bytes32) {
        return keccak256(abi.encode(
            EIP712_DOMAIN_TYPEHASH,
            keccak256("AgentEscrowV3"),
            keccak256("1"),
            chainId,
            address(this)
        ));
    }

    /// @dev The domain separator for the current chain. Returns the
    ///   cached value in the normal case; rebuilds it if the chain ID
    ///   changed (chain fork), so signatures from one fork cannot
    ///   replay on another.
    function _domainSeparator() internal view returns (bytes32) {
        if (block.chainid == _CACHED_CHAIN_ID) {
            return _CACHED_DOMAIN_SEPARATOR;
        }
        return _buildDomainSeparator(block.chainid);
    }

    bool private _locked;
    modifier nonReentrant() {
        require(!_locked, "reentrant");
        _locked = true;
        _;
        _locked = false;
    }
    modifier onlyPayer(uint256 jobId) {
        require(jobs[jobId].payer == msg.sender, "not payer");
        _;
    }
    /// @dev Explicit agent check: the job must exist, an agent must be
    ///   assigned (no silent pass for open/unaccepted jobs), and the caller
    ///   must be that agent.
    modifier onlyAgent(uint256 jobId) {
        Job storage job = jobs[jobId];
        require(job.payer != address(0), "job does not exist");
        require(job.agent != address(0), "no agent assigned");
        require(job.agent == msg.sender, "not agent");
        _;
    }

    /// @dev The dispute bond for a job amount: 20%, floored at $1 and
    ///   capped at $50 (6-decimal token units).
    function _bondAmount(uint256 jobAmount) internal pure returns (uint256) {
        uint256 bond = (jobAmount * BOND_BPS) / 10000;
        if (bond < BOND_MIN) bond = BOND_MIN;
        if (bond > BOND_MAX) bond = BOND_MAX;
        return bond;
    }

    /// @dev The longest review window a job amount may carry.
    ///   Under $10 -> 24h; $10-$100 -> 72h; over $100 -> 7 days.
    function _maxReviewWindow(uint256 jobAmount) internal pure returns (uint256) {
        if (jobAmount < TIER1_MAX_AMOUNT) return TIER1_MAX_WINDOW;
        if (jobAmount <= TIER2_MAX_AMOUNT) return TIER2_MAX_WINDOW;
        return TIER3_MAX_WINDOW;
    }

    /// @dev Recover an EIP-712 signer with manual ecrecover (no imports).
    ///   Rejects malleable signatures (EIP-2: s > n/2) and bad v values.
    function _recoverSigner(bytes32 digest, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "bad sig length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        require(uint256(s) <= MAX_SIG_S, "malleable sig");
        require(v == 27 || v == 28, "bad v");
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "bad sig");
        return signer;
    }

    /// @notice Operator-managed token whitelist. Only the operator may
    ///   change it. USD stablecoins only.
    /// @dev Listing requires 6 decimals: the bond math (20%, min $1,
    ///   max $50) and the review-window tiers are all 6-decimal units,
    ///   so a token with other decimals would make every amount
    ///   economically wrong. A token that does not implement decimals(),
    ///   or returns anything other than 6, cannot be listed. Delisting
    ///   needs no decimals check — removing a token is always safe.
    function setTokenAllowed(address token, bool allowed) external {
        require(msg.sender == operator, "not operator");
        require(token != address(0), "zero address");
        if (allowed) {
            (uint256 dec, bool ok) = _tokenDecimals(token);
            require(ok && dec == 6, "token must be 6 decimals");
        }
        allowedTokens[token] = allowed;
        emit TokenWhitelisted(token, allowed);
    }

    /// @notice Fund a job for a specific worker. Payer must have approved `amount` of `token` first.
    /// @dev The token must be whitelisted by the operator.
    /// @dev The stored amount is what actually arrived (balance before/after).
    /// @dev The review window is capped by the job amount tier.
    function createJob(
        address agent,
        address token,
        uint256 amount,
        uint256 deadlineSeconds,
        uint256 reviewWindowSeconds,
        string calldata metadataURI
    ) external nonReentrant returns (uint256 jobId) {
        require(agent != address(0), "zero address agent");
        require(agent != msg.sender, "payer cannot be agent");
        return _createJob(agent, token, amount, deadlineSeconds, reviewWindowSeconds, metadataURI);
    }

    /// @notice Fund an open job: no worker named, anyone may accept it and
    ///   becomes the agent on-chain. Payer must have approved `amount` first.
    /// @dev The token must be whitelisted by the operator.
    function createOpenJob(
        address token,
        uint256 amount,
        uint256 deadlineSeconds,
        uint256 reviewWindowSeconds,
        string calldata metadataURI
    ) external nonReentrant returns (uint256 jobId) {
        return _createJob(address(0), token, amount, deadlineSeconds, reviewWindowSeconds, metadataURI);
    }

    /// @dev Shared funding logic for createJob and createOpenJob.
    /// @dev The deadline clock does NOT start here: deadline is stored as
    ///   0 and deadlineSeconds is saved; acceptJob sets
    ///   deadline = block.timestamp + deadlineSeconds.
    /// @dev The review-window max is checked against the amount that
    ///   actually arrived, after funding.
    function _createJob(
        address agent,
        address token,
        uint256 amount,
        uint256 deadlineSeconds,
        uint256 reviewWindowSeconds,
        string calldata metadataURI
    ) internal returns (uint256 jobId) {
        require(token != address(0), "zero address");
        require(allowedTokens[token], "token not allowed");
        require(amount > 0, "amount zero");
        require(deadlineSeconds > 0, "deadline zero");
        require(reviewWindowSeconds >= MIN_REVIEW_WINDOW, "review window too short");
        uint256 balanceBefore = _balanceOf(token);
        _safeTransferFrom(token, msg.sender, amount);
        uint256 received = _balanceOf(token) - balanceBefore;
        require(received > 0, "no funds received");
        require(reviewWindowSeconds <= _maxReviewWindow(received), "review window too long");

        jobId = jobCount++;
        jobs[jobId] = Job({
            payer: msg.sender,
            agent: agent,
            token: token,
            amount: received,
            deadline: 0,
            reviewWindow: reviewWindowSeconds,
            state: State.Created,
            deliveryHash: bytes32(0),
            metadataURI: metadataURI,
            deliveredAt: 0,
            deadlineSeconds: deadlineSeconds,
            deliveryText: "",
            disputeReason: "",
            bondAmount: 0,
            disputedAt: 0
        });
        totalUnsettled[token] += received;
        emit JobCreated(jobId, msg.sender, agent, token, received, 0, metadataURI);
    }

    /// @notice Accept a job. Accepting STARTS the deadline clock.
    /// @dev For an open job (agent == address(0)) any caller may accept and
    ///   becomes the agent — except the payer.
    ///   For a named job only the named agent may accept.
    /// @dev Reverts on non-existent jobId (phantom job bug fixed in V10).
    function acceptJob(uint256 jobId) external {
        Job storage job = jobs[jobId];
        require(job.payer != address(0), "job does not exist");
        if (job.agent == address(0)) {
            require(msg.sender != job.payer, "payer cannot be agent");
            job.agent = msg.sender;
            } else {
            require(job.agent == msg.sender, "not agent");
        }
        require(job.state == State.Created, "not created");
        job.deadline = block.timestamp + job.deadlineSeconds;
        job.state = State.Accepted;
        emit JobAccepted(jobId, msg.sender);
    }

    /// @dev The worker's delivery description is stored on-chain
    ///   (deliveryText) so the judge can see what was actually delivered —
    ///   not just a hash of text the UI discarded.
    function submitDelivery(uint256 jobId, bytes32 deliveryHash, string calldata deliveryText) external onlyAgent(jobId) {
        require(bytes(deliveryText).length <= MAX_DELIVERY_TEXT, "delivery text too long");
        Job storage job = jobs[jobId];
        require(job.state == State.Accepted, "not accepted");
        require(block.timestamp <= job.deadline, "deadline passed");
        require(deliveryHash != bytes32(0), "empty delivery hash");
        job.state = State.Delivered;
        job.deliveryHash = deliveryHash;
        job.deliveryText = deliveryText;
        job.deliveredAt = block.timestamp;
        emit DeliverySubmitted(jobId, deliveryHash, deliveryText);
    }

    /// @notice Atomic deliver + dispute. The worker delivers AND raises a
    ///   dispute in ONE transaction, so the payer cannot front-run the
    ///   dispute after seeing the delivery in the mempool. The job moves
    ///   Accepted -> Disputed directly, skipping Delivered — the payer
    ///   never gets a window to call releasePartial first.
    /// @dev Same delivery validation as submitDelivery. The dispute is
    ///   raised by the agent, so no bond is posted (the bond is the
    ///   payer's). The ruling splits the job amount only.
    function submitDeliveryAndDispute(uint256 jobId, bytes32 deliveryHash, string calldata deliveryText, string calldata disputeReason) external onlyAgent(jobId) {
        require(bytes(deliveryText).length <= MAX_DELIVERY_TEXT, "delivery text too long");
        require(bytes(disputeReason).length <= MAX_DISPUTE_REASON, "dispute reason too long");
        Job storage job = jobs[jobId];
        require(job.state == State.Accepted, "not accepted");
        require(block.timestamp <= job.deadline, "deadline passed");
        require(deliveryHash != bytes32(0), "empty delivery hash");
        job.state = State.Disputed;
        job.deliveryHash = deliveryHash;
        job.deliveryText = deliveryText;
        job.deliveredAt = block.timestamp;
        job.disputeReason = disputeReason;
        job.disputedAt = block.timestamp;
        emit DeliverySubmitted(jobId, deliveryHash, deliveryText);
        emit DisputeRaised(jobId, msg.sender);
    }

    /// @notice Release funds to the agent after delivery.
    /// @dev Same window semantics as V9: the payer may release at any time
    ///   while Delivered; the agent may claim after the review window ends.
    function release(uint256 jobId) external nonReentrant {
        Job storage job = jobs[jobId];
        require(job.state == State.Delivered, "not delivered");
        if (msg.sender == job.agent) {
            require(
                block.timestamp > job.deliveredAt + job.reviewWindow,
                "review window not ended"
            );
        } else {
            require(msg.sender == job.payer, "not payer");
        }
        job.state = State.Released;
        totalUnsettled[job.token] -= job.amount;
        _payOrCredit(job.token, job.agent, job.amount);
        emit JobReleased(jobId, job.agent, job.amount);
    }

    /// @notice Payer splits a delivered job's funds: amountToWorker to the
    ///   agent, the rest back to the payer.
    /// @dev The split requires BOTH:
    ///   - The WORKER'S EIP-712 signature over
    ///     PartialRelease(jobId, amountToWorker, deadline). The payer
    ///     submits the worker's signature; without the worker's consent
    ///     there is no split — only full release() or a dispute.
    ///     A captured signature cannot replay: a successful split moves
    ///     the job to Released, so any replay reverts on "not delivered".
    ///     (V3: the per-job partial-release nonce is REMOVED — it could
    ///     never increment twice for one job, so the state transition is
    ///     the replay protection. See README.md.)
    ///   - DUST REJECTION: amountToWorker must be at least 1%
    ///     (MIN_PARTIAL_BPS) of the job amount, unless it is the full
    ///     amount. 1-wei games revert.
    ///   Still only callable DURING the review window, by the payer, while
    ///   Delivered. After the window, only the agent may claim via
    ///   release(), or a dispute resolves by ruling, agreement, or refund.
    function releasePartial(uint256 jobId, uint256 amountToWorker, uint256 deadline, bytes calldata workerSig) external nonReentrant {
        Job storage job = jobs[jobId];
        require(job.state == State.Delivered, "not delivered");
        require(msg.sender == job.payer, "not payer");
        require(amountToWorker > 0, "cannot release zero to worker");
        require(amountToWorker <= job.amount, "exceeds job amount");
        require(
            block.timestamp <= job.deliveredAt + job.reviewWindow,
            "review window passed"
        );
        require(block.timestamp <= deadline, "split signature expired");
        if (amountToWorker < job.amount) {
            require(
                amountToWorker >= (job.amount * MIN_PARTIAL_BPS) / 10000,
                "dust partial rejected"
            );
        }
        // The worker must have signed this exact split.
        bytes32 structHash = keccak256(abi.encode(
            PARTIAL_RELEASE_TYPEHASH,
            jobId,
            amountToWorker,
            deadline
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        address signer = _recoverSigner(digest, workerSig);
        require(signer == job.agent, "worker sig required");

        uint256 amountToPayer = job.amount - amountToWorker;
        job.state = State.Released;
        totalUnsettled[job.token] -= job.amount;
        if (amountToWorker > 0) {
            _payOrCredit(job.token, job.agent, amountToWorker);
        }
        if (amountToPayer > 0) {
            _payOrCredit(job.token, job.payer, amountToPayer);
        }
        emit JobPartiallyReleased(jobId, job.agent, amountToWorker, amountToPayer);
    }

    /// @notice Payer exits a job before work starts, or reclaims funds
    ///   when the agent accepted and then ghosted past the deadline.
    ///   Two cases, one entry point:
    ///   - State Created -> refund at once, state Cancelled, JobCancelled.
    ///   - State Accepted AND block.timestamp > deadline -> refund at
    ///     once, state Refunded, JobRefunded (the ghosted-agent exit).
    ///   - State Accepted before the deadline -> reverts
    ///     "deadline not passed". Any other state -> reverts
    ///     "cannot cancel in this state".
    /// @dev The old refundAfterDeadline was folded in here: a Created
    ///   job has deadline == 0, so a separate deadline-refund was a
    ///   second cancel path. One function, both exits.
    function cancel(uint256 jobId) external onlyPayer(jobId) nonReentrant {
        Job storage job = jobs[jobId];
        if (job.state == State.Created) {
            job.state = State.Cancelled;
            emit JobCancelled(jobId);
        } else if (job.state == State.Accepted) {
            require(block.timestamp > job.deadline, "deadline not passed");
            job.state = State.Refunded;
            emit JobRefunded(jobId, job.payer, job.amount);
        } else {
            revert("cannot cancel in this state");
        }
        totalUnsettled[job.token] -= job.amount;
        _payOrCredit(job.token, job.payer, job.amount);
    }

    /// @notice Either party raises a dispute — only INSIDE the review window.
    /// @dev Same boundary semantics as V9 (inclusive window).
    /// @dev The reason is stored ON-CHAIN in disputeReason (capped at
    ///   10 KB) so the judge can read it without trusting the UI.
    /// @dev BOND: when the PAYER disputes, they post a 20% bond (min $1,
    ///   max $50) in the same transaction — pulled from the payer, so the
    ///   payer must have approved it. The bond must arrive in full
    ///   (balance-delta checked). When the AGENT disputes, no bond is
    ///   posted; the ruling splits the job amount only.
    function raiseDispute(uint256 jobId, string calldata reason) external nonReentrant {
        require(bytes(reason).length <= MAX_DISPUTE_REASON, "dispute reason too long");
        Job storage job = jobs[jobId];
        require(job.payer != address(0), "job does not exist");
        require(msg.sender == job.payer || msg.sender == job.agent, "not a party");
        require(job.state == State.Delivered, "only after delivery");
        require(
            block.timestamp <= job.deliveredAt + job.reviewWindow,
            "review window ended"
        );
        job.state = State.Disputed;
        job.disputeReason = reason;
        job.disputedAt = block.timestamp;
        if (msg.sender == job.payer) {
            _collectBond(job, jobId);
        }
        emit DisputeRaised(jobId, msg.sender);
    }

    /// @dev Pull the dispute bond from the payer. Split out of
    ///   raiseDispute to keep its stack shallow. The bond must arrive
    ///   in full (balance-delta checked).
    function _collectBond(Job storage job, uint256 jobId) internal {
        uint256 bond = _bondAmount(job.amount);
        uint256 balanceBefore = _balanceOf(job.token);
        _safeTransferFrom(job.token, msg.sender, bond);
        uint256 received = _balanceOf(job.token) - balanceBefore;
        require(received == bond, "bond shortfall");
        job.bondAmount = bond;
        totalBonded[job.token] += bond;
        emit BondPosted(jobId, msg.sender, bond);
    }

    /// @notice The operator executes the AI Judge's ruling: amountToWorker
    ///   to the agent, the rest back to the payer. The operator does not
    ///   decide — the ruling is made off-chain by the judge; this call
    ///   only executes it. Judgment is final.
    /// @dev BOND: the bond follows the ruling. The judge awards the worker
    ///   >= 50% of the job amount -> bond to worker; < 50% -> bond to
    ///   payer. (>= is written as amountToWorker >= amountToPayer, so no
    ///   multiplication can overflow.)
    /// @dev HARD DEADLINE: the ruling must execute within RULING_PERIOD
    ///   of the dispute (inclusive boundary — at exactly disputedAt +
    ///   RULING_PERIOD it still succeeds). After that, only the 72h
    ///   refund valve can settle the job. No race between a late ruling
    ///   and the valve.
    /// @dev Single-use: the job leaves Disputed, so a second ruling
    ///   reverts on "not disputed". State is Refunded when the worker
    ///   gets 0, Released otherwise.
    function executeRuling(uint256 jobId, uint256 amountToWorker) external nonReentrant {
        Job storage job = jobs[jobId];
        require(msg.sender == operator, "not operator");
        require(job.state == State.Disputed, "not disputed");
        require(amountToWorker <= job.amount, "exceeds job amount");
        require(
            block.timestamp <= job.disputedAt + RULING_PERIOD,
            "ruling period ended"
        );
        address bondTo = amountToWorker >= job.amount - amountToWorker ? job.agent : job.payer;
        _settleDispute(jobId, amountToWorker, bondTo);
        emit RulingExecuted(jobId, amountToWorker, job.amount - amountToWorker, bondTo);
    }

    /// @notice Settle a disputed job by agreement of both parties, at any
    ///   time while it is Disputed. The caller is one party;
    ///   `counterpartySig` is the other party's EIP-712 signature over
    ///   SettleDispute(jobId, amountToWorker, deadline). The caller's
    ///   consent is implied by calling with that amount.
    /// @dev amountToWorker may be anything from 0 (full refund) to
    ///   job.amount (full release); there is no dust rule because both
    ///   parties chose it. Single-use: the job leaves Disputed, so the
    ///   signature cannot replay.
    /// @dev BOND: on mutual settle the bond returns to the payer in full.
    ///   The bond exists to back the judge's ruling; with no ruling there
    ///   is nothing to back, so it returns to whoever posted it.
    function settleByAgreement(
        uint256 jobId,
        uint256 amountToWorker,
        uint256 deadline,
        bytes calldata counterpartySig
    ) external nonReentrant {
        Job storage job = jobs[jobId];
        require(job.state == State.Disputed, "not disputed");
        require(msg.sender == job.payer || msg.sender == job.agent, "not a party");
        require(amountToWorker <= job.amount, "exceeds job amount");
        require(block.timestamp <= deadline, "settlement signature expired");

        bytes32 structHash = keccak256(abi.encode(
            SETTLE_DISPUTE_TYPEHASH,
            jobId,
            amountToWorker,
            deadline
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        address counterparty = msg.sender == job.payer ? job.agent : job.payer;
        require(_recoverSigner(digest, counterpartySig) == counterparty, "counterparty sig required");

        _settleDispute(jobId, amountToWorker, job.payer);
        emit SettledByAgreement(jobId, amountToWorker, job.amount - amountToWorker);
    }

    /// @notice Exit for a dispute no ruling resolved: if 72 hours pass
    ///   after the dispute with no ruling executed, anyone may call this
    ///   and the job amount + bond refund to the payer in full.
    /// @dev Boundary semantics: STRICT
    ///   (block.timestamp > disputedAt + RULING_PERIOD).
    function refundDisputeTimeout(uint256 jobId) external nonReentrant {
        Job storage job = jobs[jobId];
        require(job.state == State.Disputed, "not disputed");
        require(
            block.timestamp > job.disputedAt + RULING_PERIOD,
            "ruling period not ended"
        );
        uint256 bond = job.bondAmount;
        _settleDispute(jobId, 0, job.payer);
        emit DisputeTimeoutRefunded(jobId, job.payer, job.amount, bond);
    }

    /// @dev Shared dispute settlement: pays the job amount out (worker /
    ///   payer split) and the bond to `bondTo`. Sets Refunded when the
    ///   worker gets 0, Released otherwise. Emits JobRefunded on a full
    ///   refund. Callers emit their own path-specific event.
    function _settleDispute(uint256 jobId, uint256 amountToWorker, address bondTo) internal {
        Job storage job = jobs[jobId];
        uint256 amountToPayer = job.amount - amountToWorker;
        if (amountToWorker == 0) {
            job.state = State.Refunded;
        } else {
            job.state = State.Released;
        }
        totalUnsettled[job.token] -= job.amount;
        _payBond(job, bondTo);
        if (amountToWorker > 0) {
            _payOrCredit(job.token, job.agent, amountToWorker);
        }
        if (amountToPayer > 0) {
            _payOrCredit(job.token, job.payer, amountToPayer);
        }
        if (amountToWorker == 0) {
            emit JobRefunded(jobId, job.payer, amountToPayer);
        }
    }

    /// @dev Pay the dispute bond out to `bondTo` and clear the books.
    ///   Split out of _settleDispute to keep its stack shallow.
    function _payBond(Job storage job, address bondTo) internal {
        uint256 bond = job.bondAmount;
        if (bond == 0) return;
        totalBonded[job.token] -= bond;
        job.bondAmount = 0;
        _payOrCredit(job.token, bondTo, bond);
    }

    /// @notice Withdraw the caller's pending credit for a token.
    /// @dev Same balance-verified withdrawal as V9 (see V9 NatSpec).
    function withdraw(address token) external nonReentrant {
        uint256 amount = pendingWithdrawals[token][msg.sender];
        require(amount > 0, "nothing to withdraw");
        pendingWithdrawals[token][msg.sender] = 0;
        totalPendingCredits[token] -= amount;
        uint256 balanceBefore = _balanceOf(token);
        _tryTransfer(token, msg.sender, amount);
        uint256 balanceAfter = _balanceOf(token);
        uint256 moved = balanceBefore > balanceAfter ? balanceBefore - balanceAfter : 0;
        require(moved == amount, "withdrawal failed");
        emit Withdrawn(token, msg.sender, msg.sender, amount);
    }

    /// @dev SafeERC20-style transfer attempt. (See V9 NatSpec for the
    ///   assembly returndata-cap design and gas ceilings.)
    function _tryTransfer(address token, address to, uint256 amount) internal returns (bool) {
        if (token.code.length == 0) return false;
        bytes memory data = abi.encodeWithSelector(IERC20.transfer.selector, to, amount);
        bool success;
        assembly {
            success := call(gas(), token, 0, add(data, 0x20), mload(data), 0, 0x20)
        }
        if (!success) return false;
        return _lastCallReturnedTrue();
    }

    /// @dev Inspect the returndata of the most recent external call.
    ///   (See V9 NatSpec.)
    function _lastCallReturnedTrue() internal view returns (bool) {
        uint256 size;
        assembly { size := returndatasize() }
        if (size == 0) return true;
        if (size != 32) return false;
        uint256 value;
        assembly {
            let ptr := mload(0x40)
            returndatacopy(ptr, 0, 32)
            value := mload(ptr)
        }
        return value == 1;
    }

    /// @dev Balance read that never reverts. (See V9 NatSpec.)
    function _balanceOf(address token) internal view returns (uint256 bal) {
        bytes memory data = abi.encodeWithSelector(IERC20.balanceOf.selector, address(this));
        bool success;
        assembly {
            success := staticcall(gas(), token, add(data, 0x20), mload(data), 0, 0x20)
        }
        if (!success) return 0;
        uint256 size;
        assembly { size := returndatasize() }
        if (size != 32) return 0;
        assembly {
            let ptr := mload(0x40)
            returndatacopy(ptr, 0, 32)
            bal := mload(ptr)
        }
    }

    /// @dev Decimals read that never reverts. Same pattern as _balanceOf:
    ///   staticcall, and a 32-byte return is required. An EOA, a token
    ///   without decimals(), or a non-standard return all report
    ///   ok=false instead of panicking on an ABI decode.
    function _tokenDecimals(address token) internal view returns (uint256 dec, bool ok) {
        bytes memory data = abi.encodeWithSelector(IERC20.decimals.selector);
        bool success;
        assembly {
            success := staticcall(gas(), token, add(data, 0x20), mload(data), 0, 0x20)
        }
        if (!success) return (0, false);
        uint256 size;
        assembly { size := returndatasize() }
        if (size != 32) return (0, false);
        assembly {
            let ptr := mload(0x40)
            returndatacopy(ptr, 0, 32)
            dec := mload(ptr)
        }
        return (dec, true);
    }

    /// @dev Attempt a token payout; on failure, credit a pull balance.
    ///   (See V9 NatSpec for the balance-verification design.)
    function _payOrCredit(address token, address to, uint256 amount) internal {
        uint256 balanceBefore = _balanceOf(token);
        _tryTransfer(token, to, amount);
        uint256 balanceAfter = _balanceOf(token);
        uint256 moved = balanceBefore > balanceAfter ? balanceBefore - balanceAfter : 0;
        if (moved >= amount) {
            return;
        }
        uint256 shortfall = amount - moved;
        pendingWithdrawals[token][to] += shortfall;
        totalPendingCredits[token] += shortfall;
        emit Credited(token, to, shortfall);
    }

    /// @dev SafeERC20-style transferFrom. (See V9 NatSpec.)
    function _safeTransferFrom(address token, address from, uint256 amount) internal {
        bytes memory data = abi.encodeWithSelector(
            IERC20.transferFrom.selector, from, address(this), amount
        );
        bool success;
        assembly {
            success := call(gas(), token, 0, add(data, 0x20), mload(data), 0, 0x20)
        }
        require(success && _lastCallReturnedTrue(), "funding failed");
    }

    /// @notice The pull balance an account can withdraw for a token.
    function pendingCredit(address token, address account) external view returns (uint256 credit) {
        return pendingWithdrawals[token][account];
    }

    /// @notice The settlement invariant for a token, observable on-chain.
    ///   A surplus is harmless (donations, rounding); only a deficit
    ///   matters, so the check is >=, not ==.
    function settlementInvariant(address token) external view returns (
        uint256 balance,
        uint256 unsettledSum,
        uint256 bondedSum,
        uint256 pendingCreditsSum,
        bool holds
    ) {
        balance = _balanceOf(token);
        unsettledSum = totalUnsettled[token];
        bondedSum = totalBonded[token];
        pendingCreditsSum = totalPendingCredits[token];
        holds = balance >= unsettledSum + bondedSum + pendingCreditsSum;
    }

    function getJob(uint256 jobId) external view returns (Job memory) {
        return jobs[jobId];
    }
}
