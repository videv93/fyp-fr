from dataclasses import dataclass
from typing import List, Dict

@dataclass
class VulnerabilityDoc:
    name: str
    description: str
    scenario: str  # From GPTScan's "Scenario" column
    property: str  # From GPTScan's "Property" column
    impact: str
    code_patterns: List[str]
    prevention: List[str]
    exploit_template: Dict[str, str]

VULNERABILITY_DOCS = [
    VulnerabilityDoc(
        name="Approval Not Cleared",
        description="""
        A vulnerability where token approvals are not properly cleared after operations,
        leaving residual approvals that could be exploited in future transactions.
        """,
        scenario="Add or check approval via require/if statements before the token transfer",
        property="There is no clear/reset of the approval when the transfer finishes its main branch or encounters exceptions",
        impact="""
        Attackers can reuse old approvals to transfer more tokens than intended by the original approver.
        """,
        code_patterns=[
            "approve() or allowance check before transfer",
            "Missing approval reset after transfer",
            "Exception handling without approval clearing"
        ],
        prevention=[
            "Reset approvals to 0 after transfer completion",
            "Clear approvals when exceptions occur",
            "Implement approve-with-expiry pattern"
        ],
        exploit_template={
            "setup": """
            1. User A approves User B to spend X tokens
            2. User B performs partial transfer of Y tokens (where Y < X)
            """,
            "execution": """
            1. User B can still transfer remaining (X-Y) tokens later
            2. Even if User A intended to revoke after first transfer
            """,
            "validation": """
            Check remaining allowance is still usable after initial transfer
            """
        }
    ),

    VulnerabilityDoc(
        name="Risky First Deposit",
        description="""
        This vulnerability occurs when a contract does not perform necessary checks before accepting the first deposit. Specifically, the absence of a check like `totalSupply() == 0` allows the first depositor to manipulate the share price, potentially exploiting future depositors by skewing the token distribution or share ratios.
        """,
        scenario="The contract allows the first depositor to set an initial share price without any verification or constraints.",
        property="Lack of initialization checks before the first deposit.",
        impact="""
        An attacker can manipulate the share price by making a large initial deposit, which affects the ratio of shares to underlying assets. This manipulation can lead to significant financial losses for subsequent depositors and destabilize the token economy.
        """,
        code_patterns=[
            "function deposit() external payable {",
            "balances[msg.sender] += msg.value;",
            "shares[msg.sender] += msg.value / initialSharePrice;",
            "require(totalSupply() > 0, \"No shares available\");"
        ],
        prevention=[
            "Implement a check to ensure that the first deposit initializes the share price appropriately.",
            "Restrict the first depositor or use a predefined initial share price.",
            "Add a flag to indicate whether the initial setup has been completed."
        ],
        exploit_template={
            "setup": """
            1. Identify the deposit function in the contract.
            2. Prepare an account to perform the initial deposit.
            3. Ensure that no initialization checks are in place.
            """,
            "execution": """
            1. Make a large initial deposit to set an artificially high share price.
            2. Monitor the share price set by the deposit.
            """,
            "validation": """
            1. Verify that the share price has been manipulated to an abnormal value.
            2. Confirm that subsequent deposits are affected by the manipulated share price.
            """
        }
    ),

    # Vulnerability 2: Front Running
    VulnerabilityDoc(
        name="Front Running",
        description="""
        Front Running in smart contracts refers to the exploitation of pending transactions by submitting a transaction with a higher gas price to get it processed before the original one. This is particularly problematic in contracts that handle time-sensitive operations, slippage checks, or public value assignments without adequate safeguards.
        """,
        scenario="The contract lacks mechanisms to prevent other actors from observing and preempting transactions that can be exploited for financial gain.",
        property="Absence of nonce management, lack of slippage checks, and exposure of sensitive transaction details.",
        impact="""
        Attackers can exploit pending transactions by inserting their own transactions with higher gas fees, thereby gaining an unfair advantage. This can lead to financial losses for legitimate users, manipulation of market operations, and undermining trust in the contract's fairness.
        """,
        code_patterns=[
            "function executeTrade(uint256 amount) external {",
            "balances[msg.sender] -= amount;",
            "balances[recipient] += amount;",
            "emit TradeExecuted(msg.sender, recipient, amount);"
        ],
        prevention=[
            "Implement commit-reveal schemes to prevent observation of sensitive transaction details before execution.",
            "Use nonces or sequence numbers to manage transaction ordering and prevent manipulation.",
            "Incorporate slippage checks to ensure that trades execute within acceptable price ranges."
        ],
        exploit_template={
            "setup": """
            1. Identify functions that handle sensitive operations like trades or liquidity adjustments.
            2. Monitor the mempool for pending transactions targeting these functions.
            3. Prepare an attacker account with sufficient gas to front-run transactions.
            """,
            "execution": """
            1. Upon detecting a target transaction, quickly submit a similar transaction with a higher gas price.
            2. Ensure that the attacker's transaction is mined before the victim's transaction.
            3. Exploit the altered state to gain financial advantage.
            """,
            "validation": """
            1. Confirm that the attacker's transaction was successfully mined before the victim's transaction.
            2. Verify the profit made by the attacker due to front-running the victim's transaction.
            """
        }
    ),

    # Vulnerability 3: Price Manipulation by AMM
    VulnerabilityDoc(
        name="Price Manipulation by AMM",
        description="""
        Automated Market Makers (AMMs) rely on predefined algorithms to determine asset prices based on supply and demand. Vulnerabilities arise when critical calculations, such as swap outputs, fees, and liquidity shares, lack proper checks, allowing attackers to manipulate prices by exploiting the AMM's algorithmic behavior.
        """,
        scenario="The contract does not validate the spot price or implement safeguards against price manipulation, making it susceptible to attacks that can skew asset valuations within the AMM.",
        property="Absence of spot price validation, lack of price manipulation checks, and no direct pool balance queries.",
        impact="""
        Attackers can manipulate asset prices within the AMM, leading to unfair trades, financial losses for liquidity providers, and destabilization of the token economy. This manipulation can erode trust in the AMM's fairness and reliability.
        """,
        code_patterns=[
            "function calcSwapOutput(uint256 inputAmount) public view returns (uint256) {",
            "return (inputAmount * reserveOut) / reserveIn;",
            "}",
            "function addLiquidity(uint256 tokenAmount, uint256 ethAmount) public {",
            "reservesToken += tokenAmount;",
            "reservesETH += ethAmount;",
            "}"
        ],
        prevention=[
            "Implement spot price checks to ensure that critical calculations are based on accurate and tamper-resistant data.",
            "Use oracles to provide external price feeds that can validate internal AMM prices.",
            "Incorporate limits on how much the price can change within a single transaction or block."
        ],
        exploit_template={
            "setup": """
            1. Identify AMM-related functions such as price calculations and liquidity management.
            2. Prepare accounts with significant token holdings to influence pool balances.
            """,
            "execution": """
            1. Manipulate the pool balances by adding or removing large amounts of tokens.
            2. Execute trades that take advantage of the altered price calculations.
            3. Repeat the process to further skew prices and maximize exploitation.
            """,
            "validation": """
            1. Check the spot price and pool balances to confirm manipulation.
            2. Verify the financial gains from the manipulated trades.
            """
        }
    ),

    # Vulnerability 4: Reentrancy
    VulnerabilityDoc(
        name="Reentrancy",
        description="""
        Reentrancy is a vulnerability that occurs when a contract makes an external call to another contract before updating its state, allowing the called contract to call back into the original contract and potentially manipulate its state or drain funds.
        """,
        scenario="The contract calls an external contract or address before updating its own state variables, enabling the external contract to re-enter the vulnerable function and exploit the inconsistent state.",
        property="External calls (e.g., `call`, `delegatecall`, `send`, `transfer`) made before state updates.",
        impact="""
        Attackers can exploit reentrancy vulnerabilities to repeatedly call a vulnerable function before its state is updated, potentially draining funds or altering the contract's state in unintended ways. This can lead to significant financial losses and compromise the integrity of the contract.
        """,
        code_patterns=[
            "function withdraw(uint256 _amount) external {",
            "require(balances[msg.sender] >= _amount, \"Insufficient balance\");",
            "(bool success, ) = msg.sender.call{value: _amount}(\"\");",
            "require(success, \"Transfer failed\");",
            "balances[msg.sender] -= _amount;",
            "}"
        ],
        prevention=[
            "Use the Checks-Effects-Interactions pattern: first perform all necessary checks, then update state variables, and finally interact with external contracts.",
            "Implement reentrancy guards (e.g., using mutexes or the `nonReentrant` modifier from OpenZeppelin's ReentrancyGuard).",
            "Avoid using low-level calls like `call` when not necessary, and prefer safer alternatives.",
            "Limit the amount of gas forwarded to external contracts to reduce the risk of reentrancy."
        ],
        exploit_template={
            "setup": """
            1. Identify the vulnerable function that makes an external call before updating state.
            2. Deploy a malicious contract with a fallback function that calls back into the vulnerable function.
            """,
            "execution": """
            1. Call the vulnerable function from the malicious contract with a specific amount.
            2. In the fallback function of the malicious contract, re-enter the vulnerable function before the state is updated.
            3. Repeat the process to drain funds or manipulate the contract's state.
            """,
            "validation": """
            1. Verify that the contract's funds have been drained or the state has been manipulated.
            2. Confirm that the contract's balance is reduced beyond expected limits.
            """
        }
    ),

    VulnerabilityDoc(
        name="Wrong Checkpoint Order",
        description="""
        A vulnerability where the order of checkpoint updates and balance changes
        is incorrect, leading to reward calculation errors.
        """,
        scenario="Have inside code statements that invoke user checkpoint",
        property="And have inside code statements that calculate/assign/distribute the balance/share/stake/fee/loan/reward",
        impact="""
        Users can receive incorrect rewards or manipulate reward calculations by
        exploiting the wrong order of operations.
        """,
        code_patterns=[
            "Checkpoint after balance update",
            "Reward calculation before state update",
            "Missing synchronization between state changes"
        ],
        prevention=[
            "Update checkpoints before state changes",
            "Implement proper synchronization",
            "Use atomic operations where possible"
        ],
        exploit_template={
            "setup": """
            1. Identify reward-bearing token
            2. Monitor checkpoint and balance update sequence
            """,
            "execution": """
            1. Time transactions to exploit checkpoint lag
            2. Extract excess rewards
            """,
            "validation": """
            Compare actual vs expected reward amounts
            """
        }
    ),

    VulnerabilityDoc(
        name="Unauthorized Transfer",
        description="""
        A vulnerability where tokens can be transferred without proper authorization
        or allowance checks.
        """,
        scenario="Involve transfering token from an address different from message sender",
        property="And there is no check of allowance/approval from the address owner",
        impact="""
        Attackers can transfer tokens they don't own or aren't authorized to move.
        """,
        code_patterns=[
            "Missing allowance checks",
            "Incorrect sender verification",
            "Bypassed authorization logic"
        ],
        prevention=[
            "Implement proper allowance checks",
            "Verify msg.sender authorization",
            "Use OpenZeppelin's SafeERC20"
        ],
        exploit_template={
            "setup": """
            1. Identify vulnerable transfer function
            2. Target account with balance
            """,
            "execution": """
            1. Call transfer without approval
            2. Move unauthorized tokens
            """,
            "validation": """
            Verify transfers succeed without proper approval
            """
        }
    ),

    VulnerabilityDoc(
        name="Price Manipulation by Buying Tokens",
        description="""
        Vulnerability where token prices can be manipulated through buying pressure
        before important operations.
        """,
        scenario="Buy some tokens",
        property="Using Uniswap/PancakeSwap APIs",
        impact="""
        Attackers can artificially inflate token prices before operations that depend
        on token value.
        """,
        code_patterns=[
            "DEX integration calls",
            "Price queries before operations",
            "Missing price manipulation checks"
        ],
        prevention=[
            "Use TWAPs for price feeds",
            "Implement price impact limits",
            "Add cooldown periods"
        ],
        exploit_template={
            "setup": """
            1. Prepare large capital
            2. Monitor target token pool
            """,
            "execution": """
            1. Buy large amount of tokens
            2. Execute price-sensitive operation
            3. Sell tokens back
            """,
            "validation": """
            Verify profit exceeds gas and slippage costs
            """
        }
    ),

    VulnerabilityDoc(
        name="Vote Manipulation by Flashloan",
        description="""
        Vulnerability where governance votes can be manipulated using flash loans
        to temporarily acquire voting power.
        """,
        scenario="Calculate vote amount/number",
        property="And this vote amount/number is from a vote weight that might be manipulated by flashloan",
        impact="""
        Attackers can borrow large amounts of tokens to swing governance votes
        without long-term capital commitment.
        """,
        code_patterns=[
            "Vote weight calculation",
            "Snapshot mechanics",
            "Missing flashloan protection"
        ],
        prevention=[
            "Implement voting delays",
            "Check token holding duration",
            "Use delegation mechanics"
        ],
        exploit_template={
            "setup": """
            1. Identify flash loan source
            2. Calculate required voting power
            """,
            "execution": """
            1. Take flash loan
            2. Cast vote
            3. Repay flash loan
            """,
            "validation": """
            Verify vote was counted with borrowed tokens
            """
        }
    ),

    VulnerabilityDoc(
        name="Wrong Interest Rate Order",
        description="""
        Vulnerability where interest rate updates are performed in incorrect order,
        leading to calculation errors.
        """,
        scenario="Have inside code statements that update/accrue interest/exchange rate",
        property="And have inside code statements that calculate/assign/distribute the balance/share/stake/fee/loan/reward",
        impact="""
        Users can receive incorrect interest calculations or manipulate rates for profit.
        """,
        code_patterns=[
            "Interest rate updates",
            "Balance calculations",
            "Order-dependent operations"
        ],
        prevention=[
            "Follow rate-before-balance pattern",
            "Use atomic rate updates",
            "Implement rate checkpoints"
        ],
        exploit_template={
            "setup": """
            1. Monitor interest rate changes
            2. Identify calculation sequence
            """,
            "execution": """
            1. Time transaction before rate update
            2. Exploit calculation order
            """,
            "validation": """
            Compare actual vs expected interest
            """
        }
    ),

    VulnerabilityDoc(
        name="Slippage",
        description="""
        Vulnerability where trades can experience unexpected price slippage due to
        missing or inadequate slippage protection.
        """,
        scenario="Involve calculating swap/liquidity or adding liquidity, and there is asset exchanges or price queries",
        property="But this operation could be attacked by Slippage/Sandwich Attack due to no slip limit/minimum value check",
        impact="""
        Users can experience significant losses due to price movement between
        transaction submission and execution.
        """,
        code_patterns=[
            "DEX integration",
            "Missing slippage checks",
            "Price-sensitive operations"
        ],
        prevention=[
            "Add slippage parameters",
            "Implement price bounds",
            "Use price oracles"
        ],
        exploit_template={
            "setup": """
            1. Monitor large pending swaps
            2. Calculate profitable slippage
            """,
            "execution": """
            1. Front-run with buy
            2. Let victim transaction execute
            3. Back-run with sell
            """,
            "validation": """
            Verify extracted value from slippage
            """
        }
    )
]
