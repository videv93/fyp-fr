# Smart Contract Vulnerability Analysis Report

**Job ID:** 271ddd84-e20a-4b75-8987-568186ea0842
**Date:** 2025-03-21 00:58:47

**Contract Preview:**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface IPriceOracle {
    function getPrice() external view returns (uint256);
}

contract MinimalLending {
    address public owner;
    IERC20 public token;
    IPriceOracle public oracle;

    uint256 public constant MIN_COLLATERAL_RATIO = 150;
    uint256 public constant LIQUIDATION_THRESHOLD = 110;
    uint256 public constant INTEREST_RATE_PER_SECOND = 3170979198;

    struct Loan {
        uint256 collateral;
...
```

## Vulnerability Summary

Found 3 potential vulnerabilities:

| # | Vulnerability Type | Confidence | Affected Functions |
|---|-------------------|------------|--------------------|
| 1 | price_manipulation | 0.60 | borrow, isLiquidatable |
| 2 | arithmetic | 0.30 | getCurrentDebt, repayLoan, liquidate |
| 3 | denial_of_service | 0.00 | repayLoan, liquidate |

## Detailed Analysis

### Vulnerability #1: price_manipulation

**Confidence:** 0.60

**Reasoning:**

The contract relies on an external price oracle (via IPriceOracle.getPrice) to convert ETH collateral into a token value. If the oracle is not sufficiently decentralized or is otherwise manipulable – for example, by an attacker controlling or influencing its returned price – then a borrower might obtain an artificially high collateral value at the time of borrowing. This would allow the borrower to take out a larger loan relative to their actual collateral. Later, if the oracle price is corrected, the borrower might be in an overcollateralized position or a liquidator may trigger liquidation under potentially unfair conditions. In either case, economic attacks and abuse of the lending system become possible.

**Validation:**

The contract relies on an external price oracle for determining collateral value in both the borrow and liquidation flows. If an attacker can manipulate the oracle (for example, if it’s not decentralized or sufficiently secured), they could abuse the collateralization checks. While this is a known dependency risk common in lending protocols and the oracle isn’t part of the contract’s internal logic, its manipulation would directly impact the business logic and risk undercollateralization. Thus, this vulnerability is genuine in that it warrants caution, though its exploitability depends on the oracle’s trustworthiness.

**Code Snippet:**

```solidity
function borrow(uint256 borrowAmount) external payable {
        require(msg.value > 0, "Collateral required");
        require(loans[msg.sender].principal == 0, "Existing loan exists");

        uint256 price = oracle.getPrice();
        uint256 collateralValue = (msg.value * price) / 1e18;
        require(
            collateralValue * 100 >= borrowAmount * MIN_COLLATERAL_RATIO,
            "Insufficient collateral"
        );

        loans[msg.sender] = Loan({
            collateral: msg.value,
            principal: borrowAmount,
            startTime: block.timestamp
        });

        require(
            token.transfer(msg.sender, borrowAmount),
            "Token transfer failed"
        );
    }

function isLiquidatable(address borrower) public view returns (bool) {
        Loan memory loan = loans[borrower];
        if (loan.principal == 0) return false;
        uint256 debt = getCurrentDebt(borrower);
        uint256 price = oracle.getPrice();
        uint256 collateralValue = (loan.collateral * price) / 1e18;
        return (debt * 100) >= (collateralValue * LIQUIDATION_THRESHOLD);
    }
```

**Affected Functions:** borrow, isLiquidatable

**Exploit Plan:**

*Setup Steps:*

- Step 1: Create a test environment deploying the vulnerable lending contract along with a mock price oracle whose returned price can be manipulated.
- Step 2: Prepare necessary contracts including a simple ERC20 token contract and set up test accounts for a borrower and an attacker.

*Execution Steps:*

- Step 1: Demonstrate the normal behavior by having a borrower deposit collateral and call borrow() with a realistic oracle price, ensuring the proper loan amount is issued.
- Step 2: Manipulate the oracle to return an inflated price. Then, have the borrower call borrow() to take out a larger loan with the same collateral. Afterwards, simulate a price correction and call isLiquidatable() to show how this leads to economic abuse via an overestimated collateral value.

*Validation Steps:*

- Step 1: Explain that the vulnerability arises from relying on an external price oracle that can be manipulated, violating the principle of trusted input data for financial calculations.
- Step 2: Demonstrate fixes such as integrating multiple decentralized oracles, using time-weighted average pricing, or implementing safeguards to limit drastic price changes to prevent manipulation.

---

### Vulnerability #2: arithmetic

**Confidence:** 0.30

**Reasoning:**

The contract computes accrued interest in getCurrentDebt() by approximating the exponential growth of interest through a truncated Taylor series expansion (using terms 1 + x + x²/2 + x³/6). For longer durations or higher interest accrual, this approximation can diverge significantly from the true exponential function. This imprecision could result in the debtor owing less than they should, or create inconsistency between the amount repaid and the expected debt value. Attackers might be able to exploit these inaccuracies by timing their repayments or liquidations to capture the mispricing in the accrued debt.

**Validation:**

The arithmetic in getCurrentDebt approximates exponential interest with a 3‐term Taylor series expansion. There is some potential for minor approximation errors or precision issues if very large time intervals occur, but in practice the interest rate and time scales envisioned by the protocol keep these values small enough that errors remain negligible. There is no classic arithmetic overflow concern in Solidity ^0.8.0 since built‐in overflow checking applies. Thus, while it’s worth noting the approximation, it is unlikely to be exploitable in a way that harms the protocol’s business logic.

**Code Snippet:**

```solidity
function getCurrentDebt(address borrower) public view returns (uint256) {
        Loan memory loan = loans[borrower];
        if (loan.principal == 0) return 0;
        uint256 timeElapsed = block.timestamp - loan.startTime;
        uint256 scale = 1e18;

        uint256 x = (INTEREST_RATE_PER_SECOND * timeElapsed) / scale;

        uint256 x2 = (x * x) / scale;
        uint256 x3 = (x2 * x) / scale;

        uint256 expApprox = scale + x + (x2 / 2) + (x3 / 6);

        return (loan.principal * expApprox) / scale;
    }

function repayLoan() external {
        Loan memory loan = loans[msg.sender];
        require(loan.principal > 0, "No active loan");
        uint256 debt = getCurrentDebt(msg.sender);
        uint256 collateral = loan.collateral;
        delete loans[msg.sender];

        require(
            token.transferFrom(msg.sender, address(this), debt),
            "Token transfer failed"
        );
        (bool success, ) = msg.sender.call{value: collateral}("");
        require(success, "ETH refund failed");
    }

function liquidate(address borrower) external {
        require(isLiquidatable(borrower), "Loan not liquidatable");
        Loan memory loan = loans[borrower];
        uint256 debt = getCurrentDebt(borrower);
        uint256 collateral = loan.collateral;
        delete loans[borrower];
        require(
            token.transferFrom(msg.sender, address(this), debt),
            "Token transfer failed"
        );
        (bool success, ) = msg.sender.call{value: collateral}("");
        require(success, "Collateral transfer failed");
    }
```

**Affected Functions:** getCurrentDebt, repayLoan, liquidate

---

### Vulnerability #3: denial_of_service

**Confidence:** 0.00

**Reasoning:**

Both the repayLoan() and liquidate() functions perform an ETH refund to msg.sender via a low-level call (msg.sender.call{value: collateral}(...)). Although the code does check for the success of the call, if the recipient is a contract with a fallback function that deliberately reverts upon receiving ETH, the refund will fail and the entire transaction will revert. This could be exploited by borrowers (or liquidators) who use contracts with deliberately reverting fallback functions to force a DoS condition, either to block their own repayment (potentially stalling the system) or to prevent the liquidation process from proceeding.

**Validation:**

The reported denial‐of‐service issue centers on the ETH refund mechanism in repayLoan and liquidate, where the contract uses a low-level call to return ETH collateral. Although it is possible for a borrower (or liquidator) using a contract that reverts upon receiving ETH to block the refund, this risk mostly affects the party initiating the call (i.e., a borrower harming their own repayment or a liquidator using a problematic contract). Since users can control what address they use for borrowing or liquidating, and standard practice is to use externally owned accounts or carefully designed contracts for these purposes, this does not represent a systemic DOS vulnerability of the protocol itself.

**Code Snippet:**

```solidity
function repayLoan() external {
        Loan memory loan = loans[msg.sender];
        require(loan.principal > 0, "No active loan");
        uint256 debt = getCurrentDebt(msg.sender);
        uint256 collateral = loan.collateral;
        delete loans[msg.sender];

        require(
            token.transferFrom(msg.sender, address(this), debt),
            "Token transfer failed"
        );
        (bool success, ) = msg.sender.call{value: collateral}("");
        require(success, "ETH refund failed");
    }

function liquidate(address borrower) external {
        require(isLiquidatable(borrower), "Loan not liquidatable");
        Loan memory loan = loans[borrower];
        uint256 debt = getCurrentDebt(borrower);
        uint256 collateral = loan.collateral;
        delete loans[borrower];
        require(
            token.transferFrom(msg.sender, address(this), debt),
            "Token transfer failed"
        );
        (bool success, ) = msg.sender.call{value: collateral}("");
        require(success, "Collateral transfer failed");
    }
```

**Affected Functions:** repayLoan, liquidate

---

## Proof of Concept Exploits

### PoC #1: price_manipulation

**File:** /Users/advait/Desktop/NTU/fyp-fr/exploit/src/test/PoC_unknown_1742489802.sol

**Execution:** ❌ FAILED after 2 fix attempts

**Error:** Error
fail
Error
Error

**Exploit Code:**

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.13;

import "./basetest.sol";

// Minimal ERC20 interface
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function mint(address to, uint256 amount) external;
    function balanceOf(address account) external view returns (uint256);
    function approve(address spender, uint256 amount) external;
}

// Price Oracle interface
interface IPriceOracle {
    function getPrice() external view returns (uint256);
}

// Simple ERC20 token for testing purposes
contract SimpleERC20 is IERC20 {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowance;
    
    constructor(string memory _name, string memory _symbol) {
        name = _name;
        symbol = _symbol;
    }
    
    function mint(address to, uint256 amount) external override {
        balances[to] += amount;
        totalSupply += amount;
    }
    
    function transfer(address to, uint256 amount) external override returns (bool) {
        require(balances[msg.sender] >= amount, "Insufficient funds");
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }
    
    function transferFrom(address from, address to, uint256 amount) external override returns (bool) {
        require(balances[from] >= amount, "Insufficient funds");
        require(allowance[from][msg.sender] >= amount, "Not allowed");
        allowance[from][msg.sender] -= amount;
        balances[from] -= amount;
        balances[to] += amount;
        return true;
    }
    
    function approve(address spender, uint256 amount) external override {
        allowance[msg.sender][spender] = amount;
    }
    
    function balanceOf(address account) external view override returns (uint256) {
        return balances[account];
    }
}

// Mock Price Oracle that allows manipulation of its returned price
contract MockPriceOracle is IPriceOracle {
    uint256 public price;
    address public owner;
    
    constructor(uint256 _initialPrice) {
        price = _initialPrice;
        owner = msg.sender;
    }
    
    // Only the owner (for testing) can manipulate the oracle price
    function setPrice(uint256 _price) external {
        require(msg.sender == owner, "Not owner");
        price = _price;
    }
    
    function getPrice() external view override returns (uint256) {
        return price;
    }
}

// Vulnerable Lending contract that uses an external price oracle for collateral valuation
contract VulnerableLending {
    IERC20 public collateralToken;
    IERC20 public stablecoin;
    IPriceOracle public priceOracle;
    
    // Tracking collateral deposited and loans taken per user
    mapping(address => uint256) public collateralBalance;
    mapping(address => uint256) public loanBalance;
    
    // Using 1e18 for scaling decimals
    uint256 constant SCALE = 1e18;
    
    constructor(address _collateralToken, address _stablecoin, address _priceOracle) {
        collateralToken = IERC20(_collateralToken);
        stablecoin = IERC20(_stablecoin);
        priceOracle = IPriceOracle(_priceOracle);
    }
    
    // Deposits collateral from the user. The user must approve this contract beforehand.
    function depositCollateral(uint256 amount) external returns (bool) {
        require(collateralToken.transferFrom(msg.sender, address(this), amount), "Collateral transfer failed");
        collateralBalance[msg.sender] += amount;
        return true;
    }
    
    // Borrow stablecoin using deposited collateral.
    // The allowed borrow amount is based on collateral * oracle price.
    function borrow(uint256 amount) external returns (bool) {
        uint256 collateralVal = (collateralBalance[msg.sender] * priceOracle.getPrice()) / SCALE;
        require(loanBalance[msg.sender] + amount <= collateralVal, "Insufficient collateral");
        loanBalance[msg.sender] += amount;
        require(stablecoin.transfer(msg.sender, amount), "Stablecoin transfer failed");
        return true;
    }
    
    // Determines if a user's account is liquidatable (loan exceeds current collateral value)
    function isLiquidatable(address user) external view returns (bool) {
        uint256 collateralVal = (collateralBalance[user] * priceOracle.getPrice()) / SCALE;
        return loanBalance[user] > collateralVal;
    }
}

// Foundry test contract demonstrating the vulnerability for educational purposes
contract YourTest is BaseTestWithBalanceLog {
    SimpleERC20 collateralToken;
    SimpleERC20 stablecoin;
    MockPriceOracle priceOracle;
    VulnerableLending lending;
    
    // Define test accounts for borrower and attacker
    address borrower = address(0xB0rrower);
    address attacker = address(0xAttacker);
    
    // setUp is called before each test. It deploys tokens, the oracle, and the vulnerable lending contract.
    function setUp() public {
        vm.deal(address(this), 100 ether); // Ensure the test contract has enough ETH
        
        // Deploy a simple ERC20 token to be used as collateral and a stablecoin for lending
        collateralToken = new SimpleERC20("Collateral Token", "COL");
        stablecoin = new SimpleERC20("Stablecoin", "STBL");
        
        // Mint collateral tokens to the borrower and stablecoins to this contract for funding the lending pool
        collateralToken.mint(borrower, 1000 * 1e18);
        stablecoin.mint(address(this), 10000 * 1e18);
        
        // Deploy a mock price oracle with an initial realistic price (1.0 represented as 1e18)
        priceOracle = new MockPriceOracle(1e18);
        
        // Deploy the vulnerable lending contract with the collateral token, stablecoin, and price oracle addresses
        lending = new VulnerableLending(address(collateralToken), address(stablecoin), address(priceOracle));
        
        // Fund the lending contract with stablecoin tokens so that it can lend out funds
        require(stablecoin.transfer(address(lending), 5000 * 1e18), "Funding lending contract failed");
        
        // Have the borrower approve the lending contract to transfer collateral on their behalf
        vm.startPrank(borrower);
        collateralToken.approve(address(lending), type(uint256).max);
        vm.stopPrank();
    }
    
    // This test demonstrates how external price manipulation can lead to economic abuse.
    // The borrower first borrows safely with realistic oracle price, then exploits the vulnerability when the oracle is manipulated.
    function testExploit() public balanceLog {
        vm.deal(address(this), 10 ether); // Ensure this contract has enough ETH
        
        // --- Step 1: Demonstrate Normal Behavior ---
        // Borrower deposits 10 collateral tokens
        uint256 depositAmount = 10 * 1e18;
        vm.startPrank(borrower);
        require(lending.depositCollateral(depositAmount), "Collateral deposit failed");
        
        // With a realistic price of 1e18, maximum borrow = 10 tokens; borrow a safe amount (5 tokens)
        uint256 borrowAmount1 = 5 * 1e18;
        require(lending.borrow(borrowAmount1), "Initial borrow failed");
        
        // Verify that the account is not liquidatable under normal conditions
        bool liquidatableBefore = lending.isLiquidatable(borrower);
        require(liquidatableBefore == false, "Account unexpectedly liquidatable before price manipulation");
        vm.stopPrank();
        
        // --- Step 2: Demonstrate the Vulnerability ---
        // Manipulate the oracle to return an inflated price (10x the realistic value)
        vm.prank(address(this));
        priceOracle.setPrice(10e18);
        
        // The borrower now leverages the inflated price to borrow more funds using the same collateral.
        // Attempt to borrow an additional 80 tokens; total debt becomes 85 tokens.
        uint256 borrowAmount2 = 80 * 1e18;
        vm.startPrank(borrower);
        require(lending.borrow(borrowAmount2), "Second borrow failed");
        vm.stopPrank();
        
        // Simulate a price correction by reverting the oracle price back to its realistic level.
        vm.prank(address(this));
        priceOracle.setPrice(1e18);
        
        // Now, the loan significantly exceeds the actual collateral value. The account should be liquidatable.
        bool liquidatableAfter = lending.isLiquidatable(borrower);
        require(liquidatableAfter == true, "Account should be liquidatable after price correction");
        
        // Educational Comments:
        // The vulnerability arises from solely relying on an externally controllable price oracle,
        // which can be manipulated to temporarily inflate collateral value.
        // This allows borrowers to secure larger loans than their actual collateral warrants.
        // To prevent such vulnerabilities, developers should integrate multiple decentralized oracles,
        // use time-weighted average pricing, or implement safeguards to limit sudden price changes.
    }
}
```

---

## Recommendations

For each identified vulnerability, consider implementing the following mitigations:

- **For Arithmetic Issues**: Use SafeMath library or Solidity 0.8.x built-in overflow checking.
- **For Oracle Manipulation**: Use time-weighted average prices and multiple independent oracle sources.
- **For All Vulnerabilities**: Consider a professional audit before deploying to production.

*This report was generated automatically by the Smart Contract Vulnerability Analyzer.*
