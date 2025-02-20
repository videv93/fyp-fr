// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Vulnerable contract with reentrancy issue
contract VulnerableReentrancy {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // ⚠️ Vulnerable: External call before updating balance
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount; // Update balance after external call
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
