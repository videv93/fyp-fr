// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ReentrancyVulnerable {
    mapping(address => uint256) public balances;

    // Deposit function allows users to send Ether to the contract
    function deposit() external payable {
        require(msg.value > 0, "Must send some Ether");
        balances[msg.sender] += msg.value;
    }

    // Withdraw function contains a reentrancy vulnerability
    function withdraw(uint256 _amount) external {
        require(balances[msg.sender] >= _amount, "Insufficient balance");

        // Transfer Ether to the caller (external call before state update)
        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success, "Transfer failed");

        // Update the user's balance (state update happens after the external call)
        balances[msg.sender] -= _amount;
    }

    // Helper function to check the contract balance
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
