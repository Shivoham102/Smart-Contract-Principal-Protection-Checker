// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.6.0;

contract VulnerableContract {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient funds");

        // Vulnerable pattern: call before state change (reentrancy risk)
        (bool success, ) = msg.sender.call.value(amount)("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;
    }

    // No access control - anyone can drain any user's funds
    function adminDrain(address user) public {
        uint256 userBalance = balances[user];
        balances[user] = 0;

        // Fixed syntax to be compatible with Solidity 0.6.0
        (bool success, ) = msg.sender.call.value(userBalance)("");
        require(success, "Admin drain failed");
    }
}
