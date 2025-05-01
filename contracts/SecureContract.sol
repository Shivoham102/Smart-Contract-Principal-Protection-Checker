// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SecureContract is Ownable, ReentrancyGuard {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public emergencyPendingWithdrawals;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event EmergencyWithdrawalQueued(address indexed user, uint256 amount);
    event EmergencyWithdrawalClaimed(address indexed user, uint256 amount);

    function deposit() external payable {
        require(msg.value > 0, "No ETH sent");
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(amount > 0, "Invalid amount");
        require(balances[msg.sender] >= amount, "Insufficient balance");

        balances[msg.sender] -= amount;
        (bool success, ) = payable(msg.sender).call{value: amount}("");

        require(success, "Withdraw failed");
        emit Withdrawn(msg.sender, amount);
    }

    function emergencyWithdraw(address user) external onlyOwner nonReentrant {
        require(user != address(this), "Cannot withdraw to contract address");

        uint256 userBalance = balances[user];
        require(userBalance > 0, "No balance to withdraw");

        balances[user] = 0;
        emergencyPendingWithdrawals[user] += userBalance;

        emit EmergencyWithdrawalQueued(user, userBalance);
    }

    function claimEmergencyWithdrawal() external nonReentrant {
        uint256 amount = emergencyPendingWithdrawals[msg.sender];
        require(amount > 0, "Nothing to withdraw");

        emergencyPendingWithdrawals[msg.sender] = 0;
        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "Claim failed");

        emit EmergencyWithdrawalClaimed(msg.sender, amount);
    }
}
